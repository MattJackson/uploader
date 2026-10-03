package main

import (
	"context"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tus/tusd/v2/pkg/handler"
	"golang.org/x/crypto/bcrypt"
)

// testDirs points the app at fresh temp dirs and a fixed secret.
func testDirs(t *testing.T) (data, spool string) {
	t.Helper()
	data, spool = t.TempDir(), t.TempDir()
	setDirs(data, spool)
	secret = []byte("test-secret")
	reserve = 0
	admitted = nil
	nasFree.at = time.Time{}
	cfg = settings{}
	for _, d := range []string{partDir, outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return data, spool
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// the package must load without UPLOAD_SECRET in the environment.
func TestPackageLoadsWithoutEnv(t *testing.T) {
	if got := humanSize(2048); got != "2.0 KB" {
		t.Fatalf("humanSize(2048) = %q", got)
	}
}

// a lock left behind by a process that died (always PID 1 in the
// container, so "our own" PID after restart) must not block resuming.
func TestStaleLockDoesNotBlockResume(t *testing.T) {
	testDirs(t)
	comp := newComposer()
	ctx := context.Background()
	up, err := comp.Core.NewUpload(ctx, handler.FileInfo{Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := up.GetInfo(ctx)
	writeFile(t, filepath.Join(partDir, info.ID+".lock"), strconv.Itoa(os.Getpid())+"\n")

	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	lock, err := comp.Locker.NewLock(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Lock(lctx, func() {}); err != nil {
		t.Fatalf("resume blocked by stale lock: %v", err)
	}
	lock.Unlock()
}

// fakeFree makes freeSpace report fixed sizes per dir.
func fakeFree(t *testing.T, spool, nas int64) {
	t.Helper()
	old := freeSpace
	freeSpace = func(dir string) (int64, error) {
		if dir == spoolDir {
			return spool, nil
		}
		return nas, nil
	}
	t.Cleanup(func() { freeSpace = old })
}

func createReq(size int64) handler.HookEvent {
	return handler.HookEvent{Upload: handler.FileInfo{Size: size}}
}

// newPartial creates a tus upload of the given size with received bytes on disk.
func newPartial(t *testing.T, size int64, received int) string {
	t.Helper()
	ctx := context.Background()
	up, err := newComposer().Core.NewUpload(ctx, handler.FileInfo{Size: size})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := up.GetInfo(ctx)
	if received > 0 {
		writeFile(t, filepath.Join(partDir, info.ID), strings.Repeat("x", received))
	}
	return info.ID
}

// bytes promised to uploads still arriving count against the reserve.
func TestReserveCountsInFlightUploads(t *testing.T) {
	testDirs(t)
	reserve = 100
	fakeFree(t, 1000, 1<<40)
	id := newPartial(t, 600, 0)
	minuteAgo := time.Now().Add(-time.Minute) // past the admission window
	os.Chtimes(filepath.Join(partDir, id+".info"), minuteAgo, minuteAgo)
	if _, _, err := checkSpace(createReq(400)); err == nil {
		t.Fatal("accepted 400 bytes with 1000 free, 600 promised and a 100 reserve")
	}
	if _, _, err := checkSpace(createReq(250)); err != nil {
		t.Fatalf("refused 250 bytes that fit: %v", err)
	}
}

// an upload idle for over an hour no longer holds its unwritten bytes.
func TestReserveReleasesIdleUploads(t *testing.T) {
	testDirs(t)
	reserve = 100
	fakeFree(t, 1000, 1<<40)
	id := newPartial(t, 600, 1)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(filepath.Join(partDir, id), old, old)
	if _, _, err := checkSpace(createReq(400)); err != nil {
		t.Fatalf("idle partial still holding space: %v", err)
	}
}

// files waiting in the outbox count against the NAS reserve.
func TestReserveCountsOutboxForNAS(t *testing.T) {
	testDirs(t)
	reserve = 100
	fakeFree(t, 1<<40, 1000)
	writeFile(t, filepath.Join(outDir, "abc", "big.bin"), strings.Repeat("x", 600))
	refreshNASFree()
	if _, _, err := checkSpace(createReq(400)); err == nil {
		t.Fatal("accepted 400 bytes for a NAS with 1000 free and 600 queued")
	}
}

// if the spool's free space can't be read, refuse rather than guess.
func TestSpoolStatfsErrorRefuses(t *testing.T) {
	testDirs(t)
	old := freeSpace
	freeSpace = func(dir string) (int64, error) { return 0, syscall.EIO }
	t.Cleanup(func() { freeSpace = old })
	if _, _, err := checkSpace(createReq(1)); err == nil {
		t.Fatal("accepted an upload with unreadable spool free space")
	}
}

// a hung NAS must not hang upload creation.
func TestSlowNASDoesNotBlockCreate(t *testing.T) {
	testDirs(t)
	old := freeSpace
	release := make(chan struct{})
	freeSpace = func(dir string) (int64, error) {
		if dir == dataDir {
			<-release
		}
		return 1 << 40, nil
	}
	t.Cleanup(func() { close(release); freeSpace = old })
	done := make(chan error, 1)
	go func() { _, _, err := checkSpace(createReq(1)); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upload creation blocked on the NAS")
	}
}

// writes stop once the shared spool disk drops below half the reserve,
// whatever the accounting at creation said.
func TestSpoolGuardStopsWrites(t *testing.T) {
	testDirs(t)
	reserve = 100
	mux, err := newMux()
	if err != nil {
		t.Fatal(err)
	}
	fakeFree(t, 1000, 1<<40)
	loc := tusCreate(t, mux, 10)
	fakeFree(t, 40, 1<<40)
	rec := tusPatch(mux, loc, 0, "0123456789")
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("PATCH with 40 bytes free: status %d, want 507", rec.Code)
	}
}

func tusCreate(t *testing.T, mux http.Handler, size int) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/files/", nil)
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Length", strconv.Itoa(size))
	req.Header.Set("Upload-Metadata", "filename "+base64.StdEncoding.EncodeToString([]byte("f.bin")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Path
}

func tusPatch(mux http.Handler, path string, offset int, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PATCH", path, strings.NewReader(body))
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Offset", strconv.Itoa(offset))
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// the guard also trips mid-stream, after guardEvery bytes.
func TestSpoolGuardTripsMidStream(t *testing.T) {
	testDirs(t)
	reserve = 100
	fakeFree(t, 40, 1<<40)
	b := &guardedBody{ReadCloser: io.NopCloser(strings.NewReader("data")), n: guardEvery}
	if _, err := b.Read(make([]byte, 4)); err != errSpoolFull {
		t.Fatalf("read past guardEvery with spool full: err=%v", err)
	}
}

func withPlaceHook(t *testing.T, h func(string) error) {
	t.Helper()
	placeHook = h
	t.Cleanup(func() { placeHook = nil })
}

// a NAS error while probing names must surface, not spin forever.
func TestPlaceErrorsInsteadOfSpinning(t *testing.T) {
	_, spool := testDirs(t)
	notADir := filepath.Join(spool, "file")
	writeFile(t, notADir, "x")
	dataDir = notADir // every Lstat under it fails with ENOTDIR
	src := filepath.Join(spool, "src")
	writeFile(t, src, "data")
	done := make(chan error, 1)
	go func() { _, err := place(src, "a.txt", "id1"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("place succeeded under a non-directory")
		}
	case <-time.After(time.Second):
		t.Fatal("place spun instead of returning the error")
	}
}

// a file that appears at the chosen name (owner copying in over SMB)
// must never be overwritten.
func TestPlaceNeverOverwrites(t *testing.T) {
	data, spool := testDirs(t)
	src := filepath.Join(data, ".part-x")
	writeFile(t, src, "upload")
	once := false
	withPlaceHook(t, func(name string) error {
		if !once {
			once = true
			writeFile(t, filepath.Join(data, name), "owner's file")
		}
		return nil
	})
	_ = spool
	name, err := place(src, "a.txt", "id1")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(data, "a.txt")); string(b) != "owner's file" {
		t.Fatalf("owner's a.txt overwritten, now %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(data, name)); string(b) != "upload" {
		t.Fatalf("upload saved as %q with %q", name, b)
	}
}

// a failed placement must not leave the hidden NAS copy behind.
func TestMoveToNASCleansPartOnFailure(t *testing.T) {
	data, _ := testDirs(t)
	src := filepath.Join(outDir, "id1", "a.txt")
	writeFile(t, src, "upload")
	withPlaceHook(t, func(string) error { return errors.New("nas said no") })
	if _, err := moveToNAS(src, "a.txt", "id1"); err == nil {
		t.Fatal("moveToNAS reported success")
	}
	if left, _ := filepath.Glob(filepath.Join(data, ".part-*")); len(left) > 0 {
		t.Fatalf("left behind on NAS: %v", left)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("local copy gone after failed move: %v", err)
	}
}

// the mover must not delete an outbox dir that finish() has created
// but not yet moved the file into.
func TestMoverLeavesFreshEmptyOutboxDir(t *testing.T) {
	testDirs(t)
	dir := filepath.Join(outDir, "finishing")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	moveOutbox()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("mover removed a dir finish() was about to use: %v", err)
	}
}

// a complete upload that never made it to the outbox (finish failed)
// is picked up by the mover instead of sitting until the 7-day sweep.
func TestMoverRecoversStrandedCompleteUpload(t *testing.T) {
	data, _ := testDirs(t)
	ctx := context.Background()
	up, err := newComposer().Core.NewUpload(ctx, handler.FileInfo{Size: 4, MetaData: handler.MetaData{"filename": "photo.jpg"}})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := up.GetInfo(ctx)
	bin := filepath.Join(partDir, info.ID)
	writeFile(t, bin, "data")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(bin, old, old)
	moveOutbox()
	if b, err := os.ReadFile(filepath.Join(data, "photo.jpg")); err != nil || string(b) != "data" {
		t.Fatalf("stranded upload not delivered: %v %q", err, b)
	}
	if left, _ := filepath.Glob(filepath.Join(partDir, info.ID+"*")); len(left) > 0 {
		t.Fatalf("left in tus dir: %v", left)
	}
}

// adminCookie signs in as a fully set-up admin (password already changed).
func adminCookie(t *testing.T) *http.Cookie {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	auth = adminAuth{Hash: string(h)}
	rec := httptest.NewRecorder()
	setSession(rec, auth)
	return rec.Result().Cookies()[0]
}

func get(t *testing.T, mux http.Handler, path string, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

var linkRE = regexp.MustCompile(`data-link="([^"]+)"`)

// deleting a file revokes its link for good — a later upload that
// reuses the name must not be served through the old link.
func TestShareLinkDiesWithItsFile(t *testing.T) {
	data, _ := testDirs(t)
	mux, err := newMux()
	if err != nil {
		t.Fatal(err)
	}
	c := adminCookie(t)
	writeFile(t, filepath.Join(data, "scan.pdf"), "first")
	m := linkRE.FindStringSubmatch(get(t, mux, "/admin", c).Body.String())
	if m == nil {
		t.Fatal("no share link on admin page")
	}
	link := html.UnescapeString(m[1])
	if rec := get(t, mux, link+"?dl", nil); rec.Code != 200 || rec.Body.String() != "first" {
		t.Fatalf("fresh link: %d %q", rec.Code, rec.Body)
	}
	os.Remove(filepath.Join(data, "scan.pdf"))
	writeFile(t, filepath.Join(data, "scan.pdf"), "other") // same size as "first": only mtime differs
	later := time.Now().Add(time.Minute)
	os.Chtimes(filepath.Join(data, "scan.pdf"), later, later)
	if rec := get(t, mux, link+"?dl", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("revoked link served the new file: %d %q", rec.Code, rec.Body)
	}
}

func postForm(mux http.Handler, path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// guesses are serialised site-wide — a burst of parallel wrong guesses
// can't be used to test passwords faster than one per loginDelay, so a
// guess sent behind them waits its turn instead of being checked at once.
func TestLoginGuessesAreSerialised(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	adminCookie(t) // sets the password to "correct horse"
	old := loginDelay
	loginDelay = 200 * time.Millisecond
	t.Cleanup(func() { loginDelay = old })
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); postForm(mux, "/admin/login", url.Values{"password": {"wrong"}}, nil) }()
	}
	time.Sleep(50 * time.Millisecond) // let the wrong guesses get in first
	start := time.Now()
	rec := postForm(mux, "/admin/login", url.Values{"password": {"correct horse"}}, nil)
	elapsed := time.Since(start)
	wg.Wait()
	if rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) == 0 {
		t.Fatalf("correct login failed: %d", rec.Code)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("guess checked after %v, while 4 failures should hold it ~800ms: guesses run in parallel", elapsed)
	}
}

// login bodies are capped, so a queue of waiting logins can't hold
// megabytes each.
func TestLoginBodyIsCapped(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	adminCookie(t)
	rec := postForm(mux, "/admin/login", url.Values{"password": {strings.Repeat("x", 2<<20)}}, nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("2 MB login body: status %d, want 413", rec.Code)
	}
}

var dlRE = regexp.MustCompile(`href="(/admin/dl/[^"]+)"`)

// the admin Download link must fetch exactly the listed file, whatever
// characters its name has.
func TestAdminDownloadLinkEscapesName(t *testing.T) {
	data, _ := testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	for _, name := range []string{"Invoice #3.pdf", "what? notes.txt", "a%20b.txt"} {
		writeFile(t, filepath.Join(data, name), "body of "+name)
	}
	page := get(t, mux, "/admin", c).Body.String()
	links := dlRE.FindAllStringSubmatch(page, -1)
	if len(links) != 3 {
		t.Fatalf("found %d download links", len(links))
	}
	for _, m := range links {
		rec := get(t, mux, html.UnescapeString(m[1]), c)
		if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "body of ") {
			t.Errorf("%s: %d %q", m[1], rec.Code, rec.Body)
			continue
		}
		want := strings.TrimPrefix(rec.Body.String(), "body of ")
		if !strings.Contains(page, html.EscapeString(want)) {
			t.Errorf("%s served %q", m[1], want)
		}
	}
}

// names that aren't valid UTF-8 are repaired, not stored unlistable.
func TestCleanNameRepairsInvalidUTF8(t *testing.T) {
	if got := cleanName("r\xe9sum\xe9.pdf"); !utf8.ValidString(got) || !validName(got) {
		t.Fatalf("cleanName gave %q, which admin can't list", got)
	}
}

// bidi overrides and invisible characters can't disguise a name.
func TestCleanNameStripsBidiAndInvisible(t *testing.T) {
	for _, in := range []string{"invoice‮fdp.exe", "a​b.txt", "x⁦y⁩.pdf", "\uFEFFz.txt"} {
		got := cleanName(in)
		for _, r := range got {
			if unicode.Is(unicode.Cf, r) {
				t.Errorf("cleanName(%q) = %q keeps format char %U", in, got, r)
			}
		}
	}
}

// a damaged admin.json must not crash-loop the service.
func TestCorruptAuthFileKeepsServiceUp(t *testing.T) {
	testDirs(t)
	writeFile(t, authFile, "")
	if err := loadAuth(); err != nil {
		t.Fatalf("loadAuth on an empty admin.json: %v (process would exit)", err)
	}
	mux, _ := newMux()
	if rec := postForm(mux, "/admin/login", url.Values{"password": {"password"}}, nil); len(rec.Result().Cookies()) > 0 {
		t.Fatal("signed in against a damaged admin.json")
	}
}

// stray files with no .info (crash mid-create, old lock/stop files)
// are swept too.
func TestSweepRemovesOrphans(t *testing.T) {
	testDirs(t)
	old := time.Now().Add(-8 * 24 * time.Hour)
	for _, n := range []string{"deadbeef", "cafe.lock", "cafe.stop", "cafe.lock.1234"} {
		p := filepath.Join(partDir, n)
		writeFile(t, p, "x")
		os.Chtimes(p, old, old)
	}
	writeFile(t, filepath.Join(partDir, "fresh"), "x")
	sweepOnce()
	left, _ := os.ReadDir(partDir)
	if len(left) != 1 || left[0].Name() != "fresh" {
		names := []string{}
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Fatalf("after sweep: %v, want [fresh]", names)
	}
}

// admin POSTs from another origin (e.g. a sibling subdomain) are
// refused, even with the session cookie attached.
func TestAdminPostRejectsForeignOrigin(t *testing.T) {
	data, _ := testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	writeFile(t, filepath.Join(data, "keep.txt"), "x")
	req := httptest.NewRequest("POST", "/admin/delete", strings.NewReader("name=keep.txt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if _, err := os.Stat(filepath.Join(data, "keep.txt")); err != nil {
		t.Fatalf("cross-origin delete went through (status %d)", rec.Code)
	}
}

// bcrypt's 72-byte limit gets a length message, not a storage error.
func TestLongPasswordGetsLengthMessage(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	long := strings.Repeat("p", 80)
	rec := postForm(mux, "/admin/password", url.Values{"current": {"correct horse"}, "new": {long}, "confirm": {long}}, c)
	page := get(t, mux, rec.Header().Get("Location"), c).Body.String()
	if !strings.Contains(page, "72") {
		t.Fatalf("80-char password: page says %q", regexp.MustCompile(`class="err">[^<]*`).FindString(page))
	}
}

// the password page shows only its own messages, never caller text.
func TestPasswordPageIgnoresArbitraryErr(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	if body := get(t, mux, "/admin/password?err=Call+0800+EVIL+now", c).Body.String(); strings.Contains(body, "EVIL") {
		t.Fatal("password page reflects ?err text")
	}
}

// filename* follows RFC 8187 attr-char, with an ASCII fallback.
func TestContentDispositionEncoding(t *testing.T) {
	data, _ := testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	writeFile(t, filepath.Join(data, "a=b:c@d é.zip"), "x")
	cd := get(t, mux, "/admin/dl/"+url.PathEscape("a=b:c@d é.zip"), c).Header().Get("Content-Disposition")
	if !strings.Contains(cd, `filename*=UTF-8''a%3Db%3Ac%40d%20%C3%A9.zip`) || !strings.Contains(cd, `filename="`) {
		t.Fatalf("Content-Disposition = %q", cd)
	}
}

// validName is the only check before joining a name onto dataDir.
func TestValidName(t *testing.T) {
	for _, bad := range []string{"", ".", "..", ".hidden", ".part-abc", "a/b", "../x", `a\b`, "x\xff"} {
		if validName(bad) {
			t.Errorf("validName(%q) = true", bad)
		}
	}
	for _, ok := range []string{"a.txt", "Invoice #3.pdf", "résumé.pdf", "what? notes"} {
		if !validName(ok) {
			t.Errorf("validName(%q) = false", ok)
		}
	}
}

// client-supplied names can't climb out of dataDir or hide.
func TestCleanNameTraversal(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", "..", "/abs", `..\..\win`, ".part-x", "  .env", "a\x00b"} {
		got := cleanName(in)
		if got != "" && !validName(got) {
			t.Errorf("cleanName(%q) = %q, not a valid plain name", in, got)
		}
	}
	long := strings.Repeat("é", 150) + ".pdf"
	if got := cleanName(long); len(got) > 200 || !strings.HasSuffix(got, ".pdf") || !utf8.ValidString(got) {
		t.Errorf("long name -> %q (%d bytes)", got, len(got))
	}
}

// sessions — tampering, expiry and password changes all end them.
func TestSessionVerification(t *testing.T) {
	testDirs(t)
	c := adminCookie(t)
	req := func(v string) *http.Request {
		r := httptest.NewRequest("GET", "/admin", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: v})
		return r
	}
	if !isAdmin(req(c.Value)) {
		t.Fatal("fresh session rejected")
	}
	exp, mac, _ := strings.Cut(c.Value, ".")
	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	for name, v := range map[string]string{
		"tampered mac": exp + "." + strings.Repeat("A", len(mac)),
		"no dot":       exp + mac,
		"garbage exp":  "x." + mac,
		"expired":      past + "." + sign("admin|"+past+"|"+auth.Hash),
	} {
		if isAdmin(req(v)) {
			t.Errorf("%s accepted", name)
		}
	}
	h, _ := bcrypt.GenerateFromPassword([]byte("new password"), bcrypt.MinCost)
	auth = adminAuth{Hash: string(h)}
	if isAdmin(req(c.Value)) {
		t.Fatal("session survived a password change")
	}
}

// with the default password still in place, no admin route works.
func TestForcedChangeGatesEveryAdminRoute(t *testing.T) {
	data, _ := testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	auth.MustChange = true
	writeFile(t, filepath.Join(data, "x.txt"), "secret")
	for _, rec := range []*httptest.ResponseRecorder{
		get(t, mux, "/admin", c),
		get(t, mux, "/admin/dl/x.txt", c),
		postForm(mux, "/admin/delete", url.Values{"name": {"x.txt"}}, c),
	} {
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/password" {
			t.Errorf("status %d -> %q, want redirect to /admin/password", rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Error("file contents leaked before password change")
		}
	}
	if _, err := os.Stat(filepath.Join(data, "x.txt")); err != nil {
		t.Fatal("delete worked before password change")
	}
}

// anonymous users can create and resume uploads, never read or delete.
func TestTusDeniesDownloadAndDelete(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	loc := tusCreate(t, mux, 10)
	if rec := tusPatch(mux, loc, 0, "01234"); rec.Code != http.StatusNoContent {
		t.Fatalf("PATCH: %d", rec.Code)
	}
	for _, m := range []string{"GET", "DELETE"} {
		req := httptest.NewRequest(m, loc, nil)
		req.Header.Set("Tus-Resumable", "1.0.0")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code < 400 || strings.Contains(rec.Body.String(), "01234") {
			t.Errorf("%s %s: %d %q", m, loc, rec.Code, rec.Body)
		}
	}
	id := filepath.Base(loc)
	if _, err := os.Stat(filepath.Join(partDir, id)); err != nil {
		t.Fatalf("partial gone after anonymous DELETE: %v", err)
	}
}

// the local copy is deleted only once the NAS copy is complete.
func TestMoveToNASKeepsSourceUntilPlaced(t *testing.T) {
	data, _ := testDirs(t)
	src := filepath.Join(outDir, "id1", "a.txt")
	writeFile(t, src, "payload")
	name, err := moveToNAS(src, "a.txt", "id1")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(data, name)); string(b) != "payload" {
		t.Fatalf("NAS copy = %q", b)
	}
	if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("local copy still present after success: %v", err)
	}
	// Failure: NAS dir gone. Source must survive.
	writeFile(t, src, "payload")
	dataDir = filepath.Join(data, "missing")
	if _, err := moveToNAS(src, "a.txt", "id1"); err == nil {
		t.Fatal("moveToNAS into a missing dir succeeded")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("local copy lost after failed move: %v", err)
	}
}

// a real browser POST from our own page must pass. With
// Referrer-Policy: no-referrer browsers send Origin: null, so the check has
// to rely on Sec-Fetch-Site.
func TestAdminPostFromOwnPageAllowed(t *testing.T) {
	data, _ := testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	writeFile(t, filepath.Join(data, "gone.txt"), "x")
	req := httptest.NewRequest("POST", "https://upload.example.com/admin/delete", strings.NewReader("name=gone.txt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if _, err := os.Stat(filepath.Join(data, "gone.txt")); err == nil {
		t.Fatalf("same-origin browser delete refused: %d %s", rec.Code, rec.Body)
	}
}

// an admitted upload must not be counted twice once its
// .info exists, or a normal multi-file batch gets refused.
func TestReserveDoesNotDoubleCountNewUploads(t *testing.T) {
	testDirs(t)
	reserve = 100
	fakeFree(t, 1000, 1<<40)
	if _, _, err := checkSpace(createReq(400)); err != nil {
		t.Fatal(err)
	}
	newPartial(t, 400, 0) // tusd writes its .info right after admission
	if _, _, err := checkSpace(createReq(400)); err != nil {
		t.Fatalf("second 400 of 900 usable refused: %v", err)
	}
}

// NFSv4 reports unsupported hard links as ENOTSUPP (524).
func TestLinkUnsupportedCoversNFSv4(t *testing.T) {
	if !linkUnsupported(syscall.Errno(524)) {
		t.Fatal("ENOTSUPP (524) not treated as unsupported")
	}
}

// a retried NFS link can report EEXIST although it worked;
// that must not create a " (2)" duplicate.
func TestPlaceAcceptsOwnExistingLink(t *testing.T) {
	data, _ := testDirs(t)
	src := filepath.Join(data, ".part-x")
	writeFile(t, src, "upload")
	withPlaceHook(t, func(name string) error { return os.Link(src, filepath.Join(data, name)) })
	name, err := place(src, "a.txt", "id1")
	if err != nil || name != "a.txt" {
		t.Fatalf("place = %q, %v; want a.txt", name, err)
	}
}

// joiners in emoji and scripts are not disguises; keep them.
func TestCleanNameKeepsJoiners(t *testing.T) {
	in := "kids \U0001F468‍\U0001F469‍\U0001F467 می‌خواهم.jpg"
	if got := cleanName(in); got != in {
		t.Fatalf("cleanName stripped joiners: %q", got)
	}
}
