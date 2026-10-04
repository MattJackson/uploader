// uploader — a self-hosted drop box: anyone with the link can upload, only
// the admin can see, download, delete and share the files.
//
//	/                anyone: pick files, upload (resumable tus via Uppy)
//	/files/          tus endpoint: create + resume only (no download, no delete)
//	PUT /<name>      one-shot upload for curl -T (not resumable)
//	/admin           password login → upload, list, download, delete, copy link
//	                 (password starts as "password" and must be changed on first
//	                 login; bcrypt hash in SPOOL_DIR/admin.json — delete that
//	                 file to reset)
//	/d/<tok>/<name>  share link: landing page with a download button
//
// Uploads land on local disk (SPOOL_DIR/tus) and, once finished, are moved
// to SPOOL_DIR/outbox and then copied to DATA_DIR (which may be a network
// share) by a background mover. Long uploads never touch the share: NFS
// handles can go ESTALE, and when that happens we exit so docker restarts us with
// a fresh mount (clients resume, the mover retries).
//
// Share tokens are HMAC(secret, name): stateless, revoked by renaming or
// deleting the file.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/tus/tusd/v2/pkg/filestore"
	"github.com/tus/tusd/v2/pkg/handler"
	"github.com/tus/tusd/v2/pkg/memorylocker"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxSize    = 500 << 30 // per file
	partialTTL = 7 * 24 * time.Hour
	cookieName = "upl_admin"
	cookieTTL  = 30 * 24 * time.Hour
	// Space accounting (see checkSpace / guardSpool).
	activeWindow   = time.Hour        // idle partials stop holding their unwritten bytes
	admitWindow    = 30 * time.Second // covers the gap before tusd writes a new .info
	nasFreeMaxAge  = 5 * time.Minute
	nasFreeEvery   = 30 * time.Second
	guardEvery     = 256 << 20 // re-check spool free space every this many bytes written
	maxNameTries   = 1000
	recoverAfter   = 10 * time.Minute // complete but unfinished for this long = stranded
	staleDirAge    = time.Hour
	defaultPW      = "password"
	maxFormBytes   = 64 << 10
	loginQueueWait = 10 * time.Second
	minPWLen       = 8
	maxPWBytes     = 72 // bcrypt refuses anything longer
)

// Set from the environment in configure(); tests set them directly.
var (
	dataDir  string // finished files (NAS)
	spoolDir string // local disk
	partDir  string
	outDir   string
	authFile string
	secret   []byte
	// Refuse new uploads that would leave less than this free on either disk.
	reserve int64
)

var (
	kick = make(chan struct{}, 1)

	spaceMu  sync.Mutex  // serialises upload admission
	admitted []admission // recent admissions, guarded by spaceMu
	nasFree  struct {    // last NAS statfs, refreshed off the request path
		sync.Mutex
		bytes int64
		at    time.Time
	}

	nameMu sync.Mutex // serialises pick-a-free-name + rename

	authMu sync.Mutex // guards auth + authFile
	auth   adminAuth

	//go:embed static
	staticFS embed.FS
	//go:embed templates
	tmplFS embed.FS
	tmpl   = template.Must(template.New("").Funcs(template.FuncMap{"size": humanSize, "title": pageTitle}).ParseFS(tmplFS, "templates/*.html"))
)

func configure() {
	setDirs(envOr("DATA_DIR", "/data"), envOr("SPOOL_DIR", "/spool"))
	secret = []byte(mustEnv("UPLOAD_SECRET"))
	reserve = mustInt(envOr("RESERVE_GB", "200")) << 30
}

func setDirs(data, spool string) {
	dataDir, spoolDir = data, spool
	partDir = filepath.Join(spool, "tus")
	outDir = filepath.Join(spool, "outbox")
	authFile = filepath.Join(spool, "admin.json")
	settingsFile = filepath.Join(spool, "settings.json")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" { // distroless: no curl
		resp, err := http.Get("http://127.0.0.1:8080/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	configure()
	for _, d := range []string{partDir, outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Fatal(err)
		}
	}
	if err := loadAuth(); err != nil {
		log.Fatal(err)
	}
	loadSettings()
	mux, err := newMux()
	if err != nil {
		log.Fatal(err)
	}

	go sweepPartials()
	go mover()
	go notifier(startCh, notifyCh)
	go func() {
		for {
			refreshNASFree()
			time.Sleep(nasFreeEvery)
		}
	}()
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	log.Printf("listening on :8080, data in %s", dataDir)
	log.Fatal(srv.ListenAndServe())
}

func newMux() (*http.ServeMux, error) {
	comp := newComposer()
	tus, err := handler.NewHandler(handler.Config{
		BasePath:                  "/files/",
		StoreComposer:             comp,
		MaxSize:                   maxSize,
		RespectForwardedHeaders:   true,
		DisableDownload:           true,
		DisableTermination:        true,
		DisableConcatenation:      true,
		PreUploadCreateCallback:   checkSpace,
		PreFinishResponseCallback: finish,
	})
	if err != nil {
		return nil, err
	}

	files := guardSpool(http.StripPrefix("/files/", watch(tus)))
	mux := http.NewServeMux()
	mux.Handle("/files/", files)
	// Only the methods tus uses on the bare path: a method-less "/files"
	// would conflict with "PUT /{name}".
	bare := guardSpool(http.StripPrefix("/files", watch(tus)))
	mux.Handle("POST /files", bare)
	mux.Handle("OPTIONS /files", bare)
	mux.HandleFunc("PUT /{name}", putUpload(files, comp))
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		render(w, "index.html", map[string]any{"Owner": currentSettings().OwnerName, "Site": siteURL(r)})
	})
	mux.HandleFunc("GET /admin", adminPage)
	mux.HandleFunc("POST /admin/login", sameOrigin(login))
	mux.HandleFunc("POST /admin/logout", sameOrigin(logout))
	mux.HandleFunc("GET /admin/password", signedIn(passwordPage))
	mux.HandleFunc("POST /admin/password", sameOrigin(signedIn(changePassword)))
	mux.HandleFunc("GET /admin/arriving", authed(arriving))
	mux.HandleFunc("GET /admin/dl/{name}", authed(adminDownload))
	mux.HandleFunc("POST /admin/delete", sameOrigin(authed(deleteFile)))
	mux.HandleFunc("GET /admin/settings", authed(settingsPage))
	mux.HandleFunc("POST /admin/settings", sameOrigin(authed(saveSettingsForm)))
	mux.HandleFunc("POST /admin/settings/test", sameOrigin(authed(sendTestEmail)))
	mux.HandleFunc("GET /d/{tok}/{name}", shared)
	mux.HandleFunc("GET /healthz", healthz)
	return mux, nil
}

// ── uploads ──

func newComposer() *handler.StoreComposer {
	comp := handler.NewStoreComposer()
	filestore.New(partDir).UseIn(comp)
	// In-memory locks: there is exactly one process, and on-disk lock files
	// outlive it — tus/lockfile stores the holder PID, which is always 1 in
	// the container, so a lock left by a crash would block that upload's
	// resume forever.
	memorylocker.New().UseIn(comp)
	return comp
}

// freeSpace reports the bytes available to us on dir's filesystem. A var so
// tests can fake disk sizes and slow mounts.
var freeSpace = func(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

type admission struct {
	size int64
	at   time.Time
}

// checkSpace admits a new upload only if it fits on both disks after the
// reserve and everything already promised: the unwritten remainder of
// active partials (spool), and active partials plus the outbox (NAS).
// The spool is checked live — it is local disk, usually shared with
// other services. The NAS figure comes from a cache so a hung mount can't hang this.
func checkSpace(ev handler.HookEvent) (handler.HTTPResponse, handler.FileInfoChanges, error) {
	none := func(err error) (handler.HTTPResponse, handler.FileInfoChanges, error) {
		return handler.HTTPResponse{}, handler.FileInfoChanges{}, err
	}
	size := ev.Upload.Size
	if ev.Upload.SizeIsDeferred {
		return none(handler.NewError("ERR_SIZE_REQUIRED", "upload size required", http.StatusBadRequest))
	}
	noSpace := handler.NewError("ERR_NO_SPACE", "not enough space on the server", http.StatusInsufficientStorage)

	spaceMu.Lock()
	defer spaceMu.Unlock()
	pendSpool, pendNAS := committed()
	free, err := freeSpace(spoolDir)
	if err != nil {
		log.Printf("refusing upload: free space on %s: %v", spoolDir, err)
		return none(handler.NewError("ERR_STORAGE", "server storage unavailable", http.StatusServiceUnavailable))
	}
	if size > free-pendSpool-reserve {
		return none(noSpace)
	}
	if nas, ok := cachedNASFree(); !ok {
		log.Printf("NAS free space unknown; admitting %s on spool space alone", humanSize(size))
	} else if size > nas-pendNAS-reserve {
		return none(noSpace)
	}
	admitted = append(admitted, admission{size, time.Now()})
	// Stamp who sent it into the .info, so the admin list still knows after
	// a restart. Server-set keys win over anything the client sent.
	meta := make(handler.MetaData, len(ev.Upload.MetaData)+2)
	for k, v := range ev.Upload.MetaData {
		meta[k] = v
	}
	meta[metaIP] = clientIP(ev.HTTPRequest.Header, ev.HTTPRequest.RemoteAddr)
	meta[metaUA] = clip(ev.HTTPRequest.Header.Get("User-Agent"), 512)
	// Pick the id ourselves so the "started" email can tell later whether
	// this upload is still going. Same shape as filestore's own ids.
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return none(err)
	}
	changes := handler.FileInfoChanges{ID: hex.EncodeToString(id), MetaData: meta}
	notifyStart(changes.ID, cleanName(meta["filename"]), size, sender(meta[metaIP], meta[metaUA]))
	return handler.HTTPResponse{}, changes, nil
}

const (
	metaIP = "uploader.ip"
	metaUA = "uploader.ua"
)

func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

// seen is what the tus endpoint has observed per upload since we started:
// the latest client address and how many times it resumed (a HEAD on an
// existing upload is a client asking where to carry on from). Memory only.
var seen = struct {
	sync.Mutex
	m map[string]*sighting
}{m: map[string]*sighting{}}

type sighting struct {
	ip, ua  string
	resumes int
}

// watch records sightings for the admin list. It only reads the request and
// never touches the response, so it can't get in the way of an upload.
func watch(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || r.Method == http.MethodPatch {
			note(strings.Trim(r.URL.Path, "/"), r)
		}
		h.ServeHTTP(w, r)
	})
}

func note(id string, r *http.Request) {
	// Only real uploads: the map can't be grown by requests for made-up ids.
	if !uploadID(id) || !fileExists(filepath.Join(partDir, id+".info")) {
		return
	}
	seen.Lock()
	defer seen.Unlock()
	s := seen.m[id]
	if s == nil {
		s = &sighting{}
		seen.m[id] = s
	}
	s.ip = clientIP(r.Header, r.RemoteAddr)
	s.ua = clip(r.Header.Get("User-Agent"), 512)
	if r.Method == http.MethodHead {
		s.resumes++
	}
}

// uploadID matches the ids filestore hands out: 32 hex digits.
func uploadID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// committed returns bytes promised but not yet on each disk. Caller holds
// spaceMu.
func committed() (spool, nas int64) {
	infos, _ := filepath.Glob(filepath.Join(partDir, "*.info"))
	for _, p := range infos {
		var fi handler.FileInfo
		raw, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(raw, &fi) != nil {
			continue
		}
		if ist, err := os.Stat(p); err == nil && time.Since(ist.ModTime()) < admitWindow {
			continue // just created: still counted in admitted below
		}
		st, err := os.Stat(strings.TrimSuffix(p, ".info"))
		if err != nil || time.Since(st.ModTime()) > activeWindow {
			continue // gone, or idle: its written bytes already show in free space
		}
		spool += max(fi.Size-st.Size(), 0)
		nas += fi.Size
	}
	filepath.WalkDir(outDir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				nas += info.Size()
			}
		}
		return nil
	})
	kept := admitted[:0]
	for _, a := range admitted {
		if time.Since(a.at) < admitWindow {
			kept = append(kept, a)
			spool += a.size
			nas += a.size
		}
	}
	admitted = kept
	return spool, nas
}

func refreshNASFree() {
	free, err := freeSpace(dataDir)
	if err != nil {
		nasFatal(err)
		log.Printf("NAS free space: %v", err)
		return
	}
	nasFree.Lock()
	nasFree.bytes, nasFree.at = free, time.Now()
	nasFree.Unlock()
}

func cachedNASFree() (int64, bool) {
	nasFree.Lock()
	defer nasFree.Unlock()
	return nasFree.bytes, !nasFree.at.IsZero() && time.Since(nasFree.at) < nasFreeMaxAge
}

// guardSpool stops tus writes once the spool disk drops below half the
// reserve, whatever was promised at creation (other stacks share the disk).
// Bytes already written are kept, so clients resume once there is room.
func guardSpool(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch || r.Method == http.MethodPost {
			if !spoolHasRoom() {
				http.Error(w, "server storage full", http.StatusInsufficientStorage)
				return
			}
			r.Body = &guardedBody{ReadCloser: r.Body}
		}
		h.ServeHTTP(w, r)
	})
}

var errSpoolFull = errors.New("spool disk below reserve")

func spoolHasRoom() bool {
	free, err := freeSpace(spoolDir)
	if err != nil {
		log.Printf("spool free space: %v", err)
		return false
	}
	if free < reserve/2 {
		log.Printf("spool has %s free, below half the reserve: refusing writes", humanSize(free))
		return false
	}
	return true
}

type guardedBody struct {
	io.ReadCloser
	n int64
}

func (b *guardedBody) Read(p []byte) (int, error) {
	if b.n >= guardEvery {
		b.n = 0
		if !spoolHasRoom() {
			return 0, errSpoolFull
		}
	}
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	return n, err
}

func finish(ev handler.HookEvent) (handler.HTTPResponse, error) {
	id := ev.Upload.ID
	name, err := toOutbox(id, ev.Upload.MetaData["filename"], ev.Upload.Storage["Path"])
	if err != nil {
		// recoverStranded retries this from the mover.
		log.Printf("finish %s: %v", id, err)
		return handler.HTTPResponse{}, err
	}
	// Re-checked: an upload created by an older version may carry a
	// client-supplied value under this key.
	ip, ua := cleanIP(ev.Upload.MetaData[metaIP]), clip(ev.Upload.MetaData[metaUA], 512)
	if ip == "" { // created before we stamped uploads
		ip, ua = clientIP(ev.HTTPRequest.Header, ev.HTTPRequest.RemoteAddr), ev.HTTPRequest.Header.Get("User-Agent")
	}
	log.Printf("received %q (%s) from %s", name, humanSize(ev.Upload.Size), ip)
	notifyUpload(name, ev.Upload.Size, sender(ip, ua))
	select {
	case kick <- struct{}{}:
	default:
	}
	return handler.HTTPResponse{}, nil
}

// putUpload is a one-shot upload for `curl -T file https://host/`: curl
// appends the filename and sends Content-Length. It runs as a tus create
// plus one PATCH through the same chain as /files/, so space checks,
// notifications, the Arriving list and the outbox all behave the same.
// Nothing can resume it, so a partial left by a failed PUT is removed.
func putUpload(files http.Handler, comp *handler.StoreComposer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		size := r.ContentLength
		if size < 0 {
			http.Error(w, "Content-Length required: use curl -T <file>, not a pipe", http.StatusLengthRequired)
			return
		}

		create := tusRequest(r, http.MethodPost, "/files/", http.NoBody)
		create.Header.Set("Upload-Length", strconv.FormatInt(size, 10))
		create.Header.Set("Upload-Metadata", "filename "+base64.StdEncoding.EncodeToString([]byte(name)))
		res := &captured{w: w, h: http.Header{}}
		files.ServeHTTP(res, create)
		if res.code != http.StatusCreated {
			res.relay(w)
			return
		}
		loc, _ := url.Parse(res.h.Get("Location"))
		id := ""
		if loc != nil {
			id = filepath.Base(loc.Path)
		}
		if !uploadID(id) {
			log.Printf("put %q: unexpected Location %q", name, res.h.Get("Location"))
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		if size > 0 {
			patch := tusRequest(r, http.MethodPatch, "/files/"+id, r.Body)
			patch.ContentLength = size
			patch.Header.Set("Upload-Offset", "0")
			patch.Header.Set("Content-Type", "application/offset+octet-stream")
			res = &captured{w: w, h: http.Header{}}
			files.ServeHTTP(res, patch)
			if res.code != http.StatusNoContent || res.h.Get("Upload-Offset") != strconv.FormatInt(size, 10) {
				dropPartial(comp, id)
				res.relay(w)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "received %s (%s)\n", cleanName(name), humanSize(size))
	}
}

// tusRequest derives a tus request from r, keeping what identifies the
// sender (address, User-Agent, forwarding headers) and nothing that tus
// would read as protocol.
func tusRequest(r *http.Request, method, path string, body io.ReadCloser) *http.Request {
	t := r.Clone(r.Context())
	t.Method, t.Body, t.ContentLength = method, body, 0
	t.URL.Path, t.URL.RawPath, t.URL.RawQuery, t.RequestURI = path, "", "", path
	for k := range t.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "upload-") || strings.HasPrefix(lk, "content-") ||
			lk == "x-http-method-override" || lk == "expect" || lk == "tus-resumable" {
			t.Header.Del(k)
		}
	}
	t.Header.Set("Tus-Resumable", "1.0.0")
	return t
}

// dropPartial removes an unfinished upload. A complete one is left for
// recoverStranded.
func dropPartial(comp *handler.StoreComposer, id string) {
	ctx := context.Background()
	up, err := comp.Core.GetUpload(ctx, id)
	if err != nil {
		return
	}
	if info, err := up.GetInfo(ctx); err != nil || info.Offset >= info.Size {
		return
	}
	if err := comp.Terminater.AsTerminatableUpload(up).Terminate(ctx); err != nil {
		log.Printf("put: removing partial %s: %v", id, err)
	}
}

// captured holds a tus response so PUT can answer in its own words. It
// unwraps to the real writer so tusd's read/write deadlines still reach
// the connection.
type captured struct {
	w    http.ResponseWriter
	h    http.Header
	code int
	body strings.Builder
}

func (c *captured) Header() http.Header         { return c.h }
func (c *captured) Unwrap() http.ResponseWriter { return c.w }

func (c *captured) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
}

func (c *captured) Write(p []byte) (int, error) {
	c.WriteHeader(http.StatusOK)
	if room := 1024 - c.body.Len(); room > 0 {
		c.body.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// relay sends a failed tus response on as plain text.
func (c *captured) relay(w http.ResponseWriter) {
	code, msg := c.code, strings.TrimSpace(c.body.String())
	if code < 400 {
		code = http.StatusInternalServerError
	}
	if msg == "" {
		msg = "upload failed"
	}
	http.Error(w, msg, code)
}

// siteURL is the address people should upload to: the configured one, or
// else the one this request came in on.
func siteURL(r *http.Request) string {
	if u := currentSettings().PublicURL; u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// toOutbox moves a complete upload's data file into outbox/<id>/<name> and
// drops its tus record.
func toOutbox(id, filename, src string) (string, error) {
	name := cleanName(filename)
	if name == "" {
		name = "upload-" + id[:min(8, len(id))]
	}
	dir := filepath.Join(outDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(src, filepath.Join(dir, name)); err != nil {
		return "", err
	}
	os.Remove(src + ".info")
	return name, nil
}

// recoverStranded hands complete uploads whose finish() failed to the
// outbox; otherwise the client is told it's done and the 7-day sweep
// deletes the file. finish runs right after the last byte is written, so
// anything complete and untouched for recoverAfter is stranded, not finishing.
func recoverStranded() {
	infos, _ := filepath.Glob(filepath.Join(partDir, "*.info"))
	for _, p := range infos {
		var fi handler.FileInfo
		raw, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(raw, &fi) != nil {
			continue
		}
		bin := strings.TrimSuffix(p, ".info")
		st, err := os.Stat(bin)
		if err != nil || fi.SizeIsDeferred || st.Size() != fi.Size || time.Since(st.ModTime()) < recoverAfter {
			continue
		}
		if name, err := toOutbox(fi.ID, fi.MetaData["filename"], bin); err != nil {
			log.Printf("recover %s: %v", fi.ID, err)
		} else {
			log.Printf("recovered stranded upload %q", name)
		}
	}
}

// mover copies finished uploads from the local outbox to the NAS, one at a
// time, and deletes the local copy once the NAS copy is synced and the right
// size. Anything it can't move stays in the outbox for the next pass.
func mover() {
	for {
		moveOutbox()
		select {
		case <-kick:
		case <-time.After(time.Minute):
		}
	}
}

// moveOutbox is one mover pass over the outbox.
func moveOutbox() {
	recoverStranded()
	ids, _ := os.ReadDir(outDir)
	for _, id := range ids {
		dir := filepath.Join(outDir, id.Name())
		files, _ := os.ReadDir(dir)
		moved := false
		for _, f := range files {
			name, err := moveToNAS(filepath.Join(dir, f.Name()), f.Name(), id.Name())
			if err != nil {
				log.Printf("move %q to NAS: %v (will retry)", f.Name(), err)
				nasFatal(err)
				continue
			}
			log.Printf("saved %q to NAS", name)
			moved = true
		}
		// An empty dir may be one finish() just made and is about to fill;
		// only drop it once we emptied it, or it's clearly abandoned.
		if st, err := os.Stat(dir); moved || (err == nil && time.Since(st.ModTime()) > staleDirAge) {
			os.Remove(dir) // only succeeds once empty
		}
	}
}

func moveToNAS(src, want, id string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(dataDir, ".part-"+id) // hidden from the admin list
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != st.Size() {
		err = fmt.Errorf("copied %d of %d bytes", n, st.Size())
	}
	if err == nil {
		if tst, serr := os.Stat(tmp); serr != nil || tst.Size() != st.Size() {
			err = fmt.Errorf("NAS copy size mismatch: %v", serr)
		}
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	name, err := place(tmp, want, id)
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	os.Remove(src)
	return name, nil
}

// nasFatal exits on a stale NFS handle: nothing recovers it short of a
// remount, and docker remounts the volume when it restarts the container.
func nasFatal(err error) {
	if errors.Is(err, syscall.ESTALE) {
		log.Fatalf("NAS mount went stale (%v); exiting for a fresh mount", err)
	}
}

func healthz(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(dataDir)
	if err == nil {
		_, err = f.Readdirnames(1)
		f.Close()
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		nasFatal(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok"))
}

// place claims a name in dataDir for src (a file already in dataDir),
// adding " (2)", " (3)", … rather than ever replacing an existing file.
func place(src, want, id string) (string, error) {
	nameMu.Lock()
	defer nameMu.Unlock()
	base := cleanName(want)
	if base == "" {
		base = "upload-" + id[:min(8, len(id))]
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for i := 1; i <= maxNameTries; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		dst := filepath.Join(dataDir, name)
		if _, err := os.Lstat(dst); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if placeHook != nil {
			if err := placeHook(name); err != nil {
				return "", err
			}
		}
		// Link, not Rename: the owner can write to the share, and link fails
		// if dst appeared since the Lstat where rename would replace it.
		err := os.Link(src, dst)
		switch {
		case err == nil:
			if err := os.Remove(src); err != nil {
				log.Printf("placed %q but could not remove %s: %v", name, src, err)
			}
			return name, nil
		case errors.Is(err, fs.ErrExist):
			// A retransmitted NFS link can report EEXIST although it worked.
			if a, e1 := os.Stat(src); e1 == nil {
				if b, e2 := os.Stat(dst); e2 == nil && os.SameFile(a, b) {
					os.Remove(src)
					return name, nil
				}
			}
			continue
		case linkUnsupported(err):
			return name, os.Rename(src, dst)
		default:
			return "", err
		}
	}
	return "", fmt.Errorf("no free name for %q after %d tries", base, maxNameTries)
}

func linkUnsupported(err error) bool {
	// 524 is Linux's kernel-internal ENOTSUPP, which NFSv4 surfaces.
	for _, e := range []error{syscall.EPERM, syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.EXDEV, syscall.EMLINK, syscall.Errno(524)} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// placeHook runs between choosing a free name and claiming it. Tests use it
// to simulate a concurrent writer on the share or a failing NAS.
var placeHook func(name string) error

func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return '_'
		}
		if disguise(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimLeft(strings.TrimSpace(s), ".")
	if len(s) > 200 {
		ext := filepath.Ext(s)
		if len(ext) > 20 {
			ext = ""
		}
		s = strings.ToValidUTF8(s[:200-len(ext)], "") + ext
	}
	return s
}

// disguise reports characters that make a name display as something else:
// bidi controls, marks and invisible separators. Joiners (ZWJ/ZWNJ) stay —
// emoji sequences and several scripts need them.
func disguise(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	switch r {
	case 0x200B, 0x200E, 0x200F, 0x061C, 0xFEFF:
		return true
	}
	return false
}

// validName rejects anything that isn't a plain, visible file in dataDir.
func validName(name string) bool {
	return name != "" && utf8.ValidString(name) && !strings.HasPrefix(name, ".") &&
		!strings.ContainsAny(name, "/\\") && name == filepath.Base(name)
}

// sweepPartials drops uploads nobody has touched for a week.
func sweepPartials() {
	for {
		sweepOnce()
		time.Sleep(time.Hour)
	}
}

func sweepOnce() {
	infos, _ := filepath.Glob(filepath.Join(partDir, "*.info"))
	for _, info := range infos {
		data := strings.TrimSuffix(info, ".info")
		st, err := os.Stat(data)
		if err == nil && time.Since(st.ModTime()) < partialTTL {
			continue
		}
		for _, p := range []string{data, info, data + ".lock", data + ".stop"} {
			os.Remove(p)
		}
		log.Printf("swept stale partial %s", filepath.Base(data))
	}
	// Forget sightings of uploads that finished or were swept. Stat outside
	// the lock: note() takes it on the upload path.
	seen.Lock()
	ids := make([]string, 0, len(seen.m))
	for id := range seen.m {
		ids = append(ids, id)
	}
	seen.Unlock()
	for _, id := range ids {
		if !fileExists(filepath.Join(partDir, id+".info")) {
			seen.Lock()
			delete(seen.m, id)
			seen.Unlock()
		}
	}
	// Strays with no .info: a crash between tusd creating the data file and
	// its .info, or lock/stop files from the old file locker.
	entries, _ := os.ReadDir(partDir)
	for _, e := range entries {
		id, _, _ := strings.Cut(e.Name(), ".")
		if strings.HasSuffix(e.Name(), ".info") || fileExists(filepath.Join(partDir, id+".info")) {
			continue
		}
		if st, err := e.Info(); err == nil && time.Since(st.ModTime()) > partialTTL {
			os.Remove(filepath.Join(partDir, e.Name()))
			log.Printf("swept stray %s", e.Name())
		}
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ── admin ──

type fileRow struct {
	Name, Link, Download string
	Size                 int64
	Mod                  time.Time
}

type partRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Received int64  `json:"received"`
	Saving   bool   `json:"saving"` // finished, being copied to the NAS
	Age      int64  `json:"age"`    // seconds since the upload was created
	Idle     int64  `json:"idle"`   // seconds since the last byte arrived
	IP       string `json:"ip,omitempty"`
	UA       string `json:"ua,omitempty"`
	Client   string `json:"client,omitempty"` // UA boiled down, e.g. "Safari on macOS"
	Resumes  int    `json:"resumes"`
}

func (p partRow) Percent() int {
	if p.Size == 0 {
		return 100
	}
	return int(p.Received * 100 / p.Size)
}

func adminPage(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		render(w, "login.html", map[string]any{"Failed": r.URL.Query().Has("failed")})
		return
	}
	if currentAuth().MustChange {
		http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
		return
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		nasFatal(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var files []fileRow
	for _, e := range entries {
		if !e.Type().IsRegular() || !validName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileRow{Name: e.Name(), Size: info.Size(), Mod: info.ModTime(), Link: shareLink(e.Name(), info), Download: "/admin/dl/" + url.PathEscape(e.Name())})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Mod.After(files[j].Mod) })
	render(w, "admin.html", map[string]any{"Files": files, "Partials": partials()})
}

func partials() []partRow {
	var rows []partRow
	infos, _ := filepath.Glob(filepath.Join(partDir, "*.info"))
	for _, p := range infos {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var fi handler.FileInfo
		if json.Unmarshal(raw, &fi) != nil {
			continue
		}
		row := partRow{ID: fi.ID, Name: fi.MetaData["filename"], Size: fi.Size, IP: cleanIP(fi.MetaData[metaIP]), UA: clip(fi.MetaData[metaUA], 512)}
		// filestore writes the .info once, at creation.
		if st, err := os.Stat(p); err == nil {
			row.Age = int64(time.Since(st.ModTime()).Seconds())
		}
		if st, err := os.Stat(strings.TrimSuffix(p, ".info")); err == nil {
			row.Received = st.Size()
			row.Idle = int64(time.Since(st.ModTime()).Seconds())
		}
		seen.Lock()
		if s := seen.m[fi.ID]; s != nil {
			row.IP, row.UA, row.Resumes = s.ip, s.ua, s.resumes
		}
		seen.Unlock()
		row.Client = describeUA(row.UA)
		rows = append(rows, row)
	}
	ids, _ := os.ReadDir(outDir)
	for _, id := range ids {
		files, _ := os.ReadDir(filepath.Join(outDir, id.Name()))
		for _, f := range files {
			if info, err := f.Info(); err == nil {
				rows = append(rows, partRow{ID: "outbox/" + id.Name() + "/" + f.Name(), Name: f.Name(), Size: info.Size(), Received: info.Size(), Saving: true})
			}
		}
	}
	return rows
}

// arriving is the Arriving list as JSON, polled by the admin page.
func arriving(w http.ResponseWriter, r *http.Request) {
	rows := partials()
	if rows == nil {
		rows = []partRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(rows)
}

// describeUA names the browser and OS in a User-Agent, or returns "".
func describeUA(ua string) string {
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(ua, s) {
				return true
			}
		}
		return false
	}
	var browser, osName string
	switch { // order matters: most UAs also claim to be Safari and/or Chrome
	case has("Edg/", "EdgA/", "EdgiOS/"):
		browser = "Edge"
	case has("OPR/", "Opera"):
		browser = "Opera"
	case has("Firefox/", "FxiOS/"):
		browser = "Firefox"
	case has("Chrome/", "CriOS/"):
		browser = "Chrome"
	case has("Safari/"):
		browser = "Safari"
	case has("curl/"):
		browser = "curl"
	}
	switch {
	case has("iPhone"):
		osName = "iOS"
	case has("iPad"):
		osName = "iPadOS"
	case has("Android"):
		osName = "Android"
	case has("Windows"):
		osName = "Windows"
	case has("CrOS"):
		osName = "ChromeOS"
	case has("Macintosh", "Mac OS X"):
		osName = "macOS"
	case has("Linux"):
		osName = "Linux"
	}
	switch {
	case browser != "" && osName != "":
		return browser + " on " + osName
	case browser != "":
		return browser
	}
	return osName
}

// adminAuth is persisted to authFile. Hash is bcrypt; MustChange forces a
// new password before anything else in /admin is reachable.
type adminAuth struct {
	Hash       string `json:"hash"`
	MustChange bool   `json:"must_change"`
}

func loadAuth() error {
	raw, err := os.ReadFile(authFile)
	if errors.Is(err, fs.ErrNotExist) {
		h, err := bcrypt.GenerateFromPassword([]byte(defaultPW), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		log.Printf("no %s: admin password reset to the default, change forced on login", authFile)
		return saveAuth(adminAuth{Hash: string(h), MustChange: true})
	}
	if err == nil {
		err = json.Unmarshal(raw, &auth)
	}
	if err != nil || auth.Hash == "" {
		// Keep uploads running; admin stays locked until the file is fixed.
		log.Printf("ADMIN LOCKED: %s is unreadable (%v); delete it to reset the password to the default", authFile, err)
		auth = adminAuth{}
	}
	return nil
}

// saveAuth writes atomically and swaps the in-memory copy. Caller holds
// authMu, except at startup.
func saveAuth(a adminAuth) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(authFile, raw); err != nil {
		return err
	}
	auth = a
	return nil
}

// writeFileAtomic replaces path with raw (mode 0600) so a crash leaves
// either the old or the new contents, never a torn file.
func writeFileAtomic(path string, raw []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync() // rename must not land before the bytes do
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func currentAuth() adminAuth {
	authMu.Lock()
	defer authMu.Unlock()
	return auth
}

// loginDelay is how long each failed login holds up further guesses.
var loginDelay = time.Second

// checkPassword runs with loginSlot held and releases it, after loginDelay
// on failure.
func checkPassword(a adminAuth, pw string) bool {
	defer func() { <-loginSlot }()
	ok := bcrypt.CompareHashAndPassword([]byte(a.Hash), []byte(pw)) == nil
	if !ok {
		time.Sleep(loginDelay)
	}
	return ok
}

// loginSlot serialises password checks site-wide: a failure keeps the slot
// for loginDelay, so guesses run at most one per loginDelay however many
// arrive at once. Waiters give up after loginQueueWait.
var loginSlot = make(chan struct{}, 1)

func login(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	select {
	case loginSlot <- struct{}{}:
	case <-time.After(loginQueueWait):
		http.Error(w, "Too many sign-in attempts. Try again in a minute.", http.StatusTooManyRequests)
		return
	case <-r.Context().Done():
		return
	}
	a := currentAuth()
	ok := checkPassword(a, r.PostFormValue("password"))
	if !ok {
		http.Redirect(w, r, "/admin?failed", http.StatusSeeOther)
		return
	}
	setSession(w, a)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// Sessions are bound to the current hash, so a password change signs out
// every other session.
func setSession(w http.ResponseWriter, a adminAuth) {
	exp := strconv.FormatInt(time.Now().Add(cookieTTL).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: exp + "." + sign("admin|"+exp+"|"+a.Hash), Path: "/",
		MaxAge: int(cookieTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// parseSmallForm caps admin form bodies (nothing legitimate is near the
// limit) and parses them; on failure it has already responded.
func parseSmallForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return false
	}
	return true
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func isAdmin(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	exp, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && time.Now().Unix() < n && hmac.Equal([]byte(mac), []byte(sign("admin|"+exp+"|"+currentAuth().Hash)))
}

// csrf refuses admin POSTs a browser sent from another origin (SameSite=Lax
// alone treats sibling subdomains as same-site). It trusts Sec-Fetch-Site
// first: with Referrer-Policy no-referrer, browsers send Origin: null.
var csrf = http.NewCrossOriginProtection()

func sameOrigin(h http.HandlerFunc) http.HandlerFunc { return csrf.Handler(h).ServeHTTP }

// signedIn only needs a valid session (the change-password page itself).
func signedIn(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

// authed also requires that the default password has been changed.
func authed(h http.HandlerFunc) http.HandlerFunc {
	return signedIn(func(w http.ResponseWriter, r *http.Request) {
		if currentAuth().MustChange {
			http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
			return
		}
		h(w, r)
	})
}

// pwErrors are the only messages the password page shows; ?err= carries a
// key, never text.
var pwErrors = map[string]string{
	"current":  "Current password is wrong.",
	"short":    fmt.Sprintf("Use at least %d characters.", minPWLen),
	"long":     fmt.Sprintf("Use at most %d bytes (a limit of the hashing).", maxPWBytes),
	"mismatch": "The two passwords don't match.",
	"default":  "Pick something other than the default.",
	"save":     "Couldn't save the new password.",
}

func passwordPage(w http.ResponseWriter, r *http.Request) {
	render(w, "password.html", map[string]any{
		"Forced": currentAuth().MustChange,
		"Error":  pwErrors[r.URL.Query().Get("err")],
		"MinLen": minPWLen,
	})
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	authMu.Lock()
	defer authMu.Unlock()
	fail := func(key string) {
		http.Redirect(w, r, "/admin/password?err="+key, http.StatusSeeOther)
	}
	if !auth.MustChange && bcrypt.CompareHashAndPassword([]byte(auth.Hash), []byte(r.PostFormValue("current"))) != nil {
		fail("current")
		return
	}
	pw := r.PostFormValue("new")
	switch {
	case utf8.RuneCountInString(pw) < minPWLen:
		fail("short")
		return
	case len(pw) > maxPWBytes:
		fail("long")
		return
	case pw != r.PostFormValue("confirm"):
		fail("mismatch")
		return
	case pw == defaultPW:
		fail("default")
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err == nil {
		err = saveAuth(adminAuth{Hash: string(h)})
	}
	if err != nil {
		log.Printf("change password: %v", err)
		fail("save")
		return
	}
	log.Printf("admin password changed")
	setSession(w, auth)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func adminDownload(w http.ResponseWriter, r *http.Request) {
	serveFile(w, r, r.PathValue("name"))
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	if name := r.PostFormValue("name"); validName(name) {
		if err := os.Remove(filepath.Join(dataDir, name)); err != nil {
			log.Printf("delete %q: %v", name, err)
		} else {
			log.Printf("deleted %q", name)
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// ── share links ──

// shareToken binds a link to this exact file — name, size and mtime — so
// deleting or replacing the file revokes it for good, even if a later
// upload reuses the name.
func shareToken(name string, st fs.FileInfo) string {
	return sign(fmt.Sprintf("share|%d|%d|%s", st.Size(), st.ModTime().UnixNano(), name))[:22]
}

func shareLink(name string, st fs.FileInfo) string {
	return "/d/" + shareToken(name, st) + "/" + url.PathEscape(name)
}

func shared(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName(name) {
		http.NotFound(w, r)
		return
	}
	st, err := os.Stat(filepath.Join(dataDir, name))
	if err != nil || !st.Mode().IsRegular() || !hmac.Equal([]byte(r.PathValue("tok")), []byte(shareToken(name, st))) {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Has("dl") {
		serveFile(w, r, name)
		return
	}
	// Landing page rather than the file itself, so chat-app link previews
	// don't pull down gigabytes.
	render(w, "share.html", map[string]any{"Name": name, "Size": st.Size(), "Link": shareLink(name, st) + "?dl", "Owner": currentSettings().OwnerName})
}

// ── helpers ──

func serveFile(w http.ResponseWriter, r *http.Request, name string) {
	if !validName(name) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(dataDir, name))
	if err != nil {
		nasFatal(err)
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", contentDisposition(name))
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// contentDisposition builds an attachment header per RFC 6266: an ASCII
// filename= fallback plus filename* percent-encoded as RFC 8187 attr-chars.
func contentDisposition(name string) string {
	var ascii, ext strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			ascii.WriteByte('_')
		} else {
			ascii.WriteRune(r)
		}
	}
	for _, b := range []byte(name) {
		if 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || strings.IndexByte("!#$&+-.^_`|~", b) >= 0 {
			ext.WriteByte(b)
		} else {
			fmt.Fprintf(&ext, "%%%02X", b)
		}
	}
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, ascii.String(), ext.String())
}

func sign(s string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// clientIP is the sender's address: the last X-Forwarded-For hop (the one
// our reverse proxy added; earlier hops are whatever the client claimed),
// else the peer address. Always an IP literal or "", so it's safe to show
// and to put in emails.
func clientIP(h http.Header, remote string) string {
	if xff := h.Values("X-Forwarded-For"); len(xff) > 0 {
		hops := strings.Split(xff[len(xff)-1], ",")
		if ip := cleanIP(hops[len(hops)-1]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	return cleanIP(remote)
}

// cleanIP returns s as a canonical IP address, or "" if it isn't one.
func cleanIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// pageTitle is the upload page heading for the configured owner name.
func pageTitle(owner string) string {
	if owner == "" {
		return "Send files"
	}
	return "Send files to " + owner
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustInt(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		log.Fatalf("bad number %q", s)
	}
	return n
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s must be set", k)
	}
	return v
}
