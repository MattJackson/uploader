package main

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSMTP accepts plain SMTP and sends each message's DATA on the channel.
func fakeSMTP(t *testing.T) (host string, port int, msgs chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	msgs = make(chan string, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				say := func(s string) { c.Write([]byte(s + "\r\n")) }
				say("220 fake")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(cmd, "DATA"):
						say("354 go")
						var b strings.Builder
						for {
							l, err := r.ReadString('\n')
							if err != nil || l == ".\r\n" {
								break
							}
							b.WriteString(l)
						}
						msgs <- b.String()
						say("250 ok")
					case strings.HasPrefix(cmd, "QUIT"):
						say("221 bye")
						return
					default:
						say("250 ok")
					}
				}
			}(c)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return h, port, msgs
}

func mailSettings(host string, port int) settings {
	return settings{NotifyTo: "owner@example.com", MailFrom: "uploader@example.com",
		SMTPHost: host, SMTPPort: port, SMTPSecurity: "none", PublicURL: "https://upload.example.com"}
}

func TestSettingsFormValidates(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	base := url.Values{"smtp_port": {"587"}, "smtp_security": {"starttls"}}
	with := func(k, v string) url.Values {
		f := url.Values{}
		for kk, vv := range base {
			f[kk] = vv
		}
		f.Set(k, v)
		return f
	}
	for name, form := range map[string]url.Values{
		"header injection in notify": with("notify_to", "a@b.com\r\nBcc: x@y.com"),
		"two addresses":              with("notify_to", "a@b.com, c@d.com"),
		"bad port":                   with("smtp_port", "70000"),
		"bad mode":                   with("smtp_security", "ssl3"),
		"host with space":            with("smtp_host", "mail example.com"),
		"url scheme":                 with("public_url", "javascript:alert(1)"),
		"owner control char":         with("owner_name", "Bob\x07"),
	} {
		rec := postForm(mux, "/admin/settings", form, c)
		if !strings.Contains(rec.Header().Get("Location"), "err=") {
			t.Errorf("%s accepted", name)
		}
	}
	good := with("notify_to", "Me <me@example.com>")
	good.Set("smtp_pass", "s3cret")
	postForm(mux, "/admin/settings", good, c)
	if got := currentSettings(); got.NotifyTo != "me@example.com" || got.SMTPPass != "s3cret" {
		t.Fatalf("saved %+v", got)
	}
	postForm(mux, "/admin/settings", with("notify_to", "me@example.com"), c) // blank password field
	if currentSettings().SMTPPass != "s3cret" {
		t.Fatal("blank password field wiped the saved password")
	}
	if fi, err := os.Stat(settingsFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("settings.json: %v %v", fi.Mode(), err)
	}
	if body := get(t, mux, "/admin/settings", c).Body.String(); strings.Contains(body, "s3cret") {
		t.Fatal("settings page echoes the SMTP password")
	}
}

func TestSettingsSeededFromEnvOnce(t *testing.T) {
	testDirs(t)
	t.Setenv("OWNER_NAME", "Alex")
	t.Setenv("SMTP_HOST", "mail.example.com")
	loadSettings()
	if s := currentSettings(); s.OwnerName != "Alex" || s.SMTPHost != "mail.example.com" {
		t.Fatalf("env not used: %+v", s)
	}
	t.Setenv("OWNER_NAME", "Changed")
	loadSettings()
	if currentSettings().OwnerName != "Alex" {
		t.Fatal("env overrode saved settings")
	}
}

func TestTestEmailButton(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	host, port, msgs := fakeSMTP(t)
	saveSettings(mailSettings(host, port))
	postForm(mux, "/admin/settings/test", url.Values{}, c)
	select {
	case m := <-msgs:
		if !strings.Contains(m, "To: owner@example.com") {
			t.Fatalf("test email: %q", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no test email sent")
	}
	if body := get(t, mux, "/admin/settings", c).Body.String(); !strings.Contains(body, "Test email sent") {
		t.Fatal("result not shown")
	}
}

func TestNotifierBatchesUploads(t *testing.T) {
	testDirs(t)
	host, port, msgs := fakeSMTP(t)
	saveSettings(mailSettings(host, port))
	old := notifyBatch
	notifyBatch = 100 * time.Millisecond
	t.Cleanup(func() { notifyBatch = old })
	go notifier(startCh, notifyCh)
	notifyUpload("holiday.mp4", 4<<30, sender("203.0.113.7", safariMac))
	notifyUpload("résumé.pdf", 2048, "")
	select {
	case m := <-msgs:
		for _, want := range []string{"Subject: 2 new uploads received", "holiday.mp4 (4.0 GB) from 203.0.113.7, Safari on macOS", "résumé.pdf (2.0 KB)\r\n", "https://upload.example.com/admin"} {
			if !strings.Contains(m, want) {
				t.Errorf("email missing %q:\n%s", want, m)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no notification sent")
	}
	select {
	case m := <-msgs:
		t.Fatalf("second email for the same batch: %q", m)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestNoNotificationWhenUnconfigured(t *testing.T) {
	testDirs(t)
	notifyUpload("x", 1, "")
	select {
	case l := <-notifyCh:
		t.Fatalf("queued %+v with notifications off", l)
	default:
	}
}

func TestOwnerNameOnPages(t *testing.T) {
	data, _ := testDirs(t)
	mux, _ := newMux()
	if body := get(t, mux, "/", nil).Body.String(); !strings.Contains(body, "<h1>Send files</h1>") {
		t.Fatal("neutral title missing when no owner set")
	}
	saveSettings(settings{OwnerName: "<b>Sam</b>"})
	body := get(t, mux, "/", nil).Body.String()
	if !strings.Contains(body, "Send files to &lt;b&gt;Sam&lt;/b&gt;") {
		t.Fatalf("owner name not shown escaped: %s", body)
	}
	writeFile(t, filepath.Join(data, "f.txt"), "x")
	c := adminCookie(t)
	link := linkRE.FindStringSubmatch(get(t, mux, "/admin", c).Body.String())[1]
	if share := get(t, mux, link, nil).Body.String(); !strings.Contains(share, "shared by &lt;b&gt;Sam") {
		t.Fatal("owner missing on share page")
	}
	_ = http.StatusOK
}

const safariMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"

// creating an upload queues a "started" notice; the email leaves out
// uploads that finished while the batch collected.
func TestStartEmailListsOnlyUnfinished(t *testing.T) {
	testDirs(t)
	saveSettings(mailSettings("127.0.0.1", 25))
	mux, _ := newMux()
	going := filepath.Base(tusCreate(t, mux, 10))
	done := filepath.Base(tusCreate(t, mux, 10))
	var batch []notice
	for range 2 {
		select {
		case n := <-startCh:
			batch = append(batch, n)
		default:
			t.Fatal("create didn't queue a start notice")
		}
	}
	if batch[0].id != going || batch[1].id != done {
		t.Fatalf("notice ids %q %q, want %q %q", batch[0].id, batch[1].id, going, done)
	}
	os.Remove(filepath.Join(partDir, done+".info")) // what toOutbox does
	subject, body := startEmail(currentSettings(), batch)
	if subject != "Upload started" || strings.Count(body, "f.bin") != 1 {
		t.Fatalf("subject %q body %q", subject, body)
	}
	os.Remove(filepath.Join(partDir, going+".info"))
	if subject, _ := startEmail(currentSettings(), batch); subject != "" {
		t.Fatalf("emailed %q with every upload already finished", subject)
	}
}

// each email can be turned off on its own, and a settings form without the
// checkboxes (e.g. a page loaded before they existed) leaves them alone.
func TestNotifyToggles(t *testing.T) {
	testDirs(t)
	mux, _ := newMux()
	c := adminCookie(t)
	if s := settingsFromEnv(); s.MuteStart || s.MuteDone {
		t.Fatal("emails should default to on")
	}
	form := url.Values{"smtp_port": {"587"}, "smtp_security": {"starttls"}, "notify_to": {"me@example.com"},
		"mail_from": {"up@example.com"}, "smtp_host": {"smtp.example.com"}, "notify_flags": {"1"}, "notify_done": {"1"}}
	postForm(mux, "/admin/settings", form, c)
	if s := currentSettings(); !s.MuteStart || s.MuteDone {
		t.Fatalf("after unticking start: %+v", s)
	}
	notifyStart("x", "a", 1, "")
	notifyUpload("a", 1, "")
	if len(startCh) != 0 || len(notifyCh) != 1 {
		t.Fatalf("queued start=%d done=%d, want 0 and 1", len(startCh), len(notifyCh))
	}
	<-notifyCh
	form.Del("notify_flags")
	form.Del("notify_done")
	postForm(mux, "/admin/settings", form, c)
	if s := currentSettings(); !s.MuteStart || s.MuteDone {
		t.Fatalf("form without the checkboxes changed them: %+v", s)
	}
	if body := get(t, mux, "/admin/settings", c).Body.String(); !strings.Contains(body, `name="notify_done" value="1" checked`) ||
		strings.Contains(body, `name="notify_start" value="1" checked`) {
		t.Fatal("checkboxes don't reflect the saved settings")
	}
}

// a "started" email only lists uploads that have been running startBatch,
// later ones wait for the next email, and emails are at least notifyBatch
// apart.
func TestStartEmailsWaitForEachUpload(t *testing.T) {
	testDirs(t)
	host, port, msgs := fakeSMTP(t)
	saveSettings(mailSettings(host, port))
	oldB, oldS := notifyBatch, startBatch
	notifyBatch, startBatch = 400*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { notifyBatch, startBatch = oldB, oldS })
	a, b := newPartial(t, 10, 0), newPartial(t, 10, 0)
	ch := make(chan notice, 10)
	go batchMail(ch, 0, func() time.Duration { return startBatch }, startEmail)
	start := time.Now()
	ch <- notice{a, "first.bin", time.Now()}
	time.Sleep(150 * time.Millisecond)
	ch <- notice{b, "second.bin", time.Now()}
	m := <-msgs
	if !strings.Contains(m, "first.bin") || strings.Contains(m, "second.bin") {
		t.Fatalf("first email: %q", m)
	}
	select {
	case m := <-msgs:
		if !strings.Contains(m, "second.bin") || strings.Contains(m, "first.bin") {
			t.Fatalf("second email: %q", m)
		}
		if gap := time.Since(start); gap < 600*time.Millisecond {
			t.Fatalf("second email after %v, want the %v gap respected", gap, notifyBatch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("held notice never sent")
	}
}
