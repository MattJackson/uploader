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
	go notifier()
	notifyUpload("holiday.mp4", 4<<30)
	notifyUpload("résumé.pdf", 2048)
	select {
	case m := <-msgs:
		for _, want := range []string{"Subject: 2 new uploads received", "holiday.mp4 (4.0 GB)", "résumé.pdf (2.0 KB)", "https://upload.example.com/admin"} {
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
	notifyUpload("x", 1)
	select {
	case l := <-notifyCh:
		t.Fatalf("queued %q with notifications off", l)
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
