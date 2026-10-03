package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// settings are edited by the admin at /admin/settings and stored in
// SPOOL_DIR/settings.json (0600: it holds the SMTP password, which has to be
// recoverable). Environment variables seed them the first time only.
type settings struct {
	OwnerName    string `json:"owner_name"`    // "Send files to <OwnerName>"
	PublicURL    string `json:"public_url"`    // used for links in emails
	NotifyTo     string `json:"notify_to"`     // empty = no notifications
	MailFrom     string `json:"mail_from"`     // must be a sender the SMTP server accepts
	SMTPHost     string `json:"smtp_host"`     //
	SMTPPort     int    `json:"smtp_port"`     //
	SMTPSecurity string `json:"smtp_security"` // none | starttls | tls
	SMTPUser     string `json:"smtp_user"`     // empty = no auth
	SMTPPass     string `json:"smtp_pass"`     //
}

var securityModes = []string{"starttls", "tls", "none"}

var (
	settingsFile string
	cfgMu        sync.Mutex
	cfg          settings
)

func settingsFromEnv() settings {
	port, err := strconv.Atoi(envOr("SMTP_PORT", "587"))
	if err != nil {
		port = 587
	}
	return settings{
		OwnerName:    os.Getenv("OWNER_NAME"),
		PublicURL:    strings.TrimRight(os.Getenv("PUBLIC_URL"), "/"),
		NotifyTo:     os.Getenv("NOTIFY_TO"),
		MailFrom:     os.Getenv("MAIL_FROM"),
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     port,
		SMTPSecurity: envOr("SMTP_SECURITY", "starttls"),
		SMTPUser:     os.Getenv("SMTP_USER"),
		SMTPPass:     os.Getenv("SMTP_PASS"),
	}
}

// loadSettings reads settings.json, creating it from the environment on
// first run. A damaged file falls back to the environment without
// overwriting it.
func loadSettings() {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	raw, err := os.ReadFile(settingsFile)
	if errors.Is(err, fs.ErrNotExist) {
		cfg = settingsFromEnv()
		if err := writeFileAtomic(settingsFile, mustJSON(cfg)); err != nil {
			log.Printf("settings: %v", err)
		}
		return
	}
	var s settings
	if err == nil {
		err = json.Unmarshal(raw, &s)
	}
	if err != nil {
		log.Printf("settings: %s unreadable (%v); using environment defaults", settingsFile, err)
		s = settingsFromEnv()
	}
	cfg = s
}

func currentSettings() settings {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return cfg
}

func saveSettings(s settings) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if err := writeFileAtomic(settingsFile, mustJSON(s)); err != nil {
		return err
	}
	cfg = s
	return nil
}

func mustJSON(v any) []byte {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return raw
}

func (s settings) notifyEnabled() bool {
	return s.NotifyTo != "" && s.MailFrom != "" && s.SMTPHost != ""
}

// ── settings page ──

var settingsErrors = map[string]string{
	"owner":    "Name: up to 60 characters, no control characters.",
	"url":      "Site URL must start with https:// or http://.",
	"notify":   "Notification address isn't a valid email address.",
	"from":     "From address isn't a valid email address.",
	"host":     "Mail server host isn't valid.",
	"port":     "Port must be between 1 and 65535.",
	"security": "Pick a security mode.",
	"user":     "Username can't contain line breaks.",
	"save":     "Couldn't save settings.",
}

// lastTest is the result of the most recent "send test email", shown once.
var lastTest struct {
	sync.Mutex
	msg string
	ok  bool
}

func settingsPage(w http.ResponseWriter, r *http.Request) {
	s := currentSettings()
	lastTest.Lock()
	test, testOK := lastTest.msg, lastTest.ok
	lastTest.msg = ""
	lastTest.Unlock()
	render(w, "settings.html", map[string]any{
		"S":        s,
		"HasPass":  s.SMTPPass != "",
		"Modes":    securityModes,
		"Saved":    r.URL.Query().Has("saved"),
		"Error":    settingsErrors[r.URL.Query().Get("err")],
		"Test":     test,
		"TestOK":   testOK,
		"Notifies": s.notifyEnabled(),
	})
}

func saveSettingsForm(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	s, key := settingsFromForm(r, currentSettings())
	if key == "" && saveSettings(s) != nil {
		key = "save"
	}
	if key != "" {
		http.Redirect(w, r, "/admin/settings?err="+key, http.StatusSeeOther)
		return
	}
	log.Printf("settings saved")
	http.Redirect(w, r, "/admin/settings?saved", http.StatusSeeOther)
}

// settingsFromForm validates the form against old; key names the first
// problem (see settingsErrors), or is empty.
func settingsFromForm(r *http.Request, old settings) (settings, string) {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	s := old
	s.OwnerName = f("owner_name")
	if utf8.RuneCountInString(s.OwnerName) > 60 || strings.ContainsFunc(s.OwnerName, isControl) {
		return old, "owner"
	}
	s.PublicURL = strings.TrimRight(f("public_url"), "/")
	if s.PublicURL != "" && !strings.HasPrefix(s.PublicURL, "https://") && !strings.HasPrefix(s.PublicURL, "http://") ||
		strings.ContainsFunc(s.PublicURL, isControl) {
		return old, "url"
	}
	var ok bool
	if s.NotifyTo, ok = emailOrEmpty(f("notify_to")); !ok {
		return old, "notify"
	}
	if s.MailFrom, ok = emailOrEmpty(f("mail_from")); !ok {
		return old, "from"
	}
	s.SMTPHost = f("smtp_host")
	if len(s.SMTPHost) > 253 || strings.ContainsFunc(s.SMTPHost, func(r rune) bool { return isControl(r) || r == ' ' || r == '/' }) {
		return old, "host"
	}
	port, err := strconv.Atoi(f("smtp_port"))
	if err != nil || port < 1 || port > 65535 {
		return old, "port"
	}
	s.SMTPPort = port
	s.SMTPSecurity = f("smtp_security")
	if !contains(securityModes, s.SMTPSecurity) {
		return old, "security"
	}
	s.SMTPUser = f("smtp_user")
	if strings.ContainsFunc(s.SMTPUser, isControl) {
		return old, "user"
	}
	if pw := r.PostFormValue("smtp_pass"); pw != "" {
		s.SMTPPass = pw
	}
	if r.PostFormValue("clear_pass") != "" {
		s.SMTPPass = ""
	}
	return s, ""
}

// emailOrEmpty accepts "" or a single bare address and returns the address.
func emailOrEmpty(v string) (string, bool) {
	if v == "" {
		return "", true
	}
	a, err := mail.ParseAddress(v)
	if err != nil || strings.ContainsFunc(a.Address, isControl) {
		return "", false
	}
	return a.Address, true
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sendTestEmail(w http.ResponseWriter, r *http.Request) {
	s := currentSettings()
	msg, ok := "Test email sent to "+s.NotifyTo+".", true
	if !s.notifyEnabled() {
		msg, ok = "Fill in the notification address, From address and mail server first.", false
	} else if err := sendMail(s, s.NotifyTo, "Test email from uploader", "Notifications are working.\r\n"); err != nil {
		log.Printf("test email: %v", err)
		msg, ok = "Sending failed: "+err.Error(), false
	}
	lastTest.Lock()
	lastTest.msg, lastTest.ok = msg, ok
	lastTest.Unlock()
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// ── notifications ──

// notifyBatch is how long the notifier collects uploads before sending one
// email, so a batch of 30 photos is one message, not 30.
var notifyBatch = 2 * time.Minute

var notifyCh = make(chan string, 1000)

func notifyUpload(name string, size int64) {
	if !currentSettings().notifyEnabled() {
		return
	}
	select {
	case notifyCh <- fmt.Sprintf("%s (%s)", name, humanSize(size)):
	default: // more than 1000 queued: the email would be truncated anyway
	}
}

func notifier() {
	for first := range notifyCh {
		lines := []string{first}
		deadline := time.After(notifyBatch)
	collect:
		for {
			select {
			case l := <-notifyCh:
				lines = append(lines, l)
			case <-deadline:
				break collect
			}
		}
		s := currentSettings()
		if !s.notifyEnabled() {
			continue
		}
		subject, body := uploadEmail(s, lines)
		if err := sendMail(s, s.NotifyTo, subject, body); err != nil {
			log.Printf("notify %s: %v", s.NotifyTo, err)
		}
	}
}

func uploadEmail(s settings, lines []string) (subject, body string) {
	subject = "New upload received"
	if len(lines) > 1 {
		subject = fmt.Sprintf("%d new uploads received", len(lines))
	}
	var b strings.Builder
	b.WriteString(subject + ":\r\n\r\n")
	for _, l := range lines {
		b.WriteString("  " + l + "\r\n")
	}
	if s.PublicURL != "" {
		b.WriteString("\r\n" + s.PublicURL + "/admin\r\n")
	}
	return subject, b.String()
}

// sendMail delivers one plain-text message. Names in the body come from
// cleanName, which removes control characters, so they can't inject headers.
func sendMail(s settings, to, subject, body string) error {
	addr := net.JoinHostPort(s.SMTPHost, strconv.Itoa(s.SMTPPort))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsConf := &tls.Config{ServerName: s.SMTPHost}
	var conn net.Conn
	var err error
	if s.SMTPSecurity == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(time.Minute))
	c, err := smtp.NewClient(conn, s.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello("uploader"); err != nil {
		return err
	}
	if s.SMTPSecurity == "starttls" {
		if err := c.StartTLS(tlsConf); err != nil {
			return err
		}
	}
	if s.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", s.SMTPUser, s.SMTPPass, s.SMTPHost)); err != nil {
			return err
		}
	}
	if err := c.Mail(s.MailFrom); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	fmt.Fprintf(wc, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s",
		s.MailFrom, to, mime.QEncoding.Encode("utf-8", subject), time.Now().Format(time.RFC1123Z), body)
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
