package mailer

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeSMTP es un servidor SMTP mínimo (sin TLS, solo para pruebas en 127.0.0.1) que guarda lo que recibe.
type fakeSMTP struct {
	ln      net.Listener
	mu      sync.Mutex
	auth    string
	rcpt    string
	mailFrm string
	data    string
	// rcptReply permite simular un rechazo (p. ej. "550 no existe") del destinatario.
	rcptReply string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, rcptReply: "250 ok"}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	w("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w("250-fake")
			w("250 AUTH PLAIN")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = line
			f.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.mu.Lock()
			f.mailFrm = line
			f.mu.Unlock()
			w("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = line
			reply := f.rcptReply
			f.mu.Unlock()
			w(reply)
		case up == "DATA":
			w("354 go")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			f.mu.Lock()
			f.data = sb.String()
			f.mu.Unlock()
			w("250 queued")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func testSMTP(t *testing.T, f *fakeSMTP) *SMTPMailer {
	t.Helper()
	m, err := NewSMTP("127.0.0.1", f.port(), "ana@gmail.com", "secreto", "Apunte <ana@gmail.com>")
	if err != nil {
		t.Fatal(err)
	}
	m.requireTLS = false // el servidor de pruebas no tiene TLS
	return m
}

func TestSMTPSend(t *testing.T) {
	f := newFakeSMTP(t)
	m := testSMTP(t, f)
	msg := Message{To: "bob@example.com", Subject: "Código de verificación ñ", Text: "Tu código: 123456", HTML: "<p>123456</p>"}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.mailFrm, "<ana@gmail.com>") || !strings.Contains(f.rcpt, "<bob@example.com>") {
		t.Fatalf("sobre incorrecto: %q %q", f.mailFrm, f.rcpt)
	}
	if f.auth == "" {
		t.Fatal("no se autenticó")
	}
	for _, want := range []string{"From: \"Apunte\" <ana@gmail.com>", "To: bob@example.com", "Subject: =?utf-8?q?", "multipart/alternative", "text/plain", "text/html", "123456"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("falta %q en el mensaje:\n%s", want, f.data)
		}
	}
}

func TestSMTPPlainTextOnly(t *testing.T) {
	f := newFakeSMTP(t)
	if err := testSMTP(t, f).Send(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(f.data, "multipart") || !strings.Contains(f.data, "Content-Type: text/plain") {
		t.Fatalf("sin HTML debe ser texto plano:\n%s", f.data)
	}
}

func TestSMTPInvalidMessage(t *testing.T) {
	f := newFakeSMTP(t)
	err := testSMTP(t, f).Send(context.Background(), Message{To: "x\r\nBcc: a@b.c", Subject: "s", Text: "t"})
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("debía ser inválido: %v", err)
	}
}

func TestSMTPRejectedAndTemporary(t *testing.T) {
	f := newFakeSMTP(t)
	m := testSMTP(t, f)

	f.mu.Lock()
	f.rcptReply = "550 no existe"
	f.mu.Unlock()
	if err := m.Send(context.Background(), good); !errors.Is(err, ErrRejected) {
		t.Fatalf("5xx debe ser rechazo definitivo: %v", err)
	}

	f.mu.Lock()
	f.rcptReply = "451 intente luego"
	f.mu.Unlock()
	if err := m.Send(context.Background(), good); !errors.Is(err, ErrTemporary) {
		t.Fatalf("4xx debe ser transitorio: %v", err)
	}
}

func TestSMTPUnreachableIsTemporary(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nadie escucha
	m, err := NewSMTP("127.0.0.1", port, "u", "p", "a@b.co")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), good); !errors.Is(err, ErrTemporary) {
		t.Fatalf("sin servidor debe ser transitorio: %v", err)
	}
}

func TestSMTPRequiresSTARTTLS(t *testing.T) {
	f := newFakeSMTP(t) // no ofrece STARTTLS
	m, err := NewSMTP("127.0.0.1", f.port(), "u", "p", "a@b.co")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), good); err == nil {
		t.Fatal("sin STARTTLS no debe enviarse la contraseña")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" {
		t.Fatal("no debe haberse autenticado en claro")
	}
}

func TestNewSMTPBadFrom(t *testing.T) {
	if _, err := NewSMTP("h", 587, "u", "p", "no es correo"); err == nil {
		t.Fatal("MAIL_FROM inválido debe fallar")
	}
}

func TestFactorySMTP(t *testing.T) {
	if _, err := New(Options{Provider: "smtp", From: "a@b.co"}, nil); err == nil {
		t.Fatal("faltan datos de SMTP")
	}
	m, err := New(Options{Provider: "smtp", From: "a@b.co", SMTPHost: "smtp.gmail.com", SMTPPort: 587, SMTPUser: "u", SMTPPassword: "p"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(*SMTPMailer); !ok {
		t.Fatalf("tipo inesperado: %T", m)
	}
}
