package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

var good = Message{To: "ana@example.com", Subject: "Código", Text: "123456", IdempotencyKey: "k1"}

func TestValidate(t *testing.T) {
	bad := []Message{
		{To: "ana@example.com\r\nBcc: x@y.z", Subject: "s", Text: "t"},
		{To: "ana@example.com", Subject: "s\nBcc: x", Text: "t"},
		{To: "Ana <ana@example.com>", Subject: "s", Text: "t"},
		{To: "no-es-correo", Subject: "s", Text: "t"},
		{To: "ana@example.com", Subject: "", Text: "t"},
		{To: "ana@example.com", Subject: "s", Text: " "},
	}
	for i, m := range bad {
		if err := m.Validate(); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("caso %d debía ser inválido: %v", i, err)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMaskEmail(t *testing.T) {
	if got := MaskEmail("ana@example.com"); got != "a***@example.com" {
		t.Fatal(got)
	}
	if got := MaskEmail("x"); got != "***" {
		t.Fatal(got)
	}
}

func TestMemoryMailerConcurrent(t *testing.T) {
	m := &MemoryMailer{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Send(context.Background(), good) }()
	}
	wg.Wait()
	if len(m.Sent()) != 20 {
		t.Fatal("faltan envíos")
	}
	m.Err = errors.New("falla")
	if err := m.Send(context.Background(), good); err == nil {
		t.Fatal("debía devolver el error configurado")
	}
}

func TestLogMailerValidates(t *testing.T) {
	var buf, plain bytes.Buffer
	l := LogMailer{Log: slog.New(slog.NewJSONHandler(&buf, nil)), Out: &plain}
	if err := l.Send(context.Background(), Message{To: "x"}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatal("debía rechazar")
	}
	if err := l.Send(context.Background(), good); err != nil || !strings.Contains(buf.String(), "123456") {
		t.Fatalf("no registró el correo: %v", err)
	}
	// Y en texto legible, con destinatario y código, para leerlo en la terminal.
	if !strings.Contains(plain.String(), "123456") || !strings.Contains(plain.String(), good.To) {
		t.Fatalf("falta el correo legible: %q", plain.String())
	}
}

func TestResendSends(t *testing.T) {
	var gotAuth, gotKey string
	var payload resendPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewResend("re_secret", "AxoNote <no-reply@x.com>", srv.URL)
	if err := m.Send(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer re_secret" || gotKey != "k1" || payload.To[0] != good.To || payload.From != "AxoNote <no-reply@x.com>" {
		t.Fatalf("petición incorrecta: %q %q %+v", gotAuth, gotKey, payload)
	}
}

func TestResendErrorClassification(t *testing.T) {
	for status, want := range map[int]error{429: ErrTemporary, 500: ErrTemporary, 503: ErrTemporary, 400: ErrRejected, 401: ErrRejected, 422: ErrRejected} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		err := NewResend("k", "f@x.com", srv.URL).Send(context.Background(), good)
		srv.Close()
		if !errors.Is(err, want) {
			t.Errorf("estado %d: %v", status, err)
		}
	}
}

func TestResendNetworkErrorDoesNotLeakKey(t *testing.T) {
	m := NewResend("re_supersecret", "f@x.com", "http://127.0.0.1:1")
	err := m.Send(context.Background(), good)
	if !errors.Is(err, ErrTemporary) || strings.Contains(err.Error(), "re_supersecret") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error filtra datos: %v", err)
	}
}

func TestFactory(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	if m, err := New(Options{Provider: "log"}, log); err != nil || m == nil {
		t.Fatal(err)
	}
	if _, ok := mustNew(t, Options{Provider: "resend", ResendAPIKey: "k", From: "f@x.com"}, log).(*ResendMailer); !ok {
		t.Fatal("debía ser Resend")
	}
	if _, err := New(Options{Provider: "resend"}, log); err == nil {
		t.Fatal("sin clave debía fallar")
	}
	if _, err := New(Options{Provider: "smtp"}, log); err == nil {
		t.Fatal("proveedor desconocido debía fallar")
	}
}

func mustNew(t *testing.T, o Options, l *slog.Logger) Mailer {
	t.Helper()
	m, err := New(o, l)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
