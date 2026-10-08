package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zabaletac3/notify_backend/internal/platform/config"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestRouter(db Pinger) (http.Handler, *bytes.Buffer) {
	var buf bytes.Buffer
	cfg := &config.Config{MaxBodyBytes: 16, MaxSyncBodyBytes: 64, AllowedOrigins: []string{"https://app.example.com"}}
	return NewRouter(cfg, slog.New(slog.NewJSONHandler(&buf, nil)), db), &buf
}

func do(h http.Handler, method, path string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthAndReady(t *testing.T) {
	h, _ := newTestRouter(fakeDB{})
	if got := do(h, "GET", "/health", "", nil).Code; got != 200 {
		t.Fatalf("health %d", got)
	}
	if got := do(h, "GET", "/ready", "", nil).Code; got != 200 {
		t.Fatalf("ready %d", got)
	}
	h, _ = newTestRouter(fakeDB{err: errors.New("down: password=x")})
	rec := do(h, "GET", "/ready", "", nil)
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("ready caído: %d %s", rec.Code, rec.Body)
	}
}

func TestSecurityHeadersAndTrace(t *testing.T) {
	h, _ := newTestRouter(fakeDB{})
	rec := do(h, "GET", "/health", "", map[string]string{"x-trace-id": "bad id\n<script>"})
	for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control", "Referrer-Policy"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("falta %s", k)
		}
	}
	if id := rec.Header().Get("x-trace-id"); strings.ContainsAny(id, " <>\n") || len(id) < 8 {
		t.Fatalf("traza insegura aceptada: %q", id)
	}
	if rec := do(h, "GET", "/health", "", map[string]string{"x-trace-id": "abc12345-xyz"}); rec.Header().Get("x-trace-id") != "abc12345-xyz" {
		t.Fatal("debía conservar una traza válida")
	}
}

func TestBodyLimit(t *testing.T) {
	h, _ := newTestRouter(fakeDB{})
	if rec := do(h, "POST", "/health", strings.Repeat("a", 100), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("esperaba 413, fue %d", rec.Code)
	}
}

func TestCORSClosedList(t *testing.T) {
	h, _ := newTestRouter(fakeDB{})
	ok := do(h, "OPTIONS", "/health", "", map[string]string{"Origin": "https://app.example.com", "Access-Control-Request-Method": "GET"})
	if ok.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatal("origen permitido sin cabecera CORS")
	}
	bad := do(h, "OPTIONS", "/health", "", map[string]string{"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"})
	if bad.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("origen ajeno permitido")
	}
}

func TestCORSAllowsCredentialsAndSessionHeader(t *testing.T) {
	h, _ := newTestRouter(fakeDB{})
	pre := map[string]string{
		"Origin":                         "https://app.example.com",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "X-Apunte-Session",
	}
	ok := do(h, "OPTIONS", "/health", "", pre)
	if got := ok.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO = %q", got)
	}
	if ok.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("con cookies debe permitir credenciales: %v", ok.Header())
	}
	if !strings.Contains(ok.Header().Get("Access-Control-Allow-Headers"), "X-Apunte-Session") {
		t.Fatalf("no permite X-Apunte-Session: %q", ok.Header().Get("Access-Control-Allow-Headers"))
	}
	// Con credenciales nunca se responde un origen comodín.
	if ok.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("con credenciales no se admite el comodín de origen")
	}

	pre["Origin"] = "https://evil.com"
	bad := do(h, "OPTIONS", "/health", "", pre)
	if bad.Header().Get("Access-Control-Allow-Origin") != "" || bad.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("un origen ajeno no debe recibir CORS: %v", bad.Header())
	}
}

func TestRecoverHidesPanic(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := Recover(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secreto interno") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", "/", nil))
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != 500 || strings.Contains(string(body), "secreto") {
		t.Fatalf("pánico expuesto: %d %s", rec.Code, body)
	}
}

func TestUnknownRoute(t *testing.T) {
	h, _ := newTestRouter(fakeDB{})
	if got := do(h, "GET", "/nope", "", nil).Code; got != 404 {
		t.Fatalf("404 esperado, fue %d", got)
	}
}

func TestClientIP(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name  string
		r     *http.Request
		trust bool
		want  string
	}{
		{"sin proxy ignora la cabecera", mk("203.0.113.5:4000", "6.6.6.6"), false, "203.0.113.5"},
		{"con proxy usa la última entrada", mk("10.0.0.2:4000", "6.6.6.6, 198.51.100.7"), true, "198.51.100.7"},
		{"con proxy y una sola entrada", mk("10.0.0.2:4000", "198.51.100.7"), true, "198.51.100.7"},
		{"con proxy y entrada inválida cae a la conexión", mk("10.0.0.2:4000", "no-es-ip"), true, "10.0.0.2"},
		{"con proxy sin cabecera", mk("10.0.0.2:4000", ""), true, "10.0.0.2"},
		{"IPv6", mk("[2001:db8::1]:4000", ""), false, "2001:db8::1"},
		{"remoto ilegible", mk("???", ""), false, "unknown"},
	}
	for _, c := range cases {
		if got := ClientIP(c.r, c.trust); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
