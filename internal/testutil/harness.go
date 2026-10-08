// Package testutil monta la API completa (auth + sync + compartir) sobre una base de datos de prueba.
// Solo lo usan las pruebas de integración de los módulos.
package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zabaletac3/notify_backend/internal/modules/account"
	"github.com/zabaletac3/notify_backend/internal/modules/auth"
	"github.com/zabaletac3/notify_backend/internal/modules/notesync"
	"github.com/zabaletac3/notify_backend/internal/modules/share"
	"github.com/zabaletac3/notify_backend/internal/platform/config"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

var (
	Pepper = []byte("0123456789abcdef0123456789abcdef-pepper")
	secret = []byte("fedcba9876543210fedcba9876543210-jwt!!")
	codeRe = regexp.MustCompile(`\b(\d{6})\b`)
	// AuthKey y RecoveryKey son las pruebas de contraseña que usan todas las cuentas de prueba.
	AuthKey     = "A" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	RecoveryKey = "R" + "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
)

const (
	SealedKey = "a1.AAAAAAAAAAAAAAAA.QUJDRA"
	SealedA   = "a1.BBBBBBBBBBBBBBBB.QUJDREVGRw"
	SealedB   = "a1.CCCCCCCCCCCCCCCC.QUJDREVGRw"
)

// Env es la API de prueba.
type Env struct {
	T    *testing.T
	H    http.Handler
	Mail *mailer.MemoryMailer
	Auth *auth.Service
	DB   *testdb.DB
	Now  time.Time
}

// New monta la API. El reloj de las cuentas y del limitador es e.Now.
func New(t *testing.T) *Env {
	t.Helper()
	db := testdb.New(t)
	e := &Env{T: t, DB: db, Mail: &mailer.MemoryMailer{}, Now: time.Now().UTC()}
	now := func() time.Time { return e.Now }
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	hasher, _ := security.NewAuthKeyHasher(Pepper)
	signer, err := security.NewSigner(security.SignerOptions{Secret: secret, Issuer: "t", TTL: 15 * time.Minute, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	limiter := ratelimit.New(db.App, Pepper)
	limiter.Now = now
	e.Auth = auth.NewService(auth.Deps{Pool: db.App, Hasher: hasher, Signer: signer, Limiter: limiter, Mailer: e.Mail, Log: log, Now: now,
		Config: auth.Config{Pepper: Pepper, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, WebBaseURL: "http://web.test"}})
	t.Cleanup(e.Auth.Close)
	ah := auth.NewHandler(e.Auth, log, true)
	principal := func(ctx context.Context) (string, string, bool) {
		p, ok := auth.PrincipalFrom(ctx)
		return p.UserID, p.DeviceID, ok
	}
	sh := notesync.NewHandler(notesync.NewService(db.App, notesync.Limits{MaxChanges: 500, MaxNotes: 10000, MaxFolders: 500}), log, principal)
	shr := share.NewHandler(share.NewService(db.App, limiter), log, func(ctx context.Context) (string, bool) { u, _, ok := principal(ctx); return u, ok }, true)
	acc := account.NewHandler(account.NewService(db.App, 1<<30), log, func(ctx context.Context) (string, bool) { u, _, ok := principal(ctx); return u, ok })
	protected := func(r chi.Router) {
		r.Group(func(r chi.Router) { r.Use(ah.Require); sh.Routes(r); shr.PrivateRoutes(r); acc.Routes(r) })
	}
	e.H = httpserver.NewRouter(&config.Config{MaxBodyBytes: 1 << 20, MaxSyncBodyBytes: 8 << 20}, log, pinger{}, ah.Routes, protected, shr.PublicRoutes)
	return e
}

type pinger struct{}

func (pinger) Ping(context.Context) error { return nil }

// Resp es una respuesta HTTP ya leída.
type Resp struct {
	Code int
	Body map[string]any
	Raw  string
	Hdr  http.Header
}

// Do hace una petición a /v1.
func (e *Env) Do(method, path string, body any, token, ip string) Resp {
	e.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, "/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ip == "" {
		ip = "198.51.100.1"
	}
	req.Header.Set("X-Forwarded-For", ip)
	rec := httptest.NewRecorder()
	e.H.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return Resp{Code: rec.Code, Body: m, Raw: rec.Body.String(), Hdr: rec.Header()}
}

// Account crea una cuenta verificada y devuelve su token de acceso.
func (e *Env) Account(email string) string {
	e.T.Helper()
	body := map[string]any{"userId": uuid.Must(uuid.NewV7()).String(), "fullName": "Ana Pérez", "email": email, "acceptedTerms": true,
		"authKey": AuthKey, "recoveryAuth": RecoveryKey, "keys": map[string]any{
			"kdf":              map[string]any{"alg": "argon2id", "memoryKiB": 1024, "iterations": 1, "parallelism": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA"},
			"wrappedMasterKey": SealedKey, "recoveryWrappedMasterKey": SealedKey, "keysVersion": 1}}
	if r := e.Do("POST", "/auth/register", body, "", ""); r.Code != 201 {
		e.T.Fatalf("registro: %d %s", r.Code, r.Raw)
	}
	e.Auth.Close()
	sent := e.Mail.Sent()
	code := codeRe.FindStringSubmatch(sent[len(sent)-1].Text)[1]
	r := e.Do("POST", "/auth/verify-email", map[string]any{"email": email, "code": code}, "", "")
	if r.Code != 200 {
		e.T.Fatalf("verificación: %d %s", r.Code, r.Raw)
	}
	return r.Body["accessToken"].(string)
}

// NewID devuelve un UUID v7.
func NewID() string { return uuid.Must(uuid.NewV7()).String() }

// CreateNote sube una nota con /sync y devuelve su id.
func (e *Env) CreateNote(token string, trashed bool) string {
	e.T.Helper()
	id := NewID()
	var deleted any
	if trashed {
		deleted = "2026-03-01T10:00:00Z"
	}
	r := e.Do("POST", "/sync", map[string]any{"deviceId": "x", "deviceName": "x", "cursor": nil, "changes": []map[string]any{{
		"entity": "note", "id": id, "op": "upsert", "baseRevision": 0,
		"data": map[string]any{"folderId": nil, "createdAt": "2026-03-01T10:00:00Z", "updatedAt": "2026-03-01T10:00:00Z",
			"deletedAt": deleted, "wrappedKey": SealedKey, "payload": SealedA}}}}, token, "")
	if r.Code != 200 {
		e.T.Fatalf("crear nota: %d %s", r.Code, r.Raw)
	}
	return id
}
