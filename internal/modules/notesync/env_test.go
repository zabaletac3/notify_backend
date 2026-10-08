package notesync_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zabaletac3/notify_backend/internal/modules/auth"
	"github.com/zabaletac3/notify_backend/internal/modules/notesync"
	"github.com/zabaletac3/notify_backend/internal/platform/config"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

var (
	pepper = []byte("0123456789abcdef0123456789abcdef-pepper")
	secret = []byte("fedcba9876543210fedcba9876543210-jwt!!")
	codeRe = regexp.MustCompile(`\b(\d{6})\b`)
	ak     = strings.Repeat("A", 43)
	rk     = strings.Repeat("R", 43)
)

const (
	sealedKey = "a1.AAAAAAAAAAAAAAAA.QUJDRA"
	sealedPl  = "a1.BBBBBBBBBBBBBBBB.QUJDREVGRw"
	sealedPl2 = "a1.CCCCCCCCCCCCCCCC.QUJDREVGRw"
)

type env struct {
	t    *testing.T
	h    http.Handler
	mail *mailer.MemoryMailer
	auth *auth.Service
	db   *testdb.DB
}

type Limits = notesync.Limits

func newEnv(t *testing.T, lim notesync.Limits) *env {
	t.Helper()
	db := testdb.New(t)
	e := &env{t: t, db: db, mail: &mailer.MemoryMailer{}}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	hasher, _ := security.NewAuthKeyHasher(pepper)
	signer, err := security.NewSigner(security.SignerOptions{Secret: secret, Issuer: "t", TTL: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	e.auth = auth.NewService(auth.Deps{Pool: db.App, Hasher: hasher, Signer: signer, Limiter: ratelimit.New(db.App, pepper), Mailer: e.mail, Log: log,
		Config: auth.Config{Pepper: pepper, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, WebBaseURL: "http://web.test"}})
	t.Cleanup(e.auth.Close)
	ah := auth.NewHandler(e.auth, log, true)
	if lim.MaxChanges == 0 {
		lim = notesync.Limits{MaxChanges: 500, MaxNotes: 10000, MaxFolders: 500}
	}
	sh := notesync.NewHandler(notesync.NewService(db.App, lim), log, func(ctx context.Context) (string, string, bool) {
		p, ok := auth.PrincipalFrom(ctx)
		return p.UserID, p.DeviceID, ok
	})
	protected := func(r chi.Router) {
		r.Group(func(r chi.Router) { r.Use(ah.Require); sh.Routes(r) })
	}
	e.h = httpserver.NewRouter(&config.Config{MaxBodyBytes: 1 << 20, MaxSyncBodyBytes: 8 << 20}, log, pinger{}, ah.Routes, protected)
	return e
}

type pinger struct{}

func (pinger) Ping(context.Context) error { return nil }

type resp struct {
	Code int
	Body map[string]any
	Raw  string
}

func (e *env) do(method, path string, body any, token string) resp {
	e.t.Helper()
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
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return resp{Code: rec.Code, Body: m, Raw: rec.Body.String()}
}

// device es una sesión (token) de una cuenta.
type device struct {
	e     *env
	token string
	id    string
}

// account crea una cuenta verificada y devuelve su primera sesión; login() abre otra.
func (e *env) account(email string) *device {
	e.t.Helper()
	body := map[string]any{"userId": uuid.Must(uuid.NewV7()).String(), "fullName": "Ana Pérez", "email": email, "acceptedTerms": true,
		"authKey": ak, "recoveryAuth": rk, "keys": map[string]any{
			"kdf":              map[string]any{"alg": "argon2id", "memoryKiB": 1024, "iterations": 1, "parallelism": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA"},
			"wrappedMasterKey": sealedKey, "recoveryWrappedMasterKey": sealedKey, "keysVersion": 1}}
	if r := e.do("POST", "/auth/register", body, ""); r.Code != 201 {
		e.t.Fatalf("registro: %d %s", r.Code, r.Raw)
	}
	e.auth.Close()
	sent := e.mail.Sent()
	code := codeRe.FindStringSubmatch(sent[len(sent)-1].Text)[1]
	r := e.do("POST", "/auth/verify-email", map[string]any{"email": email, "code": code}, "")
	if r.Code != 200 {
		e.t.Fatalf("verificación: %d %s", r.Code, r.Raw)
	}
	return e.login(email, "Portátil")
}

func (e *env) login(email, name string) *device {
	e.t.Helper()
	r := e.do("POST", "/auth/login", map[string]any{"email": email, "authKey": ak, "device": map[string]any{"name": name, "platform": "linux"}}, "")
	if r.Code != 200 {
		e.t.Fatalf("login: %d %s", r.Code, r.Raw)
	}
	tok := r.Body["accessToken"].(string)
	claims, err := e.auth.Authenticate(context.Background(), tok)
	if err != nil {
		e.t.Fatal(err)
	}
	return &device{e: e, token: tok, id: claims.DeviceID}
}

// ── Atajos para construir cambios ───────────────────────────────

func newID() string { return uuid.Must(uuid.NewV7()).String() }

const ts = "2026-03-01T10:00:00Z"

func noteUpsert(id string, base int, folder any, payload string) map[string]any {
	return map[string]any{"entity": "note", "id": id, "op": "upsert", "baseRevision": base,
		"data": map[string]any{"folderId": folder, "createdAt": ts, "updatedAt": ts, "deletedAt": nil, "wrappedKey": sealedKey, "payload": payload}}
}

func folderUpsert(id string, base int, payload string) map[string]any {
	return map[string]any{"entity": "folder", "id": id, "op": "upsert", "baseRevision": base,
		"data": map[string]any{"createdAt": ts, "updatedAt": ts, "wrappedKey": sealedKey, "payload": payload}}
}

func del(entity, id string, base int) map[string]any {
	return map[string]any{"entity": entity, "id": id, "op": "delete", "baseRevision": base}
}

// sync envía cambios con el cursor dado y devuelve la respuesta.
func (d *device) sync(cursor any, changes ...map[string]any) resp {
	d.e.t.Helper()
	if changes == nil {
		changes = []map[string]any{}
	}
	return d.e.do("POST", "/sync", map[string]any{"deviceId": "ignorado", "deviceName": "ignorado", "cursor": cursor, "changes": changes}, d.token)
}

func list(r resp, key string) []map[string]any {
	var out []map[string]any
	arr, _ := r.Body[key].([]any)
	for _, v := range arr {
		out = append(out, v.(map[string]any))
	}
	return out
}

func (r resp) cursor() string { s, _ := r.Body["cursor"].(string); return s }

func (r resp) String() string { return fmt.Sprintf("%d %s", r.Code, r.Raw) }
