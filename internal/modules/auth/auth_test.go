package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zabaletac3/notify_backend/internal/modules/auth"
	"github.com/zabaletac3/notify_backend/internal/platform/config"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

var (
	pepper  = []byte("0123456789abcdef0123456789abcdef-pepper")
	secret  = []byte("fedcba9876543210fedcba9876543210-jwt!!")
	codeRe  = regexp.MustCompile(`\b(\d{6})\b`)
	authKey = strings.Repeat("A", 43)
	recKey  = strings.Repeat("R", 43)
)

type env struct {
	t    *testing.T
	h    http.Handler
	mail *mailer.MemoryMailer
	svc  *auth.Service
	db   *testdb.DB
	now  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testdb.New(t)
	e := &env{t: t, db: db, mail: &mailer.MemoryMailer{}, now: time.Now().UTC()}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	hasher, err := security.NewAuthKeyHasher(pepper)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewSigner(security.SignerOptions{Secret: secret, Issuer: "t", TTL: 15 * time.Minute, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	limiter := ratelimit.New(db.App, pepper)
	limiter.Now = func() time.Time { return e.now }
	e.svc = auth.NewService(auth.Deps{Pool: db.App, Hasher: hasher, Signer: signer, Limiter: limiter, Mailer: e.mail, Log: log,
		Config: auth.Config{Pepper: pepper, AccessTTL: 15 * time.Minute, RefreshTTL: 30 * 24 * time.Hour, WebBaseURL: "http://web.test"},
		Now:    func() time.Time { return e.now }})
	t.Cleanup(e.svc.Close)
	h := auth.NewHandler(e.svc, log, true)
	e.h = httpserver.NewRouter(&config.Config{MaxBodyBytes: 1 << 20}, log, pinger{}, h.Routes)
	return e
}

type pinger struct{}

func (pinger) Ping(context.Context) error { return nil }

type resp struct {
	Code int
	Body map[string]any
	Raw  string
	Hdr  http.Header
}

func (e *env) call(method, path string, body any, token string, ip string) resp {
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
	if ip == "" {
		ip = "198.51.100.1"
	}
	req.Header.Set("X-Forwarded-For", ip)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return resp{Code: rec.Code, Body: m, Raw: rec.Body.String(), Hdr: rec.Header()}
}

func keys() map[string]any {
	return map[string]any{
		"kdf":                      map[string]any{"alg": "argon2id", "memoryKiB": 1024, "iterations": 1, "parallelism": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA"},
		"wrappedMasterKey":         "a1.AAAAAAAAAAAAAAAA.QUJDRA",
		"recoveryWrappedMasterKey": "a1.BBBBBBBBBBBBBBBB.QUJDRA",
		"keysVersion":              1,
	}
}

func regBody(email string) map[string]any {
	return map[string]any{"userId": uuid.Must(uuid.NewV7()).String(), "fullName": "Ana Pérez", "email": email,
		"acceptedTerms": true, "authKey": authKey, "recoveryAuth": recKey, "keys": keys()}
}

// register crea la cuenta y devuelve el código que recibió por correo.
func (e *env) register(email string) string {
	e.t.Helper()
	before := len(e.mail.Sent())
	if r := e.call("POST", "/auth/register", regBody(email), "", ""); r.Code != 201 {
		e.t.Fatalf("registro: %d %s", r.Code, r.Raw)
	}
	e.svc.Close()
	sent := e.mail.Sent()
	if len(sent) != before+1 {
		e.t.Fatalf("esperaba un correo, hay %d nuevos", len(sent)-before)
	}
	m := codeRe.FindStringSubmatch(sent[len(sent)-1].Text)
	if m == nil {
		e.t.Fatalf("el correo no trae código: %q", sent[len(sent)-1].Text)
	}
	return m[1]
}

func (e *env) verified(email string) map[string]any {
	e.t.Helper()
	code := e.register(email)
	r := e.call("POST", "/auth/verify-email", map[string]any{"email": email, "code": code}, "", "")
	if r.Code != 200 {
		e.t.Fatalf("verify: %d %s", r.Code, r.Raw)
	}
	return r.Body
}

func (e *env) login(email, ak, ip string) resp {
	return e.call("POST", "/auth/login", map[string]any{"email": email, "authKey": ak,
		"device": map[string]any{"name": "Portátil", "platform": "linux"}}, "", ip)
}

func tok(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func TestRegisterVerifyLoginFlow(t *testing.T) {
	e := newEnv(t)
	email := "ana@example.com"

	// prelogin de una cuenta nueva (no existe aún): parámetros falsos, estables y con la misma forma.
	p1 := e.call("POST", "/auth/prelogin", map[string]string{"email": email}, "", "")
	p2 := e.call("POST", "/auth/prelogin", map[string]string{"email": "  ANA@example.com "}, "", "")
	if p1.Code != 200 || p1.Raw != p2.Raw {
		t.Fatalf("prelogin falso inestable: %s vs %s", p1.Raw, p2.Raw)
	}

	code := e.register(email)

	// Antes de verificar, el login con la contraseña correcta responde email-not-verified.
	if r := e.login(email, authKey, ""); r.Code != 403 || r.Body["code"] != "email-not-verified" {
		t.Fatalf("login sin verificar: %d %s", r.Code, r.Raw)
	}
	// Código incorrecto.
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	if r := e.call("POST", "/auth/verify-email", map[string]any{"email": email, "code": bad}, "", ""); r.Code != 422 {
		t.Fatalf("código malo: %d %s", r.Code, r.Raw)
	}
	r := e.call("POST", "/auth/verify-email", map[string]any{"email": email, "code": code}, "", "")
	if r.Code != 200 || tok(r.Body, "accessToken") == "" || tok(r.Body, "refreshToken") == "" {
		t.Fatalf("verify: %d %s", r.Code, r.Raw)
	}
	if u := r.Body["user"].(map[string]any); u["emailVerified"] != true || u["email"] != email {
		t.Fatalf("usuario: %v", u)
	}
	// El código solo vale una vez.
	if r := e.call("POST", "/auth/verify-email", map[string]any{"email": email, "code": code}, "", ""); r.Code != 422 {
		t.Fatalf("código reutilizado: %d", r.Code)
	}

	// prelogin ahora devuelve los parámetros reales (la sal del registro).
	if p := e.call("POST", "/auth/prelogin", map[string]string{"email": email}, "", ""); !strings.Contains(p.Raw, `"memoryKiB":1024`) {
		t.Fatalf("prelogin real: %s", p.Raw)
	}

	// Login correcto: sesión con claves.
	l := e.login(email, authKey, "")
	if l.Code != 200 || l.Body["keys"] == nil || tok(l.Body, "accessToken") == "" {
		t.Fatalf("login: %d %s", l.Code, l.Raw)
	}
	if k := l.Body["keys"].(map[string]any); k["wrappedMasterKey"] != "a1.AAAAAAAAAAAAAAAA.QUJDRA" || k["keysVersion"] != float64(1) {
		t.Fatalf("claves: %v", k)
	}

	// /auth/session con el token.
	s := e.call("GET", "/auth/session", nil, tok(l.Body, "accessToken"), "")
	if s.Code != 200 || s.Body["user"].(map[string]any)["email"] != email || s.Body["accessToken"] != nil {
		t.Fatalf("session: %d %s", s.Code, s.Raw)
	}
}

func TestLoginErrorsAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	wrong := e.login("ana@example.com", strings.Repeat("B", 43), "10.0.0.1")
	ghost := e.login("nadie@example.com", authKey, "10.0.0.2")
	if wrong.Code != 401 || wrong.Raw != ghost.Raw || wrong.Body["code"] != "invalid-credentials" {
		t.Fatalf("respuestas distintas: %s vs %s", wrong.Raw, ghost.Raw)
	}
	// Entradas mal formadas: la misma respuesta, sin detalles.
	for _, b := range []map[string]any{{"email": "x", "authKey": authKey}, {"email": "ana@example.com", "authKey": "corta"}} {
		if r := e.call("POST", "/auth/login", b, "", ""); r.Code != 401 || r.Raw != wrong.Raw {
			t.Fatalf("entrada inválida distinguible: %d %s", r.Code, r.Raw)
		}
	}
}

func TestLoginBruteForceIsBlocked(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	ip := "203.0.113.9"
	for i := 0; i < 5; i++ {
		if r := e.login("ana@example.com", strings.Repeat("B", 43), ip); r.Code != 401 {
			t.Fatalf("fallo %d: %d", i+1, r.Code)
		}
	}
	r := e.login("ana@example.com", authKey, ip) // aun con la clave correcta
	if r.Code != 429 || r.Body["kind"] != "rate-limited" || r.Hdr.Get("Retry-After") == "" {
		t.Fatalf("debía bloquear: %d %s", r.Code, r.Raw)
	}
	// Otra IP no queda bloqueada para esa cuenta (el bloqueo es por correo+IP).
	if r := e.login("ana@example.com", authKey, "203.0.113.10"); r.Code != 200 {
		t.Fatalf("otra IP: %d %s", r.Code, r.Raw)
	}
	// Pasado el bloqueo vuelve a funcionar.
	e.now = e.now.Add(16 * time.Minute)
	if r := e.login("ana@example.com", authKey, ip); r.Code != 200 {
		t.Fatalf("tras el bloqueo: %d %s", r.Code, r.Raw)
	}
}

func TestRegisterDoesNotRevealExistingAccounts(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	n := len(e.mail.Sent())
	fresh := e.call("POST", "/auth/register", regBody("luis@example.com"), "", "")
	dup := e.call("POST", "/auth/register", regBody("ana@example.com"), "", "")
	e.svc.Close()
	if dup.Code != 201 || fresh.Code != 201 {
		t.Fatalf("registro: %d %d", fresh.Code, dup.Code)
	}
	if strings.ReplaceAll(dup.Raw, "ana", "x") != strings.ReplaceAll(fresh.Raw, "luis", "x") {
		t.Fatalf("respuestas distinguibles: %s vs %s", dup.Raw, fresh.Raw)
	}
	sent := e.mail.Sent()[n:]
	var gotCode, gotNotice bool
	for _, m := range sent {
		if m.To == "luis@example.com" && codeRe.MatchString(m.Text) {
			gotCode = true
		}
		if m.To == "ana@example.com" && strings.Contains(m.Subject, "intentó registrar") {
			gotNotice = true
		}
		if m.To == "ana@example.com" && codeRe.MatchString(m.Text) {
			t.Fatal("se envió un código al dueño de la cuenta existente")
		}
	}
	if !gotCode || !gotNotice {
		t.Fatalf("correos incorrectos: código=%v aviso=%v", gotCode, gotNotice)
	}
	// La cuenta original sigue intacta: su login funciona.
	if r := e.login("ana@example.com", authKey, ""); r.Code != 200 {
		t.Fatalf("la cuenta existente se alteró: %d", r.Code)
	}
}

func TestUnverifiedRegistrationIsReplacedNotSquatted(t *testing.T) {
	e := newEnv(t)
	// Un atacante registra el correo de la víctima, sin verificarlo.
	attackerBody := regBody("victima@example.com")
	attackerBody["authKey"] = strings.Repeat("X", 43)
	e.call("POST", "/auth/register", attackerBody, "", "")
	e.svc.Close()
	// La víctima se registra después: toma el correo.
	e.now = e.now.Add(time.Minute)
	e.verified("victima@example.com")
	if r := e.login("victima@example.com", strings.Repeat("X", 43), ""); r.Code != 401 {
		t.Fatalf("la clave del atacante no debe servir: %d", r.Code)
	}
	if r := e.login("victima@example.com", authKey, ""); r.Code != 200 {
		t.Fatalf("la víctima debe poder entrar: %d", r.Code)
	}
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t)
	mut := func(f func(map[string]any)) resp {
		b := regBody("ana@example.com")
		f(b)
		return e.call("POST", "/auth/register", b, "", "")
	}
	cases := map[string]func(map[string]any){
		"correo":            func(b map[string]any) { b["email"] = "no-es-correo" },
		"correo con nombre": func(b map[string]any) { b["email"] = "Ana <ana@example.com>" },
		"términos":          func(b map[string]any) { b["acceptedTerms"] = false },
		"nombre corto":      func(b map[string]any) { b["fullName"] = "A" },
		"userId":            func(b map[string]any) { b["userId"] = "admin" },
		"authKey":           func(b map[string]any) { b["authKey"] = "corta" },
		"iguales":           func(b map[string]any) { b["recoveryAuth"] = b["authKey"] },
		"kdf débil": func(b map[string]any) {
			k := keys()
			k["kdf"].(map[string]any)["memoryKiB"] = 8
			b["keys"] = k
		},
		"kdf enorme": func(b map[string]any) {
			k := keys()
			k["kdf"].(map[string]any)["memoryKiB"] = 1 << 30
			b["keys"] = k
		},
		"texto sin cifrar": func(b map[string]any) {
			k := keys()
			k["wrappedMasterKey"] = "mi clave en claro"
			b["keys"] = k
		},
	}
	for name, f := range cases {
		if r := mut(f); r.Code != 422 || r.Body["kind"] != "validation" {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	// Campos desconocidos y tipo de contenido erróneo.
	b := regBody("ana@example.com")
	b["isAdmin"] = true
	if r := e.call("POST", "/auth/register", b, "", ""); r.Code != 422 {
		t.Errorf("campo desconocido aceptado: %d", r.Code)
	}
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/auth/register", strings.NewReader("x"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 422 {
		t.Errorf("text/plain aceptado: %d", rec.Code)
	}
	if len(e.mail.Sent()) != 0 {
		t.Error("se enviaron correos por registros inválidos")
	}
}

func TestVerifyCodeAttemptsAreLimited(t *testing.T) {
	e := newEnv(t)
	code := e.register("ana@example.com")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		e.call("POST", "/auth/verify-email", map[string]any{"email": "ana@example.com", "code": wrong}, "", "")
	}
	// Agotados los intentos, ni siquiera el código correcto sirve (hay que pedir otro).
	r := e.call("POST", "/auth/verify-email", map[string]any{"email": "ana@example.com", "code": code}, "", "")
	if r.Code != 422 && r.Code != 429 {
		t.Fatalf("tras 5 intentos fallidos debía rechazar: %d %s", r.Code, r.Raw)
	}
}

func TestResendCodeRespectsGapAndHidesAccounts(t *testing.T) {
	e := newEnv(t)
	e.register("ana@example.com")
	n := len(e.mail.Sent())
	if r := e.call("POST", "/auth/resend-code", map[string]string{"email": "ana@example.com"}, "", ""); r.Code != 204 {
		t.Fatalf("%d", r.Code)
	}
	if r := e.call("POST", "/auth/resend-code", map[string]string{"email": "nadie@example.com"}, "", ""); r.Code != 204 {
		t.Fatalf("%d", r.Code)
	}
	e.svc.Close()
	if len(e.mail.Sent()) != n {
		t.Fatal("reenvió antes de 60 s o a una cuenta inexistente")
	}
	e.now = e.now.Add(61 * time.Second)
	e.call("POST", "/auth/resend-code", map[string]string{"email": "ana@example.com"}, "", "")
	e.svc.Close()
	if len(e.mail.Sent()) != n+1 {
		t.Fatal("debía reenviar pasados 60 s")
	}
	// El código nuevo sustituye al anterior.
	code := codeRe.FindStringSubmatch(e.mail.Sent()[n].Text)[1]
	if r := e.call("POST", "/auth/verify-email", map[string]any{"email": "ana@example.com", "code": code}, "", ""); r.Code != 200 {
		t.Fatalf("código nuevo: %d %s", r.Code, r.Raw)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	l := e.login("ana@example.com", authKey, "")
	r1 := tok(l.Body, "refreshToken")

	n := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": r1}, "", "")
	if n.Code != 200 || tok(n.Body, "refreshToken") == "" || tok(n.Body, "refreshToken") == r1 || tok(n.Body, "accessToken") == "" {
		t.Fatalf("refresh: %d %s", n.Code, n.Raw)
	}
	r2 := tok(n.Body, "refreshToken")

	// Reusar el token ya gastado: se revoca toda la familia (también el r2 legítimo).
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": r1}, "", ""); r.Code != 401 || r.Body["kind"] != "session-expired" {
		t.Fatalf("reuso: %d %s", r.Code, r.Raw)
	}
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": r2}, "", ""); r.Code != 401 {
		t.Fatalf("la familia debía quedar revocada: %d %s", r.Code, r.Raw)
	}
	var n2 int
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE event = 'refresh-reuse'`).Scan(&n2); err != nil || n2 != 1 {
		t.Fatalf("auditoría: %d %v", n2, err)
	}
	// Tokens inventados o vacíos.
	for _, bad := range []string{"", "corto", strings.Repeat("a", 43)} {
		if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": bad}, "", ""); r.Code != 401 {
			t.Fatalf("token inventado %q: %d", bad, r.Code)
		}
	}
}

func TestRefreshExpires(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	l := e.login("ana@example.com", authKey, "")
	e.now = e.now.Add(31 * 24 * time.Hour)
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": tok(l.Body, "refreshToken")}, "", ""); r.Code != 401 {
		t.Fatalf("token caducado aceptado: %d", r.Code)
	}
}

func TestProtectedRoutesNeedValidToken(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	for _, path := range []string{"/auth/session", "/devices"} {
		if r := e.call("GET", path, nil, "", ""); r.Code != 401 || r.Body["kind"] != "session-expired" {
			t.Errorf("%s sin token: %d %s", path, r.Code, r.Raw)
		}
		if r := e.call("GET", path, nil, "basura", ""); r.Code != 401 {
			t.Errorf("%s con basura: %d", path, r.Code)
		}
	}
	l := e.login("ana@example.com", authKey, "")
	e.now = e.now.Add(20 * time.Minute) // el token de acceso caduca a los 15 min
	if r := e.call("GET", "/auth/session", nil, tok(l.Body, "accessToken"), ""); r.Code != 401 || r.Body["kind"] != "session-expired" {
		t.Fatalf("token caducado: %d %s", r.Code, r.Raw)
	}
}

func TestDevicesAndRevocation(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	a := e.login("ana@example.com", authKey, "")
	b := e.call("POST", "/auth/login", map[string]any{"email": "ana@example.com", "authKey": authKey,
		"device": map[string]any{"name": "Móvil", "platform": "android"}}, "", "")
	ta, tb := tok(a.Body, "accessToken"), tok(b.Body, "accessToken")

	list := e.call("GET", "/devices", nil, ta, "")
	var devs []map[string]any
	_ = json.Unmarshal([]byte(list.Raw), &devs)
	if list.Code != 200 || len(devs) < 2 {
		t.Fatalf("lista: %d %s", list.Code, list.Raw)
	}
	var bID, aID string
	for _, d := range devs {
		if d["name"] == "Móvil" {
			bID = d["id"].(string)
		}
		if d["current"] == true {
			aID = d["id"].(string)
		}
	}
	if bID == "" || aID == "" || aID == bID {
		t.Fatalf("dispositivos: %s", list.Raw)
	}

	// No se puede quitar el dispositivo actual.
	if r := e.call("DELETE", "/devices/"+aID, nil, ta, ""); r.Code != 422 {
		t.Fatalf("quitar el actual: %d %s", r.Code, r.Raw)
	}
	// Id inválido / inexistente / de otra cuenta → 404.
	e.verified("luis@example.com")
	other := e.login("luis@example.com", authKey, "")
	var od []map[string]any
	_ = json.Unmarshal([]byte(e.call("GET", "/devices", nil, tok(other.Body, "accessToken"), "").Raw), &od)
	for _, id := range []string{"no-uuid", uuid.NewString(), od[0]["id"].(string)} {
		if r := e.call("DELETE", "/devices/"+id, nil, ta, ""); r.Code != 404 {
			t.Fatalf("quitar %q: %d %s", id, r.Code, r.Raw)
		}
	}

	// A quita al dispositivo B: el siguiente uso de B recibe device-revoked y no puede renovar.
	if r := e.call("DELETE", "/devices/"+bID, nil, ta, ""); r.Code != 204 {
		t.Fatalf("quitar B: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/auth/session", nil, tb, ""); r.Code != 401 || r.Body["kind"] != "device-revoked" {
		t.Fatalf("B tras ser quitado: %d %s", r.Code, r.Raw)
	}
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": tok(b.Body, "refreshToken")}, "", ""); r.Code != 401 {
		t.Fatalf("B no debe renovar: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/auth/session", nil, ta, ""); r.Code != 200 {
		t.Fatalf("A no debe verse afectado: %d", r.Code)
	}
	if after := e.call("GET", "/devices", nil, ta, ""); strings.Contains(after.Raw, "Móvil") {
		t.Fatalf("B sigue en la lista: %s", after.Raw)
	}
}

func TestLogoutRevokesTheDevice(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	l := e.login("ana@example.com", authKey, "")
	if r := e.call("POST", "/auth/logout", nil, tok(l.Body, "accessToken"), ""); r.Code != 204 {
		t.Fatalf("logout: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/auth/session", nil, tok(l.Body, "accessToken"), ""); r.Code != 401 {
		t.Fatalf("el token sigue valiendo tras el logout: %d", r.Code)
	}
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": tok(l.Body, "refreshToken")}, "", ""); r.Code != 401 {
		t.Fatalf("el refresh sigue valiendo tras el logout: %d", r.Code)
	}
}

func TestTokensCannotCrossAccounts(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.verified("luis@example.com")
	a := e.login("ana@example.com", authKey, "")
	l := e.login("luis@example.com", authKey, "")
	var devs []map[string]any
	_ = json.Unmarshal([]byte(e.call("GET", "/devices", nil, tok(a.Body, "accessToken"), "").Raw), &devs)
	if len(devs) != 2 { // el de la verificación y el del login, ambos de Ana
		t.Fatalf("Ana debía ver 2 dispositivos: %d", len(devs))
	}
	for _, d := range devs {
		var owner string
		if err := e.db.Admin.QueryRow(context.Background(), `SELECT u.email FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1`, d["id"]).Scan(&owner); err != nil || owner != "ana@example.com" {
			t.Fatalf("la lista de Ana contiene un dispositivo de %q (%v)", owner, err)
		}
	}
	s := e.call("GET", "/auth/session", nil, tok(l.Body, "accessToken"), "")
	if s.Body["user"].(map[string]any)["email"] != "luis@example.com" {
		t.Fatalf("sesión equivocada: %s", s.Raw)
	}
}

func TestPreLoginIsRateLimitedAndValidated(t *testing.T) {
	e := newEnv(t)
	if r := e.call("POST", "/auth/prelogin", map[string]string{"email": "x"}, "", ""); r.Code != 422 {
		t.Fatalf("%d", r.Code)
	}
	var last resp
	for i := 0; i < 40; i++ {
		last = e.call("POST", "/auth/prelogin", map[string]string{"email": "ana@example.com"}, "", "192.0.2.77")
	}
	if last.Code != 429 {
		t.Fatalf("prelogin sin límite: %d", last.Code)
	}
}

func TestDatabaseNeverStoresSecrets(t *testing.T) {
	e := newEnv(t)
	code := e.register("ana@example.com")
	var dump string
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT
		(SELECT string_agg(auth_key_hash::text || coalesce(recovery_auth_hash::text,'') || keys::text, '|') FROM users) ||
		(SELECT coalesce(string_agg(code_hash::text, '|'), '') FROM verification_codes)`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{authKey, recKey, code} {
		if strings.Contains(dump, secret) {
			t.Fatalf("la base de datos contiene %q en claro", secret)
		}
	}
	l := e.login("ana@example.com", authKey, "") // sin verificar → 403, pero no debe guardar tokens
	_ = l
	e.verified("luis@example.com")
	lg := e.login("luis@example.com", authKey, "")
	var plain int
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT count(*) FROM refresh_tokens WHERE token_hash = $1::bytea`, []byte(tok(lg.Body, "refreshToken"))).Scan(&plain); err != nil || plain != 0 {
		t.Fatalf("token de renovación en claro: %d %v", plain, err)
	}
}
