package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zabaletac3/notify_backend/internal/platform/oidc"
)

// ── Auxiliares del flujo de Google ──────────────────────────────

func newVerifier(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// googleLogin recorre start → navegación (proveedor simulado) → callback y devuelve el `code` de
// resultado (o el código de error del fragmento) para el verifier dado.
func (e *env) googleLogin(verifier string) (result string, errCode string) {
	e.t.Helper()
	s := e.call("POST", "/auth/google/start", map[string]any{"challenge": challengeOf(verifier)}, "", "")
	if s.Code != 200 {
		e.t.Fatalf("google start: %d %s", s.Code, s.Raw)
	}
	su, err := url.Parse(tok(s.Body, "url"))
	if err != nil {
		e.t.Fatalf("url de autorización: %v", err)
	}
	cb := e.call("GET", "/auth/google/callback?code="+url.QueryEscape(su.Query().Get("code"))+
		"&state="+url.QueryEscape(su.Query().Get("state")), nil, "", "")
	if cb.Code != 302 {
		e.t.Fatalf("google callback: %d %s", cb.Code, cb.Raw)
	}
	loc := cb.Hdr.Get("Location")
	i := strings.Index(loc, "#")
	if i < 0 {
		e.t.Fatalf("callback sin fragmento: %s", loc)
	}
	q, err := url.ParseQuery(loc[i+1:])
	if err != nil {
		e.t.Fatalf("fragmento: %v", err)
	}
	return q.Get("code"), q.Get("error")
}

// googleExchange canjea el resultado del flujo con el verifier usado.
func (e *env) googleExchange(result, verifier string) resp {
	e.t.Helper()
	return e.call("POST", "/auth/google/exchange", map[string]any{"code": result, "verifier": verifier}, "", "")
}

func googleIdentity(sub, email string) oidc.Identity {
	return oidc.Identity{Subject: sub, Email: email, EmailVerified: true, Name: "Persona Google"}
}

// googleRegister crea la cuenta por Google de principio a fin y devuelve la sesión y el userId.
func (e *env) googleRegister(sub, email string) (map[string]any, string) {
	e.t.Helper()
	e.fake.Identity = googleIdentity(sub, email)
	ver := newVerifier(e.t)
	result, errc := e.googleLogin(ver)
	if errc != "" {
		e.t.Fatalf("callback devolvió error %q", errc)
	}
	ex := e.googleExchange(result, ver)
	if ex.Code != 200 || ex.Body["status"] != "signup-required" {
		e.t.Fatalf("exchange: %d %s", ex.Code, ex.Raw)
	}
	if ex.Body["email"] != email {
		e.t.Fatalf("correo del ticket: %s", ex.Raw)
	}
	body := map[string]any{"signupToken": tok(ex.Body, "signupToken"), "userId": uuid.Must(uuid.NewV7()).String(),
		"fullName": "Persona Google", "acceptedTerms": true, "authKey": authKey, "recoveryAuth": recKey, "keys": keys()}
	r := e.call("POST", "/auth/google/register", body, "", "")
	if r.Code != 200 {
		e.t.Fatalf("register con google: %d %s", r.Code, r.Raw)
	}
	u := r.Body["user"].(map[string]any)
	return r.Body, u["id"].(string)
}

// ── Pruebas ─────────────────────────────────────────────────────

func TestGoogleRegisterCreatesVerifiedAccount(t *testing.T) {
	e := newEnv(t)
	sess, uid := e.googleRegister("sub-reg", "nueva@example.com")
	if tok(sess, "accessToken") == "" || sess["keys"] == nil {
		t.Fatalf("la sesión de registro debe traer tokens y claves: %v", sess)
	}
	u := sess["user"].(map[string]any)
	if u["emailVerified"] != true || u["hasGoogle"] != true || u["email"] != "nueva@example.com" {
		t.Fatalf("usuario: %v", u)
	}
	// /me refleja hasGoogle.
	me := e.call("GET", "/me", nil, tok(sess, "accessToken"), "")
	if me.Body["hasGoogle"] != true {
		t.Fatalf("hasGoogle en /me: %s", me.Raw)
	}
	// Identidad guardada y cuenta verificada; sin correo de verificación.
	var n int
	if err := e.db.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM user_identities WHERE provider='google' AND subject='sub-reg' AND user_id=$1`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("identidad: %d %v", n, err)
	}
	var verified bool
	_ = e.db.Admin.QueryRow(context.Background(), `SELECT email_verified_at IS NOT NULL FROM users WHERE id=$1`, uid).Scan(&verified)
	if !verified {
		t.Fatal("la cuenta de Google debe nacer verificada")
	}
	e.svc.Close()
	if len(e.mail.Sent()) != 0 {
		t.Fatalf("no debía enviarse correo de verificación: %d", len(e.mail.Sent()))
	}
}

func TestGoogleLoginLinkedIdentity(t *testing.T) {
	e := newEnv(t)
	_, uid := e.googleRegister("sub-login", "login@example.com")

	e.fake.Identity = googleIdentity("sub-login", "login@example.com")
	ver := newVerifier(t)
	result, errc := e.googleLogin(ver)
	if errc != "" {
		t.Fatalf("error %q", errc)
	}
	ex := e.googleExchange(result, ver)
	if ex.Code != 200 || ex.Body["status"] != "authenticated" {
		t.Fatalf("login google: %d %s", ex.Code, ex.Raw)
	}
	us := ex.Body["session"].(map[string]any)["user"].(map[string]any)
	if us["id"] != uid {
		t.Fatalf("cuenta equivocada: %s", ex.Raw)
	}
	if ex.Body["session"].(map[string]any)["keys"] == nil {
		t.Fatalf("la sesión debe traer claves: %s", ex.Raw)
	}
}

func TestGoogleDoesNotBypassMFA(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-mfa", "mfa@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)
	e.advance()

	e.fake.Identity = googleIdentity("sub-mfa", "mfa@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)
	ex := e.googleExchange(result, ver)
	if ex.Code != 200 || ex.Body["status"] != "mfa-required" || tok(ex.Body, "mfaToken") == "" {
		t.Fatalf("google con MFA debía pedir el segundo paso: %d %s", ex.Code, ex.Raw)
	}
	if _, ok := ex.Body["session"]; ok {
		t.Fatalf("el reto no debe traer sesión: %s", ex.Raw)
	}
	r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(ex.Body, "mfaToken"), "code": e.totpNow(secret)}, "", "")
	if r.Code != 200 || tok(r.Body, "accessToken") == "" {
		t.Fatalf("segundo paso tras Google: %d %s", r.Code, r.Raw)
	}
}

func TestGoogleLinkRequiredAndNeverAutoLinks(t *testing.T) {
	e := newEnv(t)
	e.verified("ya@example.com") // cuenta verificada por correo

	e.fake.Identity = googleIdentity("sub-link", "ya@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)
	ex := e.googleExchange(result, ver)
	if ex.Code != 200 || ex.Body["status"] != "link-required" {
		t.Fatalf("debía pedir vincular: %d %s", ex.Code, ex.Raw)
	}
	if ex.Body["email"] != "ya@example.com" || ex.Body["kdf"] == nil {
		t.Fatalf("link-required incompleto: %s", ex.Raw)
	}
	// No se vinculó automáticamente por coincidencia de correo.
	var n int
	_ = e.db.Admin.QueryRow(context.Background(), `SELECT count(*) FROM user_identities WHERE subject='sub-link'`).Scan(&n)
	if n != 0 {
		t.Fatal("no debe haber auto-vinculación por correo")
	}

	// Contraseña errónea: 401 y cuenta para los límites del login.
	if r := e.call("POST", "/auth/google/link", map[string]any{"linkToken": tok(ex.Body, "linkToken"), "authKey": strings.Repeat("Z", 43)}, "", ""); r.Code != 401 {
		t.Fatalf("link con contraseña errónea: %d %s", r.Code, r.Raw)
	}
	// Contraseña correcta: vincula y abre sesión.
	r := e.call("POST", "/auth/google/link", map[string]any{"linkToken": tok(ex.Body, "linkToken"), "authKey": authKey}, "", "")
	if r.Code != 200 || tok(r.Body, "accessToken") == "" {
		t.Fatalf("link: %d %s", r.Code, r.Raw)
	}
	_ = e.db.Admin.QueryRow(context.Background(), `SELECT count(*) FROM user_identities WHERE subject='sub-link'`).Scan(&n)
	if n != 1 {
		t.Fatal("la identidad debía quedar vinculada")
	}

	// La siguiente vez entra directo.
	ver2 := newVerifier(t)
	result2, _ := e.googleLogin(ver2)
	ex2 := e.googleExchange(result2, ver2)
	if ex2.Body["status"] != "authenticated" {
		t.Fatalf("tras vincular: %s", ex2.Raw)
	}
}

func TestGoogleEmailChangeKeepsSubject(t *testing.T) {
	e := newEnv(t)
	_, uid := e.googleRegister("sub-mail", "viejo@example.com")
	if _, err := e.db.Admin.Exec(context.Background(), `UPDATE users SET email='nuevo@example.com' WHERE id=$1`, uid); err != nil {
		t.Fatal(err)
	}
	e.fake.Identity = googleIdentity("sub-mail", "viejo@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)
	ex := e.googleExchange(result, ver)
	if ex.Body["status"] != "authenticated" {
		t.Fatalf("se identifica por sub, no por correo: %s", ex.Raw)
	}
	if ex.Body["session"].(map[string]any)["user"].(map[string]any)["id"] != uid {
		t.Fatal("debe entrar a la misma cuenta")
	}
}

func TestGoogleCallbackUnverifiedEmail(t *testing.T) {
	e := newEnv(t)
	id := googleIdentity("sub-unverified", "sinverificar@example.com")
	id.EmailVerified = false
	e.fake.Identity = id
	ver := newVerifier(t)
	_, errc := e.googleLogin(ver)
	if errc != "email-unverified" {
		t.Fatalf("correo sin verificar debía dar #error=email-unverified, dio %q", errc)
	}
}

func TestGoogleStateReuseAndExpiry(t *testing.T) {
	e := newEnv(t)
	e.fake.Identity = googleIdentity("sub-state", "state@example.com")
	ver := newVerifier(t)
	s := e.call("POST", "/auth/google/start", map[string]any{"challenge": challengeOf(ver)}, "", "")
	su, _ := url.Parse(tok(s.Body, "url"))
	code, state := su.Query().Get("code"), su.Query().Get("state")
	path := "/auth/google/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)

	first := e.call("GET", path, nil, "", "")
	if first.Code != 302 || !strings.Contains(first.Hdr.Get("Location"), "#code=") {
		t.Fatalf("primer callback: %d %s", first.Code, first.Hdr.Get("Location"))
	}
	// Reusar el state: ticket ya consumido.
	again := e.call("GET", path, nil, "", "")
	if !strings.Contains(again.Hdr.Get("Location"), "#error=") {
		t.Fatalf("reuso de state aceptado: %s", again.Hdr.Get("Location"))
	}
	// Caducado.
	s2 := e.call("POST", "/auth/google/start", map[string]any{"challenge": challengeOf(newVerifier(t))}, "", "")
	su2, _ := url.Parse(tok(s2.Body, "url"))
	e.now = e.now.Add(11 * time.Minute)
	exp := e.call("GET", "/auth/google/callback?code="+url.QueryEscape(su2.Query().Get("code"))+"&state="+url.QueryEscape(su2.Query().Get("state")), nil, "", "")
	if !strings.Contains(exp.Hdr.Get("Location"), "#error=") {
		t.Fatalf("state caducado aceptado: %s", exp.Hdr.Get("Location"))
	}
}

func TestGoogleResultReuseAndVerifierMismatch(t *testing.T) {
	e := newEnv(t)
	e.fake.Identity = googleIdentity("sub-reuse", "reuse@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)

	if ex := e.googleExchange(result, newVerifier(t)); ex.Code != 422 || ex.Body["fields"].(map[string]any)["verifier"] != "invalid-payload" {
		t.Fatalf("verifier distinto: %d %s", ex.Code, ex.Raw)
	}
	// Mismo resultado: ya consumido (aunque el verifier no cuadró, el ticket no se consume; se usa el bueno).
	if ex := e.googleExchange(result, ver); ex.Code != 200 {
		t.Fatalf("primer canje real: %d %s", ex.Code, ex.Raw)
	}
	if ex := e.googleExchange(result, ver); ex.Code != 422 || ex.Body["fields"].(map[string]any)["code"] != "invalid-token" {
		t.Fatalf("resultado reutilizado: %d %s", ex.Code, ex.Raw)
	}
}

func TestGoogleAccountInGracePeriod(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-grace", "gracia@example.com")
	ta := tok(sess, "accessToken")
	if r := e.call("POST", "/me/delete", map[string]any{"authKey": authKey}, ta, ""); r.Code != 202 {
		t.Fatalf("borrar cuenta: %d %s", r.Code, r.Raw)
	}
	e.fake.Identity = googleIdentity("sub-grace", "gracia@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)
	ex := e.googleExchange(result, ver)
	if ex.Code != 403 || ex.Body["code"] != "account-deleted" {
		t.Fatalf("cuenta en gracia: %d %s", ex.Code, ex.Raw)
	}
}

func TestGoogleRegisterDiscardsUnverified(t *testing.T) {
	e := newEnv(t)
	e.register("dup@example.com") // registro sin verificar (lo creó otro)
	e.fake.Identity = googleIdentity("sub-dup", "dup@example.com")
	_, uid := e.googleRegister("sub-dup", "dup@example.com")
	var count int
	var verified bool
	if err := e.db.Admin.QueryRow(context.Background(),
		`SELECT count(*), bool_and(email_verified_at IS NOT NULL) FROM users WHERE email='dup@example.com'`).Scan(&count, &verified); err != nil {
		t.Fatal(err)
	}
	if count != 1 || !verified {
		t.Fatalf("el registro sin verificar debía descartarse: count=%d verified=%v", count, verified)
	}
	var owner string
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT user_id::text FROM user_identities WHERE subject='sub-dup'`).Scan(&owner); err != nil || owner != uid {
		t.Fatalf("identidad del registro: %q %v", owner, err)
	}
}

func TestGoogleUnlink(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-unlink", "unlink@example.com")
	ta := tok(sess, "accessToken")

	// Exige la contraseña.
	if r := e.call("DELETE", "/me/identities/google", map[string]any{"authKey": strings.Repeat("Z", 43)}, ta, ""); r.Code != 422 {
		t.Fatalf("unlink con contraseña errónea: %d %s", r.Code, r.Raw)
	}
	if r := e.call("DELETE", "/me/identities/google", map[string]any{"authKey": authKey}, ta, ""); r.Code != 204 {
		t.Fatalf("unlink: %d %s", r.Code, r.Raw)
	}
	// Tras desvincular, Google lleva a link-required (la cuenta sigue existiendo).
	e.fake.Identity = googleIdentity("sub-unlink", "unlink@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)
	ex := e.googleExchange(result, ver)
	if ex.Body["status"] != "link-required" {
		t.Fatalf("tras desvincular: %s", ex.Raw)
	}
}

func TestGoogleCookieModeAndCSRF(t *testing.T) {
	e := newEnv(t)
	e.fake.Identity = googleIdentity("sub-cookie", "cookie@example.com")
	ver := newVerifier(t)
	result, _ := e.googleLogin(ver)
	// Canje del resultado en modo cookie.
	ex := e.call("POST", "/auth/google/exchange", map[string]any{"code": result, "verifier": ver}, "", "", cookieMode())
	if ex.Body["status"] != "signup-required" {
		t.Fatalf("exchange modo cookie: %s", ex.Raw)
	}
	body := map[string]any{"signupToken": tok(ex.Body, "signupToken"), "userId": uuid.Must(uuid.NewV7()).String(),
		"fullName": "Persona Google", "acceptedTerms": true, "authKey": authKey, "recoveryAuth": recKey, "keys": keys()}
	reg := e.call("POST", "/auth/google/register", body, "", "", cookieMode())
	if reg.Code != 200 || findCookie(reg, refreshCookieName) == nil {
		t.Fatalf("registro google modo cookie: %d %s", reg.Code, reg.Raw)
	}
	if _, ok := reg.Body["refreshToken"]; ok {
		t.Fatalf("en modo cookie no debe venir refreshToken: %s", reg.Raw)
	}

	// Origin no permitido en modo cookie → 403 (CSRF), sin consumir nada.
	bad := e.call("POST", "/auth/google/exchange", map[string]any{"code": "x", "verifier": newVerifier(t)}, "", "",
		cookieMode(), origin("https://evil.example"))
	if bad.Code != 403 || bad.Body["code"] != "csrf" {
		t.Fatalf("csrf exchange: %d %s", bad.Code, bad.Raw)
	}
}

func TestGoogleDisabledReturnsForbidden(t *testing.T) {
	e := newEnvOIDC(t, true, nil)
	ver := newVerifier(t)
	if r := e.call("POST", "/auth/google/start", map[string]any{"challenge": challengeOf(ver)}, "", ""); r.Code != 403 || r.Body["code"] != "google-disabled" {
		t.Fatalf("start con google off: %d %s", r.Code, r.Raw)
	}
	bodies := map[string]map[string]any{
		"/auth/google/exchange": {"code": "x", "verifier": newVerifier(t)},
		"/auth/google/link":     {"linkToken": "z", "authKey": authKey},
		"/auth/google/register": {"signupToken": "w", "userId": uuid.Must(uuid.NewV7()).String(), "fullName": "Persona Google",
			"acceptedTerms": true, "authKey": authKey, "recoveryAuth": recKey, "keys": keys()},
	}
	for path, body := range bodies {
		if r := e.call("POST", path, body, "", ""); r.Code != 403 || r.Body["code"] != "google-disabled" {
			t.Errorf("%s con google off: %d %s", path, r.Code, r.Raw)
		}
	}
	// El callback nunca responde JSON: 302 con #error.
	cb := e.call("GET", "/auth/google/callback?code=x&state=y", nil, "", "")
	if cb.Code != 302 || !strings.Contains(cb.Hdr.Get("Location"), "#error=google-disabled") {
		t.Fatalf("callback con google off: %d %s", cb.Code, cb.Hdr.Get("Location"))
	}
	// Desvincular también responde 403 cuando Google está apagado.
	sess := e.googleRegisterViaEmail(t)
	if r := e.call("DELETE", "/me/identities/google", map[string]any{"authKey": authKey}, tok(sess, "accessToken"), ""); r.Code != 403 {
		t.Fatalf("unlink con google off: %d %s", r.Code, r.Raw)
	}
}

// googleRegisterViaEmail crea una cuenta normal (sin Google) para pruebas que solo necesitan sesión.
func (e *env) googleRegisterViaEmail(t *testing.T) map[string]any {
	t.Helper()
	return e.verified("normal@example.com")
}

func TestGoogleStartValidation(t *testing.T) {
	e := newEnv(t)
	if r := e.call("POST", "/auth/google/start", map[string]any{"challenge": "corto"}, "", ""); r.Code != 422 {
		t.Fatalf("challenge inválido: %d %s", r.Code, r.Raw)
	}
	// Tope por IP.
	var last resp
	for i := 0; i < 35; i++ {
		last = e.call("POST", "/auth/google/start", map[string]any{"challenge": challengeOf(newVerifier(t))}, "", "203.0.113.77")
	}
	if last.Code != 429 {
		t.Fatalf("google/start sin límite: %d", last.Code)
	}
}
