package auth_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

// totpNow calcula el código TOTP del secreto base32 para el instante actual del arnés.
func (e *env) totpNow(secretB32 string) string {
	e.t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		e.t.Fatalf("secreto base32: %v", err)
	}
	return security.TOTPCode(raw, e.now.Unix()/30)
}

// advance mueve el reloj del arnés un paso TOTP: obliga a usar un código nuevo (anti-reutilización).
func (e *env) advance() { e.now = e.now.Add(30 * time.Second) }

// enrollMFA hace setup + enable con el token dado y devuelve el secreto y los 10 códigos de respaldo.
func (e *env) enrollMFA(token string) (secret string, codes []string) {
	e.t.Helper()
	r := e.call("POST", "/mfa/totp/setup", map[string]any{"authKey": authKey}, token, "")
	if r.Code != 200 {
		e.t.Fatalf("setup: %d %s", r.Code, r.Raw)
	}
	secret, _ = r.Body["secret"].(string)
	if secret == "" || r.Body["otpauthUri"] == "" {
		e.t.Fatalf("setup incompleto: %s", r.Raw)
	}
	r = e.call("POST", "/mfa/totp/enable", map[string]any{"code": e.totpNow(secret)}, token, "")
	if r.Code != 200 {
		e.t.Fatalf("enable: %d %s", r.Code, r.Raw)
	}
	arr, _ := r.Body["recoveryCodes"].([]any)
	for _, c := range arr {
		codes = append(codes, c.(string))
	}
	if len(codes) != 10 {
		e.t.Fatalf("esperaba 10 códigos de respaldo, hay %d", len(codes))
	}
	return secret, codes
}

func mfaLogin(e *env, email, ip string) resp {
	return e.call("POST", "/auth/login", loginBody(email, "Portátil", "linux"), "", ip)
}

func TestMFAEnrollAndStatus(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")

	if r := e.call("GET", "/mfa", nil, ta, ""); r.Code != 200 || r.Body["enabled"] != false || r.Body["recoveryCodesLeft"] != float64(0) {
		t.Fatalf("estado inicial: %d %s", r.Code, r.Raw)
	}
	_, codes := e.enrollMFA(ta)
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("código repetido: %q", c)
		}
		seen[c] = true
	}
	r := e.call("GET", "/mfa", nil, ta, "")
	if r.Code != 200 || r.Body["enabled"] != true || r.Body["recoveryCodesLeft"] != float64(10) || r.Body["enabledAt"] == nil {
		t.Fatalf("estado tras alta: %d %s", r.Code, r.Raw)
	}
}

func TestMFASetupRequiresPassword(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")

	if r := e.call("POST", "/mfa/totp/setup", map[string]any{"authKey": ""}, ta, ""); r.Code != 422 || r.Body["fields"].(map[string]any)["password"] != "required" {
		t.Fatalf("sin contraseña: %d %s", r.Code, r.Raw)
	}
	wrong := strings.Repeat("W", 43)
	for i := 0; i < 5; i++ {
		r := e.call("POST", "/mfa/totp/setup", map[string]any{"authKey": wrong}, ta, "")
		if r.Code != 422 || r.Body["fields"].(map[string]any)["password"] != "wrong-password" {
			t.Fatalf("contraseña errónea %d: %d %s", i, r.Code, r.Raw)
		}
	}
	// El contador `sensitive` es compartido: el sexto intento queda bloqueado.
	if r := e.call("POST", "/mfa/totp/setup", map[string]any{"authKey": wrong}, ta, ""); r.Code != 429 {
		t.Fatalf("tras agotar el contador: %d %s", r.Code, r.Raw)
	}
}

func TestMFAEnableWrongCode(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	r := e.call("POST", "/mfa/totp/setup", map[string]any{"authKey": authKey}, ta, "")
	secret, _ := r.Body["secret"].(string)

	wrong := "000000"
	if e.totpNow(secret) == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		if r := e.call("POST", "/mfa/totp/enable", map[string]any{"code": wrong}, ta, ""); r.Code != 422 || r.Body["fields"].(map[string]any)["code"] != "invalid-code" {
			t.Fatalf("código erróneo %d: %d %s", i, r.Code, r.Raw)
		}
	}
	if r := e.call("POST", "/mfa/totp/enable", map[string]any{"code": wrong}, ta, ""); r.Code != 429 {
		t.Fatalf("tras agotar intentos: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/mfa", nil, ta, ""); r.Body["enabled"] != false {
		t.Fatalf("no debía quedar activo: %s", r.Raw)
	}
}

func TestMFAClosesOtherSessions(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	other := e.login("ana@example.com", authKey, "")
	tb := tok(other.Body, "accessToken")
	if tb == "" {
		t.Fatalf("segunda sesión sin token: %s", other.Raw)
	}
	e.enrollMFA(ta)
	if r := e.call("GET", "/mfa", nil, tb, ""); r.Code != 401 {
		t.Fatalf("la otra sesión debía cerrarse: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/mfa", nil, ta, ""); r.Code != 200 {
		t.Fatalf("la sesión actual debía seguir: %d %s", r.Code, r.Raw)
	}
}

func TestMFALoginChallengeHasNoSession(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	e.enrollMFA(ta)
	e.advance()

	l := mfaLogin(e, "ana@example.com", "")
	if l.Code != 200 || l.Body["mfaRequired"] != true || tok(l.Body, "mfaToken") == "" || l.Body["expiresAt"] == nil {
		t.Fatalf("reto: %d %s", l.Code, l.Raw)
	}
	for _, k := range []string{"accessToken", "refreshToken", "keys"} {
		if _, ok := l.Body[k]; ok {
			t.Fatalf("el reto no debe traer %s: %s", k, l.Raw)
		}
	}
	if len(l.Cookies) != 0 {
		t.Fatalf("el reto no debe emitir cookie: %v", l.Cookies)
	}

	// Modo cookie: tampoco cookie ni refreshToken.
	lc := e.call("POST", "/auth/login", loginBody("ana@example.com", "Portátil", "linux"), "", "", cookieMode())
	if lc.Body["mfaRequired"] != true || len(lc.Cookies) != 0 {
		t.Fatalf("reto en modo cookie: %d %s", lc.Code, lc.Raw)
	}
}

func TestMFALoginSuccess(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)

	// Modo cuerpo.
	e.advance()
	l := mfaLogin(e, "ana@example.com", "")
	mt := tok(l.Body, "mfaToken")
	r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": mt, "code": e.totpNow(secret)}, "", "")
	if r.Code != 200 || tok(r.Body, "accessToken") == "" || r.Body["keys"] == nil {
		t.Fatalf("login mfa: %d %s", r.Code, r.Raw)
	}
	if _, ok := r.Body["refreshToken"]; !ok {
		t.Fatalf("en modo cuerpo debe venir refreshToken: %s", r.Raw)
	}

	// Modo cookie.
	e.advance()
	lc := e.call("POST", "/auth/login", loginBody("ana@example.com", "Portátil", "linux"), "", "", cookieMode())
	mt2 := tok(lc.Body, "mfaToken")
	rc := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": mt2, "code": e.totpNow(secret)}, "", "", cookieMode())
	if rc.Code != 200 || findCookie(rc, refreshCookieName) == nil {
		t.Fatalf("login mfa modo cookie: %d %s", rc.Code, rc.Raw)
	}
	if _, ok := rc.Body["refreshToken"]; ok {
		t.Fatalf("en modo cookie no debe venir refreshToken: %s", rc.Raw)
	}
}

func TestMFAStepTwoAntiReuse(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)

	e.advance()
	code := e.totpNow(secret)
	l := mfaLogin(e, "ana@example.com", "")
	if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(l.Body, "mfaToken"), "code": code}, "", ""); r.Code != 200 {
		t.Fatalf("primer uso: %d %s", r.Code, r.Raw)
	}
	// Nuevo ticket, mismo código: el paso ya se usó.
	l2 := mfaLogin(e, "ana@example.com", "")
	if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(l2.Body, "mfaToken"), "code": code}, "", ""); r.Code != 422 {
		t.Fatalf("reutilización: %d %s", r.Code, r.Raw)
	}
}

func TestMFARecoveryCodeLogin(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	_, codes := e.enrollMFA(ta)

	e.advance()
	l := mfaLogin(e, "ana@example.com", "")
	r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(l.Body, "mfaToken"), "code": codes[0]}, "", "")
	if r.Code != 200 {
		t.Fatalf("código de respaldo: %d %s", r.Code, r.Raw)
	}
	// El mismo código no vuelve a servir.
	l2 := mfaLogin(e, "ana@example.com", "")
	if x := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(l2.Body, "mfaToken"), "code": codes[0]}, "", ""); x.Code != 422 {
		t.Fatalf("código de respaldo reutilizado: %d %s", x.Code, x.Raw)
	}
	st := e.call("GET", "/mfa", nil, tok(r.Body, "accessToken"), "")
	if st.Body["recoveryCodesLeft"] != float64(9) {
		t.Fatalf("códigos restantes: %s", st.Raw)
	}
}

func TestMFATicketInvalid(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)

	e.advance()
	l := mfaLogin(e, "ana@example.com", "")
	mt := tok(l.Body, "mfaToken")
	if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": mt, "code": e.totpNow(secret)}, "", ""); r.Code != 200 {
		t.Fatalf("login mfa: %d %s", r.Code, r.Raw)
	}
	// Ticket ya consumido.
	if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": mt, "code": e.totpNow(secret)}, "", ""); r.Code != 422 || r.Body["fields"].(map[string]any)["mfaToken"] != "invalid-token" {
		t.Fatalf("ticket consumido: %d %s", r.Code, r.Raw)
	}
	// Ticket inventado.
	if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": strings.Repeat("x", 43), "code": "123456"}, "", ""); r.Code != 422 {
		t.Fatalf("ticket inventado: %d %s", r.Code, r.Raw)
	}
}

func TestMFABruteForceAcrossIPs(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)
	e.advance()
	l := mfaLogin(e, "ana@example.com", "198.51.100.1")
	mt := tok(l.Body, "mfaToken")
	wrong := "000000"
	if e.totpNow(secret) == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": mt, "code": wrong}, "", "198.51.100.1"); r.Code != 422 {
			t.Fatalf("fallo %d: %d %s", i, r.Code, r.Raw)
		}
	}
	// Otra IP, ticket nuevo y el código correcto: sigue bloqueada por cuenta.
	l2 := mfaLogin(e, "ana@example.com", "203.0.113.9")
	if r := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(l2.Body, "mfaToken"), "code": e.totpNow(secret)}, "", "203.0.113.9"); r.Code != 429 {
		t.Fatalf("debería estar bloqueada por cuenta: %d %s", r.Code, r.Raw)
	}
}

func TestRefreshDoesNotRequireMFA(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	rt := tok(sess, "refreshToken")
	e.enrollMFA(ta)
	// Refrescar la sesión actual no pide segundo paso (el MFA es de sesiones nuevas).
	r := e.call("POST", "/auth/refresh", map[string]any{"refreshToken": rt}, "", "")
	if r.Code != 200 || tok(r.Body, "accessToken") == "" {
		t.Fatalf("refresh: %d %s", r.Code, r.Raw)
	}
}

func TestMFADisableRequiresPasswordAndCode(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)

	// Sin código: no se desactiva.
	if r := e.call("POST", "/mfa/totp/disable", map[string]any{"authKey": authKey}, ta, ""); r.Code != 422 {
		t.Fatalf("disable sin código: %d %s", r.Code, r.Raw)
	}
	// Contraseña errónea: no se desactiva.
	if r := e.call("POST", "/mfa/totp/disable", map[string]any{"authKey": strings.Repeat("W", 43), "code": e.totpNow(secret)}, ta, ""); r.Code != 422 {
		t.Fatalf("disable con contraseña errónea: %d %s", r.Code, r.Raw)
	}
	// Contraseña y código correctos.
	e.advance()
	if r := e.call("POST", "/mfa/totp/disable", map[string]any{"authKey": authKey, "code": e.totpNow(secret)}, ta, ""); r.Code != 204 {
		t.Fatalf("disable: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/mfa", nil, ta, ""); r.Body["enabled"] != false {
		t.Fatalf("sigue activo: %s", r.Raw)
	}
	// El login vuelve a un solo paso.
	e.advance()
	l := mfaLogin(e, "ana@example.com", "")
	if l.Body["accessToken"] == nil {
		t.Fatalf("login debería ser de un paso: %s", l.Raw)
	}
}

func TestMFARegenerateRecoveryCodes(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, codes := e.enrollMFA(ta)
	e.advance()
	r := e.call("POST", "/mfa/recovery-codes", map[string]any{"authKey": authKey, "code": e.totpNow(secret)}, ta, "")
	if r.Code != 200 {
		t.Fatalf("regenerar: %d %s", r.Code, r.Raw)
	}
	arr, _ := r.Body["recoveryCodes"].([]any)
	if len(arr) != 10 {
		t.Fatalf("esperaba 10 códigos: %s", r.Raw)
	}
	// Los códigos viejos ya no valen.
	e.advance()
	l := mfaLogin(e, "ana@example.com", "")
	if x := e.call("POST", "/auth/login/mfa", map[string]any{"mfaToken": tok(l.Body, "mfaToken"), "code": codes[0]}, "", ""); x.Code != 422 {
		t.Fatalf("código viejo seguía valiendo: %d %s", x.Code, x.Raw)
	}
}

func resetBodyMFA(token, mode, rec string, extra map[string]any) map[string]any {
	b := resetBody(token, mode, rec)
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestMFAResetWipeRequiresCode(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	secret, _ := e.enrollMFA(ta)
	e.addNote("ana@example.com")
	n0, _, _, _ := e.counts()

	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")

	// Sin código: 422 y las notas siguen.
	r := e.call("POST", "/auth/password/reset", resetBodyMFA(token, "wipe", newRecKey, nil), "", "")
	if r.Code != 422 || r.Body["fields"].(map[string]any)["mfaCode"] != "required" {
		t.Fatalf("wipe sin código: %d %s", r.Code, r.Raw)
	}
	if n, _, _, _ := e.counts(); n != n0 {
		t.Fatalf("las notas no debían borrarse: %d -> %d", n0, n)
	}
	// Con código correcto: procede.
	e.advance()
	r = e.call("POST", "/auth/password/reset", resetBodyMFA(token, "wipe", newRecKey, map[string]any{"mfaCode": e.totpNow(secret)}), "", "")
	if r.Code != 204 {
		t.Fatalf("wipe con código: %d %s", r.Code, r.Raw)
	}
	if n, f, tomb, sh := e.counts(); n != 0 || f != 0 || tomb != 0 || sh != 0 {
		t.Fatalf("wipe incompleto: %d %d %d %d", n, f, tomb, sh)
	}
}

func TestMFAResetKeepCanDisable(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("ana@example.com")
	ta := tok(sess, "accessToken")
	e.enrollMFA(ta)

	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	// keep sin código no lo exige, y con disableMfa además lo desactiva.
	r := e.call("POST", "/auth/password/reset", resetBodyMFA(token, "keep", recKey, map[string]any{"disableMfa": true}), "", "")
	if r.Code != 204 {
		t.Fatalf("reset keep: %d %s", r.Code, r.Raw)
	}
	e.advance()
	l := e.login("ana@example.com", newAuthKey, "")
	if tok(l.Body, "accessToken") == "" {
		t.Fatalf("tras desactivar, el login debería ser de un paso: %s", l.Raw)
	}
	e.svc.Close()
	found := false
	for _, m := range e.mail.Sent() {
		if strings.Contains(m.Text, "desactivó la verificación en dos pasos") {
			found = true
		}
	}
	if !found {
		t.Fatal("el correo debería mencionar la desactivación del segundo factor")
	}
}
