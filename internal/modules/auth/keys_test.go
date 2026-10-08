package auth_test

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var tokenRe = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

const (
	newAuthKey = "N" + "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" // 43 caracteres
	newRecKey  = "Q" + "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	sealedA    = "a1.AAAAAAAAAAAAAAAA.QUJDRA"
	sealedNew  = "a1.CCCCCCCCCCCCCCCC.QUJDRA"
	sealedRec2 = "a1.DDDDDDDDDDDDDDDD.QUJDRA"
)

func newKeys(wrapped, rec string, salt string) map[string]any {
	return map[string]any{
		"kdf":              map[string]any{"alg": "argon2id", "memoryKiB": 1024, "iterations": 1, "parallelism": 1, "salt": salt},
		"wrappedMasterKey": wrapped, "recoveryWrappedMasterKey": rec, "keysVersion": 1,
	}
}

func (e *env) lastResetToken(to string) string {
	e.t.Helper()
	e.svc.Close()
	sent := e.mail.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		if sent[i].To == to && strings.Contains(sent[i].Subject, "Restablece") {
			return tokenRe.FindStringSubmatch(sent[i].Text)[1]
		}
	}
	e.t.Fatalf("no hay correo de restablecimiento para %s", to)
	return ""
}

func (e *env) mailsTo(to, subject string) int {
	e.svc.Close()
	n := 0
	for _, m := range e.mail.Sent() {
		if m.To == to && strings.Contains(m.Subject, subject) {
			n++
		}
	}
	return n
}

func (e *env) addNote(userEmail string) {
	e.t.Helper()
	ctx := context.Background()
	var uid string
	if err := e.db.Admin.QueryRow(ctx, `SELECT id::text FROM users WHERE email = $1`, userEmail).Scan(&uid); err != nil {
		e.t.Fatal(err)
	}
	nid := uuid.Must(uuid.NewV7()).String()
	for _, q := range []string{
		`INSERT INTO notes (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload) VALUES ('` + nid + `', '` + uid + `', 1, 1, now(), now(), '` + sealedA + `', '` + sealedA + `')`,
		`INSERT INTO folders (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload) VALUES (gen_random_uuid(), '` + uid + `', 1, 2, now(), now(), '` + sealedA + `', '` + sealedA + `')`,
		`INSERT INTO tombstones (user_id, entity, id, revision, seq) VALUES ('` + uid + `', 'note', gen_random_uuid(), 1, 3)`,
		`INSERT INTO share_links (slug, note_id, user_id, wrapped_key, payload) VALUES (substr(replace('` + uid + `', '-', ''), 1, 22), '` + nid + `', '` + uid + `', '` + sealedA + `', '` + sealedA + `')`,
	} {
		if _, err := e.db.Admin.Exec(ctx, q); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) counts() (notes, folders, tombs, shares int) {
	ctx := context.Background()
	_ = e.db.Admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM notes), (SELECT count(*) FROM folders), (SELECT count(*) FROM tombstones), (SELECT count(*) FROM share_links)`).Scan(&notes, &folders, &tombs, &shares)
	return
}

func TestKeysEndpointRequiresAuthAndReturnsBundle(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	if r := e.call("GET", "/keys", nil, "", ""); r.Code != 401 {
		t.Fatalf("sin token: %d", r.Code)
	}
	l := e.login("ana@example.com", authKey, "")
	r := e.call("GET", "/keys", nil, tok(l.Body, "accessToken"), "")
	if r.Code != 200 || r.Body["wrappedMasterKey"] != sealedA || r.Body["keysVersion"] != float64(1) {
		t.Fatalf("keys: %d %s", r.Code, r.Raw)
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	a := e.login("ana@example.com", authKey, "")
	b := e.login("ana@example.com", authKey, "")
	ta, tb := tok(a.Body, "accessToken"), tok(b.Body, "accessToken")
	body := func(cur, nw string) map[string]any {
		// El cliente intenta colar otra clave de recuperación: el servidor la ignora.
		return map[string]any{"currentAuthKey": cur, "newAuthKey": nw, "keys": newKeys(sealedNew, sealedRec2, "BBBBBBBBBBBBBBBBBBBBBB")}
	}

	if r := e.call("POST", "/me/password", body(authKey, newAuthKey), "", ""); r.Code != 401 {
		t.Fatalf("sin token: %d", r.Code)
	}
	if r := e.call("POST", "/me/password", body(strings.Repeat("W", 43), newAuthKey), ta, ""); r.Code != 422 || r.Body["fields"].(map[string]any)["currentPassword"] != "wrong-password" {
		t.Fatalf("contraseña actual errónea: %d %s", r.Code, r.Raw)
	}
	if r := e.call("POST", "/me/password", body(authKey, authKey), ta, ""); r.Code != 422 || r.Body["fields"].(map[string]any)["newPassword"] != "same-password" {
		t.Fatalf("misma contraseña: %d %s", r.Code, r.Raw)
	}
	if r := e.call("POST", "/me/password", body(authKey, newAuthKey), ta, ""); r.Code != 204 {
		t.Fatalf("cambio: %d %s", r.Code, r.Raw)
	}

	// La sesión actual sigue; la otra queda cerrada.
	if r := e.call("GET", "/auth/session", nil, ta, ""); r.Code != 200 {
		t.Fatalf("la sesión actual debía seguir: %d", r.Code)
	}
	if r := e.call("GET", "/auth/session", nil, tb, ""); r.Code != 401 || r.Body["kind"] != "device-revoked" {
		t.Fatalf("la otra sesión debía cerrarse: %d %s", r.Code, r.Raw)
	}
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": tok(b.Body, "refreshToken")}, "", ""); r.Code != 401 {
		t.Fatalf("el refresh de la otra sesión debía revocarse: %d", r.Code)
	}
	// Login: la clave vieja ya no sirve; la nueva sí, con las claves nuevas y la recuperación intacta.
	if r := e.login("ana@example.com", authKey, "10.1.1.1"); r.Code != 401 {
		t.Fatalf("la clave vieja aún sirve: %d", r.Code)
	}
	n := e.login("ana@example.com", newAuthKey, "")
	k, _ := n.Body["keys"].(map[string]any)
	if n.Code != 200 || k["wrappedMasterKey"] != sealedNew || k["recoveryWrappedMasterKey"] != "a1.BBBBBBBBBBBBBBBB.QUJDRA" || k["keysVersion"] != float64(2) {
		t.Fatalf("claves tras el cambio: %d %s", n.Code, n.Raw)
	}
	if k["kdf"].(map[string]any)["salt"] != "BBBBBBBBBBBBBBBBBBBBBB" {
		t.Fatalf("la sal nueva no se guardó: %v", k["kdf"])
	}
	if e.mailsTo("ana@example.com", "contraseña de Apunte cambió") != 1 {
		t.Fatal("falta el aviso por correo")
	}
}

func TestChangePasswordWrongAttemptsAreLimited(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	l := e.login("ana@example.com", authKey, "")
	ta := tok(l.Body, "accessToken")
	bad := map[string]any{"currentAuthKey": strings.Repeat("W", 43), "newAuthKey": newAuthKey, "keys": newKeys(sealedNew, sealedA, "BBBBBBBBBBBBBBBBBBBBBB")}
	for i := 0; i < 5; i++ {
		e.call("POST", "/me/password", bad, ta, "")
	}
	good := map[string]any{"currentAuthKey": authKey, "newAuthKey": newAuthKey, "keys": newKeys(sealedNew, sealedA, "BBBBBBBBBBBBBBBBBBBBBB")}
	if r := e.call("POST", "/me/password", good, ta, ""); r.Code != 429 {
		t.Fatalf("tras 5 fallos debía bloquear: %d %s", r.Code, r.Raw)
	}
}

func TestChangePasswordValidation(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	ta := tok(e.login("ana@example.com", authKey, "").Body, "accessToken")
	for name, b := range map[string]map[string]any{
		"sin claves":       {"currentAuthKey": authKey, "newAuthKey": newAuthKey, "keys": map[string]any{}},
		"authKey corta":    {"currentAuthKey": authKey, "newAuthKey": "x", "keys": newKeys(sealedNew, sealedA, "BBBBBBBBBBBBBBBBBBBBBB")},
		"texto sin cifrar": {"currentAuthKey": authKey, "newAuthKey": newAuthKey, "keys": newKeys("en claro", sealedA, "BBBBBBBBBBBBBBBBBBBBBB")},
	} {
		if r := e.call("POST", "/me/password", b, ta, ""); r.Code != 422 {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
}

func TestRotateRecoveryKey(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	ta := tok(e.login("ana@example.com", authKey, "").Body, "accessToken")
	body := func(pw string) map[string]any {
		return map[string]any{"authKey": pw, "recoveryAuth": newRecKey, "recoveryWrappedMasterKey": sealedRec2}
	}
	if r := e.call("PUT", "/keys/recovery", body(strings.Repeat("W", 43)), ta, ""); r.Code != 422 || r.Body["fields"].(map[string]any)["password"] != "wrong-password" {
		t.Fatalf("contraseña errónea: %d %s", r.Code, r.Raw)
	}
	if r := e.call("PUT", "/keys/recovery", map[string]any{"authKey": authKey, "recoveryAuth": authKey, "recoveryWrappedMasterKey": sealedRec2}, ta, ""); r.Code != 422 {
		t.Fatalf("recoveryAuth igual a authKey: %d", r.Code)
	}
	if r := e.call("PUT", "/keys/recovery", body(authKey), ta, ""); r.Code != 204 {
		t.Fatalf("rotación: %d %s", r.Code, r.Raw)
	}
	k := e.call("GET", "/keys", nil, ta, "")
	if k.Body["recoveryWrappedMasterKey"] != sealedRec2 || k.Body["wrappedMasterKey"] != sealedA || k.Body["keysVersion"] != float64(2) {
		t.Fatalf("claves tras rotar: %s", k.Raw)
	}

	// La clave de recuperación anterior deja de servir; la nueva sí.
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	reset := func(rec string) resp {
		return e.call("POST", "/auth/password/reset", map[string]any{"token": token, "mode": "keep", "newAuthKey": newAuthKey,
			"recoveryAuth": rec, "keys": newKeys(sealedNew, sealedRec2, "BBBBBBBBBBBBBBBBBBBBBB")}, "", "")
	}
	if r := reset(recKey); r.Code != 422 || r.Body["fields"].(map[string]any)["recoveryKey"] != "invalid-recovery-key" {
		t.Fatalf("la clave de recuperación vieja debía rechazarse: %d %s", r.Code, r.Raw)
	}
	if r := reset(newRecKey); r.Code != 204 {
		t.Fatalf("la clave nueva debía servir: %d %s", r.Code, r.Raw)
	}
}

func TestForgotPasswordHidesAccountsAndThrottles(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.register("pendiente@example.com") // sin verificar
	n := len(e.mail.Sent())

	known := e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	ghost := e.call("POST", "/auth/password/forgot", map[string]string{"email": "nadie@example.com"}, "", "")
	pend := e.call("POST", "/auth/password/forgot", map[string]string{"email": "pendiente@example.com"}, "", "")
	if known.Code != 202 || ghost.Code != 202 || pend.Code != 202 || known.Raw != ghost.Raw || known.Raw != pend.Raw {
		t.Fatalf("respuestas distintas: %d/%d/%d", known.Code, ghost.Code, pend.Code)
	}
	e.svc.Close()
	got := e.mail.Sent()[n:]
	if len(got) != 1 || got[0].To != "ana@example.com" {
		t.Fatalf("solo la cuenta verificada debía recibir el enlace: %+v", got)
	}
	if !strings.Contains(got[0].Text, "http://web.test/reset-password?token=") {
		t.Fatalf("enlace: %q", got[0].Text)
	}
	// Una segunda petición inmediata no envía otro correo.
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	if e.mailsTo("ana@example.com", "Restablece") != 1 {
		t.Fatal("reenvió antes de 60 s")
	}
	// Pasado el minuto, el token nuevo sustituye al anterior.
	first := e.lastResetToken("ana@example.com")
	e.now = e.now.Add(61 * time.Second)
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	second := e.lastResetToken("ana@example.com")
	if first == second {
		t.Fatal("el token no cambió")
	}
	if r := e.call("POST", "/auth/password/reset/bundle", map[string]string{"token": first}, "", ""); r.Code != 422 {
		t.Fatalf("el token anterior debía invalidarse: %d", r.Code)
	}
}

func TestResetBundle(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	r := e.call("POST", "/auth/password/reset/bundle", map[string]string{"token": token}, "", "")
	if r.Code != 200 || r.Body["recoveryWrappedMasterKey"] != "a1.BBBBBBBBBBBBBBBB.QUJDRA" || r.Body["userId"] == "" || r.Body["kdf"] == nil {
		t.Fatalf("bundle: %d %s", r.Code, r.Raw)
	}
	if strings.Contains(r.Raw, "wrappedMasterKey\":\""+sealedA) {
		t.Fatal("el bundle no debe incluir la clave maestra envuelta con la contraseña")
	}
	for _, bad := range []string{"", "corto", strings.Repeat("a", 43)} {
		if x := e.call("POST", "/auth/password/reset/bundle", map[string]string{"token": bad}, "", ""); x.Code != 422 || x.Body["fields"].(map[string]any)["token"] != "invalid-token" {
			t.Fatalf("token inválido %q: %d %s", bad, x.Code, x.Raw)
		}
	}
	e.now = e.now.Add(61 * time.Minute)
	if x := e.call("POST", "/auth/password/reset/bundle", map[string]string{"token": token}, "", ""); x.Code != 422 {
		t.Fatalf("token caducado: %d", x.Code)
	}
}

func resetBody(token, mode, rec string) map[string]any {
	return map[string]any{"token": token, "mode": mode, "newAuthKey": newAuthKey, "recoveryAuth": rec,
		"keys": newKeys(sealedNew, sealedRec2, "BBBBBBBBBBBBBBBBBBBBBB")}
}

func TestResetKeepPreservesNotes(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.addNote("ana@example.com")
	s1 := e.login("ana@example.com", authKey, "")
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")

	// Una clave de recuperación equivocada no gasta el token.
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", strings.Repeat("Z", 43)), "", ""); r.Code != 422 || r.Body["fields"].(map[string]any)["recoveryKey"] != "invalid-recovery-key" {
		t.Fatalf("recuperación errónea: %d %s", r.Code, r.Raw)
	}
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", recKey), "", ""); r.Code != 204 {
		t.Fatalf("reset keep: %d %s", r.Code, r.Raw)
	}
	if notes, folders, tombs, shares := e.counts(); notes != 1 || folders != 1 || tombs != 1 || shares != 1 {
		t.Fatalf("keep debía conservar los datos: %d %d %d %d", notes, folders, tombs, shares)
	}
	// Todas las sesiones previas se cierran.
	if r := e.call("GET", "/auth/session", nil, tok(s1.Body, "accessToken"), ""); r.Code != 401 {
		t.Fatalf("la sesión previa debía cerrarse: %d", r.Code)
	}
	// Sirve solo la contraseña nueva, con la misma clave de recuperación (recoveryWrapped no cambia).
	if r := e.login("ana@example.com", authKey, "10.2.2.2"); r.Code != 401 {
		t.Fatalf("la clave vieja aún sirve: %d", r.Code)
	}
	l := e.login("ana@example.com", newAuthKey, "")
	k, _ := l.Body["keys"].(map[string]any)
	if l.Code != 200 || k["wrappedMasterKey"] != sealedNew || k["recoveryWrappedMasterKey"] != "a1.BBBBBBBBBBBBBBBB.QUJDRA" {
		t.Fatalf("login tras reset: %d %s", l.Code, l.Raw)
	}
	// El token es de un solo uso.
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", recKey), "", ""); r.Code != 422 || r.Body["fields"].(map[string]any)["token"] != "invalid-token" {
		t.Fatalf("token reutilizado: %d %s", r.Code, r.Raw)
	}
	if e.mailsTo("ana@example.com", "contraseña de Apunte cambió") != 1 {
		t.Fatal("falta el aviso por correo")
	}
}

func TestResetWipeDeletesEverything(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.verified("luis@example.com")
	e.addNote("ana@example.com")
	e.addNote("luis@example.com")
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	// wipe no necesita la clave de recuperación vieja: la `recoveryAuth` es la de la clave nueva.
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "wipe", newRecKey), "", ""); r.Code != 204 {
		t.Fatalf("reset wipe: %d %s", r.Code, r.Raw)
	}
	// Solo se borró lo de Ana; lo de Luis sigue.
	if notes, folders, tombs, shares := e.counts(); notes != 1 || folders != 1 || tombs != 1 || shares != 1 {
		t.Fatalf("wipe borró lo que no debía o no borró: %d %d %d %d", notes, folders, tombs, shares)
	}
	l := e.login("ana@example.com", newAuthKey, "")
	k, _ := l.Body["keys"].(map[string]any)
	if l.Code != 200 || k["recoveryWrappedMasterKey"] != sealedRec2 || k["wrappedMasterKey"] != sealedNew {
		t.Fatalf("claves nuevas tras wipe: %d %s", l.Code, l.Raw)
	}
	// La clave de recuperación nueva ya vale para un reset keep posterior.
	e.now = e.now.Add(2 * time.Minute)
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	t2 := e.lastResetToken("ana@example.com")
	if r := e.call("POST", "/auth/password/reset", resetBody(t2, "keep", newRecKey), "", ""); r.Code != 204 {
		t.Fatalf("keep con la recuperación nueva: %d %s", r.Code, r.Raw)
	}
}

func TestResetKeepRecoveryGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	for i := 0; i < 5; i++ {
		e.call("POST", "/auth/password/reset", resetBody(token, "keep", strings.Repeat("Z", 43)), "", "")
	}
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", recKey), "", ""); r.Code != 429 {
		t.Fatalf("tras 5 intentos fallidos debía bloquear aun con la clave correcta: %d %s", r.Code, r.Raw)
	}
}

func TestResetValidation(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	for name, f := range map[string]func(map[string]any){
		"modo":       func(b map[string]any) { b["mode"] = "destroy" },
		"authKey":    func(b map[string]any) { b["newAuthKey"] = "x" },
		"recovery":   func(b map[string]any) { b["recoveryAuth"] = "" },
		"claves":     func(b map[string]any) { b["keys"] = map[string]any{} },
		"sin cifrar": func(b map[string]any) { b["keys"] = newKeys("claro", sealedA, "BBBBBBBBBBBBBBBBBBBBBB") },
	} {
		b := resetBody(token, "keep", recKey)
		f(b)
		if r := e.call("POST", "/auth/password/reset", b, "", ""); r.Code != 422 {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	// Tras tanto intento inválido el token sigue sirviendo.
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", recKey), "", ""); r.Code != 204 {
		t.Fatalf("el token válido debía seguir sirviendo: %d %s", r.Code, r.Raw)
	}
}

func TestDeleteAccountAndRecoveryWithinGrace(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	l := e.login("ana@example.com", authKey, "")
	ta := tok(l.Body, "accessToken")
	if r := e.call("DELETE", "/me", nil, ta, ""); r.Code != 202 {
		t.Fatalf("delete: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/auth/session", nil, ta, ""); r.Code != 401 {
		t.Fatalf("la sesión debía cerrarse: %d", r.Code)
	}
	if r := e.call("POST", "/auth/refresh", map[string]string{"refreshToken": tok(l.Body, "refreshToken")}, "", ""); r.Code != 401 {
		t.Fatalf("el refresh debía revocarse: %d", r.Code)
	}
	if r := e.login("ana@example.com", authKey, "10.3.3.3"); r.Code != 401 {
		t.Fatalf("no se puede iniciar sesión en una cuenta eliminada: %d", r.Code)
	}
	if e.mailsTo("ana@example.com", "se eliminará") != 1 {
		t.Fatal("falta el aviso de eliminación")
	}
	// prelogin ya no revela los parámetros reales.
	if p := e.call("POST", "/auth/prelogin", map[string]string{"email": "ana@example.com"}, "", ""); p.Code != 200 {
		t.Fatalf("prelogin: %d", p.Code)
	}
	// Dentro del plazo, restablecer la contraseña recupera la cuenta (si quien borró no era su dueño).
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", recKey), "", ""); r.Code != 204 {
		t.Fatalf("reset: %d %s", r.Code, r.Raw)
	}
	if r := e.login("ana@example.com", newAuthKey, ""); r.Code != 200 {
		t.Fatalf("la cuenta debía recuperarse: %d %s", r.Code, r.Raw)
	}
}

func TestResetTokenIsStoredHashed(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "ana@example.com"}, "", "")
	token := e.lastResetToken("ana@example.com")
	var dump string
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT coalesce(string_agg(code_hash::text, '|'), '') FROM verification_codes`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, token) {
		t.Fatal("el token de restablecimiento está en claro")
	}
}
