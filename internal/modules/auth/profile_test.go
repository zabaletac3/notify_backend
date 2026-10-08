package auth_test

import (
	"strings"
	"testing"
	"time"
)

func TestProfileGetAndUpdate(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	ta := tok(e.login("ana@example.com", authKey, "").Body, "accessToken")
	if r := e.call("GET", "/me", nil, "", ""); r.Code != 401 {
		t.Fatalf("sin token: %d", r.Code)
	}
	me := e.call("GET", "/me", nil, ta, "")
	if me.Code != 200 || me.Body["email"] != "ana@example.com" || me.Body["fullName"] != "Ana Pérez" || me.Body["emailVerified"] != true {
		t.Fatalf("GET /me: %s", me.Raw)
	}
	up := e.call("PATCH", "/me", map[string]string{"fullName": "  Ana María Pérez "}, ta, "")
	if up.Code != 200 || up.Body["fullName"] != "Ana María Pérez" {
		t.Fatalf("PATCH: %s", up.Raw)
	}
	for _, bad := range []string{"A", "", strings.Repeat("x", 81)} {
		if r := e.call("PATCH", "/me", map[string]string{"fullName": bad}, ta, ""); r.Code != 422 {
			t.Errorf("nombre %q: %d", bad, r.Code)
		}
	}
	if r := e.call("PATCH", "/me", map[string]any{"fullName": "Ana", "email": "x@y.com"}, ta, ""); r.Code != 422 {
		t.Errorf("no se puede cambiar el correo por aquí: %d", r.Code)
	}
}

func (e *env) emailCode(to string) string {
	e.t.Helper()
	e.svc.Close()
	sent := e.mail.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		if sent[i].To == to && strings.Contains(sent[i].Subject, "Confirma tu nuevo correo") {
			return codeRe.FindStringSubmatch(sent[i].Text)[1]
		}
	}
	e.t.Fatalf("no hay código para %s", to)
	return ""
}

func TestEmailChangeFlow(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	ta := tok(e.login("ana@example.com", authKey, "").Body, "accessToken")
	req := func(email, pw string) resp {
		return e.call("POST", "/me/email-change", map[string]string{"newEmail": email, "authKey": pw}, ta, "")
	}

	if r := req("nuevo@example.com", strings.Repeat("W", 43)); r.Code != 422 || r.Body["fields"].(map[string]any)["password"] != "wrong-password" {
		t.Fatalf("contraseña errónea: %d %s", r.Code, r.Raw)
	}
	if r := req("no-es-correo", authKey); r.Code != 422 {
		t.Fatalf("correo inválido: %d", r.Code)
	}
	if r := req("ana@example.com", authKey); r.Code != 422 {
		t.Fatalf("mismo correo: %d", r.Code)
	}
	r := req("Nuevo@Example.com", authKey)
	if r.Code != 202 || r.Body["email"] != "nuevo@example.com" {
		t.Fatalf("solicitud: %d %s", r.Code, r.Raw)
	}
	code := e.emailCode("nuevo@example.com")

	confirm := func(email, c string) resp {
		return e.call("POST", "/me/email-change/confirm", map[string]string{"email": email, "code": c}, ta, "")
	}
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	if x := confirm("nuevo@example.com", bad); x.Code != 422 || x.Body["fields"].(map[string]any)["code"] != "invalid-code" {
		t.Fatalf("código malo: %d %s", x.Code, x.Raw)
	}
	if x := confirm("otro@example.com", code); x.Code != 422 {
		t.Fatalf("correo distinto al solicitado: %d", x.Code)
	}
	ok := confirm("nuevo@example.com", code)
	if ok.Code != 200 || ok.Body["email"] != "nuevo@example.com" {
		t.Fatalf("confirmación: %d %s", ok.Code, ok.Raw)
	}
	// Ahora se inicia sesión con el correo nuevo; el viejo ya no existe.
	if l := e.login("nuevo@example.com", authKey, "10.8.8.8"); l.Code != 200 {
		t.Fatalf("login con el correo nuevo: %d", l.Code)
	}
	if l := e.login("ana@example.com", authKey, "10.8.8.9"); l.Code != 401 {
		t.Fatalf("el correo viejo aún funciona: %d", l.Code)
	}
	// El código vale una vez, y el dueño del correo viejo recibe un aviso.
	if x := confirm("nuevo@example.com", code); x.Code != 422 {
		t.Fatalf("código reutilizado: %d", x.Code)
	}
	if e.mailsTo("ana@example.com", "correo de tu cuenta de Apunte cambió") != 1 {
		t.Fatal("falta el aviso al correo anterior")
	}
}

func TestEmailChangeToTakenAddressDoesNotRevealIt(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	e.verified("luis@example.com")
	ta := tok(e.login("ana@example.com", authKey, "").Body, "accessToken")
	taken := e.call("POST", "/me/email-change", map[string]string{"newEmail": "luis@example.com", "authKey": authKey}, ta, "")
	fresh := e.call("POST", "/me/email-change", map[string]string{"newEmail": "libre@example.com", "authKey": authKey}, ta, "")
	if taken.Code != 202 || fresh.Code != 202 {
		t.Fatalf("respuestas: %d %d", taken.Code, fresh.Code)
	}
	if strings.ReplaceAll(taken.Raw, "luis", "x") != strings.ReplaceAll(fresh.Raw, "libre", "x") {
		t.Fatalf("distinguibles: %s vs %s", taken.Raw, fresh.Raw)
	}
	e.svc.Close()
	for _, m := range e.mail.Sent() {
		if m.To == "luis@example.com" && codeRe.MatchString(m.Text) && strings.Contains(m.Subject, "Confirma") {
			t.Fatal("se envió un código al dueño del correo")
		}
	}
	if e.mailsTo("luis@example.com", "intentó usar tu correo") != 1 {
		t.Fatal("falta el aviso al dueño del correo")
	}
}

func TestEmailChangeLimitsAndExpiry(t *testing.T) {
	e := newEnv(t)
	e.verified("ana@example.com")
	ta := tok(e.login("ana@example.com", authKey, "").Body, "accessToken")
	e.call("POST", "/me/email-change", map[string]string{"newEmail": "nuevo@example.com", "authKey": authKey}, ta, "")
	code := e.emailCode("nuevo@example.com")
	e.now = e.now.Add(11 * time.Minute)
	if x := e.call("POST", "/me/email-change/confirm", map[string]string{"email": "nuevo@example.com", "code": code}, ta, ""); x.Code != 422 {
		t.Fatalf("código caducado: %d", x.Code)
	}
	// Sin solicitud pendiente.
	tb := tok(e.login("ana@example.com", authKey, "10.9.9.9").Body, "accessToken")
	if x := e.call("POST", "/me/email-change/confirm", map[string]string{"email": "otro@example.com", "code": "123456"}, tb, ""); x.Code != 422 {
		t.Fatalf("sin solicitud: %d", x.Code)
	}
	// Sin sesión no se puede pedir ni confirmar.
	if x := e.call("POST", "/me/email-change", map[string]string{"newEmail": "a@b.com", "authKey": authKey}, "", ""); x.Code != 401 {
		t.Fatalf("sin token: %d", x.Code)
	}
	// Límite de solicitudes por cuenta.
	var last resp
	for i := 0; i < 7; i++ {
		last = e.call("POST", "/me/email-change", map[string]string{"newEmail": "x" + string(rune('a'+i)) + "@example.com", "authKey": authKey}, ta, "")
	}
	if last.Code != 429 {
		t.Fatalf("debía limitar las solicitudes de cambio de correo: %d %s", last.Code, last.Raw)
	}
}
