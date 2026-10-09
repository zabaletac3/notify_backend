package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// trustedBody es un alta de dispositivo de confianza válida (el `id` lo genera el cliente).
func trustedBody(id string) map[string]any {
	return map[string]any{"id": id, "name": "Navegador", "platform": "web", "wrappedMasterKey": sealedA}
}

func trustedCount(t *testing.T, e *env, email string) int {
	t.Helper()
	var n int
	if err := e.db.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM trusted_devices d JOIN users u ON u.id = d.user_id WHERE u.email = $1`, email).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTrustedDeviceAddListGetRevoke(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-trust", "trust@example.com")
	ta := tok(sess, "accessToken")
	id := uuid.Must(uuid.NewV7()).String()

	if r := e.call("POST", "/trusted-devices", trustedBody(id), ta, ""); r.Code != 201 {
		t.Fatalf("alta: %d %s", r.Code, r.Raw)
	}

	// Lista: solo el vigente.
	list := e.call("GET", "/trusted-devices", nil, ta, "")
	if list.Code != 200 || !strings.Contains(list.Raw, id) {
		t.Fatalf("lista: %d %s", list.Code, list.Raw)
	}

	// Lectura: entrega la clave maestra cifrada.
	get := e.call("GET", "/trusted-devices/"+id, nil, ta, "")
	if get.Code != 200 || get.Body["wrappedMasterKey"] != sealedA {
		t.Fatalf("lectura: %d %s", get.Code, get.Raw)
	}

	// Baja: revoca (404 en lectura posterior y fuera de la lista), pero la fila sigue.
	if r := e.call("DELETE", "/trusted-devices/"+id, nil, ta, ""); r.Code != 204 {
		t.Fatalf("baja: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/trusted-devices/"+id, nil, ta, ""); r.Code != 404 {
		t.Fatalf("tras la baja debía dar 404: %d %s", r.Code, r.Raw)
	}
	if list := e.call("GET", "/trusted-devices", nil, ta, ""); strings.Contains(list.Raw, id) {
		t.Fatalf("el revocado no debe listarse: %s", list.Raw)
	}
	if n := trustedCount(t, e, "trust@example.com"); n != 1 {
		t.Fatalf("la baja revoca, no borra: %d filas", n)
	}

	// Auditoría de los tres eventos.
	var events int
	if err := e.db.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event IN ('trusted-device-add', 'trusted-device-use', 'trusted-device-revoke')`).Scan(&events); err != nil || events != 3 {
		t.Fatalf("eventos de auditoría: %d %v", events, err)
	}
}

func TestTrustedDeviceRequiresGoogle(t *testing.T) {
	e := newEnv(t)
	sess := e.verified("normal@example.com")
	ta := tok(sess, "accessToken")
	r := e.call("POST", "/trusted-devices", trustedBody(uuid.Must(uuid.NewV7()).String()), ta, "")
	if r.Code != 403 || r.Body["code"] != "google-not-linked" {
		t.Fatalf("alta sin Google: %d %s", r.Code, r.Raw)
	}
}

func TestTrustedDeviceLimit(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-limit", "limit@example.com")
	ta := tok(sess, "accessToken")
	for i := 0; i < 10; i++ {
		if r := e.call("POST", "/trusted-devices", trustedBody(uuid.Must(uuid.NewV7()).String()), ta, ""); r.Code != 201 {
			t.Fatalf("alta %d: %d %s", i+1, r.Code, r.Raw)
		}
	}
	r := e.call("POST", "/trusted-devices", trustedBody(uuid.Must(uuid.NewV7()).String()), ta, "")
	if r.Code != 403 || r.Body["code"] != "limit-reached" {
		t.Fatalf("undécimo: %d %s", r.Code, r.Raw)
	}
}

func TestTrustedDeviceIsolationBetweenAccounts(t *testing.T) {
	e := newEnv(t)
	a, _ := e.googleRegister("sub-a", "a@example.com")
	ta := tok(a, "accessToken")
	id := uuid.Must(uuid.NewV7()).String()
	if r := e.call("POST", "/trusted-devices", trustedBody(id), ta, ""); r.Code != 201 {
		t.Fatalf("alta de A: %d %s", r.Code, r.Raw)
	}

	b, _ := e.googleRegister("sub-b", "b@example.com")
	tb := tok(b, "accessToken")
	if r := e.call("GET", "/trusted-devices/"+id, nil, tb, ""); r.Code != 404 {
		t.Fatalf("B no debe leer el dispositivo de A: %d %s", r.Code, r.Raw)
	}
	if r := e.call("DELETE", "/trusted-devices/"+id, nil, tb, ""); r.Code != 404 {
		t.Fatalf("B no debe borrar el dispositivo de A: %d %s", r.Code, r.Raw)
	}
	// Reutilizar el id de A da 422 sin detalles (clave primaria global).
	r := e.call("POST", "/trusted-devices", trustedBody(id), tb, "")
	if r.Code != 422 {
		t.Fatalf("id de otra cuenta: %d %s", r.Code, r.Raw)
	}
	// La fila de A sigue intacta y visible solo para A.
	if list := e.call("GET", "/trusted-devices", nil, ta, ""); !strings.Contains(list.Raw, id) {
		t.Fatalf("el dispositivo de A desapareció: %s", list.Raw)
	}
}

func TestTrustedDeviceValidation(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-val", "val@example.com")
	ta := tok(sess, "accessToken")
	base := func() map[string]any { return trustedBody(uuid.Must(uuid.NewV7()).String()) }
	cases := map[string]func(map[string]any){
		"id no uuid":        func(b map[string]any) { b["id"] = "no-es-uuid" },
		"nombre vacío":      func(b map[string]any) { b["name"] = "   " },
		"plataforma":        func(b map[string]any) { b["platform"] = "msdos" },
		"sin cifrar":        func(b map[string]any) { b["wrappedMasterKey"] = "mi clave en claro" },
		"versión rara":      func(b map[string]any) { b["wrappedMasterKey"] = "a2.AAAA.BBBB" },
		"base64 inválido":   func(b map[string]any) { b["wrappedMasterKey"] = "a1.AA AA.BBBB" },
		"sin texto cifrado": func(b map[string]any) { b["wrappedMasterKey"] = "a1.AAAA." },
	}
	for name, f := range cases {
		b := base()
		f(b)
		if r := e.call("POST", "/trusted-devices", b, ta, ""); r.Code != 422 {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	// Un id con formato inválido tampoco se puede leer ni borrar: 404 uniforme.
	for _, bad := range []string{"no-uuid", uuid.NewString()} {
		if r := e.call("GET", "/trusted-devices/"+bad, nil, ta, ""); r.Code != 404 {
			t.Errorf("lectura %q: %d", bad, r.Code)
		}
		if r := e.call("DELETE", "/trusted-devices/"+bad, nil, ta, ""); r.Code != 404 {
			t.Errorf("baja %q: %d", bad, r.Code)
		}
	}
}

func TestTrustedDeviceRevokedOnCredentialChange(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-change", "change@example.com")
	ta := tok(sess, "accessToken")
	id := uuid.Must(uuid.NewV7()).String()
	if r := e.call("POST", "/trusted-devices", trustedBody(id), ta, ""); r.Code != 201 {
		t.Fatalf("alta: %d %s", r.Code, r.Raw)
	}

	// Cambio de contraseña: revoca todos (la sesión actual sigue viva).
	body := map[string]any{"currentAuthKey": authKey, "newAuthKey": newAuthKey, "keys": newKeys(sealedNew, sealedA, "BBBBBBBBBBBBBBBBBBBBBB")}
	if r := e.call("POST", "/me/password", body, ta, ""); r.Code != 204 {
		t.Fatalf("cambio de contraseña: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/trusted-devices/"+id, nil, ta, ""); r.Code != 404 {
		t.Fatalf("tras cambiar la contraseña debía dar 404: %d %s", r.Code, r.Raw)
	}
}

func TestTrustedDeviceRevokedOnReset(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-reset", "reset@example.com")
	ta := tok(sess, "accessToken")
	id := uuid.Must(uuid.NewV7()).String()
	if r := e.call("POST", "/trusted-devices", trustedBody(id), ta, ""); r.Code != 201 {
		t.Fatalf("alta: %d %s", r.Code, r.Raw)
	}

	// Reset keep: revoca la confianza (no la borra).
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "reset@example.com"}, "", "")
	token := e.lastResetToken("reset@example.com")
	if r := e.call("POST", "/auth/password/reset", resetBody(token, "keep", recKey), "", ""); r.Code != 204 {
		t.Fatalf("reset keep: %d %s", r.Code, r.Raw)
	}
	l := e.login("reset@example.com", newAuthKey, "")
	if l.Code != 200 {
		t.Fatalf("login tras reset: %d %s", l.Code, l.Raw)
	}
	if r := e.call("GET", "/trusted-devices/"+id, nil, tok(l.Body, "accessToken"), ""); r.Code != 404 {
		t.Fatalf("tras reset keep debía dar 404: %d %s", r.Code, r.Raw)
	}
	if n := trustedCount(t, e, "reset@example.com"); n != 1 {
		t.Fatalf("reset keep revoca, no borra: %d filas", n)
	}

	// Reset wipe: la clave maestra cambia, así que las filas se borran.
	e.now = e.now.Add(2 * time.Minute)
	e.call("POST", "/auth/password/forgot", map[string]string{"email": "reset@example.com"}, "", "")
	token2 := e.lastResetToken("reset@example.com")
	if r := e.call("POST", "/auth/password/reset", resetBody(token2, "wipe", newRecKey), "", ""); r.Code != 204 {
		t.Fatalf("reset wipe: %d %s", r.Code, r.Raw)
	}
	if n := trustedCount(t, e, "reset@example.com"); n != 0 {
		t.Fatalf("reset wipe debía borrar los dispositivos de confianza: %d filas", n)
	}
}

func TestTrustedDeviceRevokedOnUnlinkGoogle(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-unlink-td", "unlink-td@example.com")
	ta := tok(sess, "accessToken")
	id := uuid.Must(uuid.NewV7()).String()
	if r := e.call("POST", "/trusted-devices", trustedBody(id), ta, ""); r.Code != 201 {
		t.Fatalf("alta: %d %s", r.Code, r.Raw)
	}
	if r := e.call("DELETE", "/me/identities/google", map[string]string{"authKey": authKey}, ta, ""); r.Code != 204 {
		t.Fatalf("desvincular: %d %s", r.Code, r.Raw)
	}
	if r := e.call("GET", "/trusted-devices/"+id, nil, ta, ""); r.Code != 404 {
		t.Fatalf("tras desvincular Google debía dar 404: %d %s", r.Code, r.Raw)
	}
}

// La lectura exige una sesión completa: con MFA activo, un `mfaToken` no vale como Bearer.
func TestTrustedDeviceRequiresFullSession(t *testing.T) {
	e := newEnv(t)
	sess, _ := e.googleRegister("sub-mfa-td", "mfa-td@example.com")
	ta := tok(sess, "accessToken")
	id := uuid.Must(uuid.NewV7()).String()
	if r := e.call("POST", "/trusted-devices", trustedBody(id), ta, ""); r.Code != 201 {
		t.Fatalf("alta: %d %s", r.Code, r.Raw)
	}
	e.enrollMFA(ta)

	challenge := e.call("POST", "/auth/login", map[string]any{"email": "mfa-td@example.com", "authKey": authKey}, "", "")
	mfaToken := tok(challenge.Body, "mfaToken")
	if mfaToken == "" {
		t.Fatalf("se esperaba un reto de MFA: %s", challenge.Raw)
	}
	if r := e.call("GET", "/trusted-devices/"+id, nil, mfaToken, ""); r.Code != 401 {
		t.Fatalf("un mfaToken no debe valer como Bearer: %d %s", r.Code, r.Raw)
	}
	// La confianza sigue vigente para la sesión completa.
	if r := e.call("GET", "/trusted-devices/"+id, nil, ta, ""); r.Code != 200 {
		t.Fatalf("la sesión completa debía leer el dispositivo: %d %s", r.Code, r.Raw)
	}
}
