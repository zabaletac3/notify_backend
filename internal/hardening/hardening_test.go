// Package hardening reúne pruebas de abuso contra la API completa: secretos en registros, inyección,
// cuerpos hostiles y cabeceras. Un fallo aquí es un hallazgo de seguridad.
package hardening_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zabaletac3/notify_backend/internal/testutil"
)

const (
	slug = "AbCdEfGhIjKlMnOpQrStUv"
	wrap = "a1.WWWWWWWWWWWWWWWW.QUJDRA"
	copy = "a1.PPPPPPPPPPPPPPPP.QUJDREVGRw"
)

// Recorre los flujos sensibles y comprueba que NADA secreto llegó a los registros.
func TestLogsNeverContainSecrets(t *testing.T) {
	e := testutil.New(t)
	email := "persona.secreta@example.com"
	tok := e.Account(email)
	note := e.CreateNote(tok, false)

	// Más flujos: enlace, lectura pública, cambio de contraseña, olvido/restablecimiento, errores.
	e.Do("PUT", "/notes/"+note+"/share", map[string]any{"slug": slug, "wrappedShareKey": wrap, "payload": copy}, tok, "")
	e.Do("GET", "/public/notes/"+slug, nil, "", "")
	e.Do("POST", "/auth/login", map[string]any{"email": email, "authKey": strings.Repeat("Z", 43)}, "", "10.1.1.1") // fallo
	login := e.Do("POST", "/auth/login", map[string]any{"email": email, "authKey": testutil.AuthKey}, "", "")
	refresh, _ := login.Body["refreshToken"].(string)
	e.Do("POST", "/auth/refresh", map[string]any{"refreshToken": refresh}, "", "")

	// Modo cookie: el valor de la cookie de refresco tampoco debe acabar en los registros.
	cookieLogin := e.Do("POST", "/auth/login", map[string]any{"email": email, "authKey": testutil.AuthKey}, "", "",
		testutil.Header("X-Apunte-Session", "cookie"))
	var cookieRT string
	for _, c := range cookieLogin.Cookies {
		if c.Name == "apunte_rt" {
			cookieRT = c.Value
		}
	}
	if cookieRT == "" {
		t.Fatal("el login en modo cookie no entregó la cookie de refresco")
	}
	cookieRefresh := e.Do("POST", "/auth/refresh", nil, "", "", testutil.Header("X-Apunte-Session", "cookie"),
		testutil.Cookie(&http.Cookie{Name: "apunte_rt", Value: cookieRT}))
	var rotatedRT string
	for _, c := range cookieRefresh.Cookies {
		if c.Name == "apunte_rt" {
			rotatedRT = c.Value
		}
	}
	e.Do("POST", "/auth/logout", nil, "", "", testutil.Header("X-Apunte-Session", "cookie"),
		testutil.Cookie(&http.Cookie{Name: "apunte_rt", Value: rotatedRT}))

	e.Do("POST", "/auth/password/forgot", map[string]any{"email": email}, "", "")
	e.Auth.Close()
	var resetToken string
	for _, m := range e.Mail.Sent() {
		if strings.Contains(m.Subject, "Restablece") {
			resetToken = m.Text[strings.Index(m.Text, "token=")+6:]
			resetToken = strings.Fields(resetToken)[0]
		}
	}
	e.Do("POST", "/auth/password/reset/bundle", map[string]any{"token": resetToken}, "", "")
	e.Do("POST", "/sync", map[string]any{"cursor": nil, "changes": []any{map[string]any{"entity": "note", "id": "x", "op": "upsert"}}}, tok, "")
	e.Do("GET", "/notes/no-uuid", nil, tok, "")
	e.Do("POST", "/auth/register", map[string]any{"email": "otra@example.com"}, "", "")
	e.Do("POST", "/me/delete", map[string]any{"authKey": testutil.AuthKey}, tok, "")

	logs := e.Logs.String()
	if strings.TrimSpace(logs) == "" {
		t.Fatal("la API no registró nada: la prueba no comprueba nada")
	}
	secrets := map[string]string{
		"authKey": testutil.AuthKey, "recoveryKey": testutil.RecoveryKey, "token de acceso": tok, "token de renovación": refresh,
		"token de restablecimiento": resetToken, "payload": testutil.SealedA, "clave envuelta": testutil.SealedKey,
		"slug": slug, "copia pública": copy, "clave del enlace": wrap, "correo": email, "id de nota": note,
		"cookie de refresco": cookieRT, "cookie de refresco rotada": rotatedRT,
	}
	for name, v := range secrets {
		if v != "" && strings.Contains(logs, v) {
			t.Errorf("los registros contienen %s", name)
		}
	}
	for _, m := range e.Mail.Sent() { // los códigos de 6 dígitos
		for _, w := range strings.Fields(m.Text) {
			if len(w) == 6 && strings.Trim(w, "0123456789") == "" && strings.Contains(logs, w) {
				t.Errorf("los registros contienen un código de verificación (%s)", m.Subject)
			}
		}
	}
	if !strings.Contains(logs, "/v1/public/notes/{slug}") {
		t.Error("la ruta pública debe registrarse por patrón, no por URL")
	}
}

// Detalle de PostgreSQL: los errores de restricción traen valores de la fila; no deben llegar al log.
func TestPostgresErrorStringsCarryNoRowValues(t *testing.T) {
	pe := &pgconn.PgError{Severity: "ERROR", Code: "23505", Message: "duplicate key value violates unique constraint",
		Detail: "Key (email)=(ana@example.com) already exists.", Where: "valores secretos", Hint: "pista"}
	if msg := pe.Error(); strings.Contains(msg, "ana@example.com") || strings.Contains(msg, "secretos") {
		t.Fatalf("el texto del error de PostgreSQL filtra datos de la fila: %s", msg)
	}
}

// Cadenas hostiles en TODOS los campos de texto: nunca un 500 ni daño en los datos.
func TestHostileStringsNeverCauseServerErrors(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	note := e.CreateNote(tok, false)
	hostile := []string{
		"' OR '1'='1", `"; DROP TABLE users; --`, "a\x00b", "\u0000", "%00", "../../etc/passwd", "${jndi:ldap://x}",
		"{{7*7}}", "<script>alert(1)</script>", strings.Repeat("A", 100_000), "\r\nX-Injected: 1", "😀😀😀", "' UNION SELECT NULL--",
	}
	var users0 int
	_ = e.DB.Admin.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users0)
	check := func(label string, r testutil.Resp) {
		t.Helper()
		if r.Code >= 500 {
			t.Errorf("%s: respondió %d %.120s", label, r.Code, r.Raw)
		}
		if strings.Contains(r.Hdr.Get("X-Injected"), "1") {
			t.Errorf("%s: inyección de cabeceras", label)
		}
	}
	for i, h := range hostile {
		ip := fmt.Sprintf("10.9.%d.%d", i/200, i%200+1)
		check("prelogin", e.Do("POST", "/auth/prelogin", map[string]any{"email": h}, "", ip))
		check("login email", e.Do("POST", "/auth/login", map[string]any{"email": h, "authKey": testutil.AuthKey}, "", ip))
		check("login authKey", e.Do("POST", "/auth/login", map[string]any{"email": "ana@example.com", "authKey": h}, "", ip))
		check("register", e.Do("POST", "/auth/register", map[string]any{"userId": h, "fullName": h, "email": h, "acceptedTerms": true,
			"authKey": h, "recoveryAuth": h, "keys": map[string]any{"kdf": map[string]any{"alg": h, "salt": h}, "wrappedMasterKey": h}}, "", ip))
		check("verify", e.Do("POST", "/auth/verify-email", map[string]any{"email": h, "code": h}, "", ip))
		check("forgot", e.Do("POST", "/auth/password/forgot", map[string]any{"email": h}, "", ip))
		check("reset", e.Do("POST", "/auth/password/reset", map[string]any{"token": h, "mode": h, "newAuthKey": h, "recoveryAuth": h, "keys": map[string]any{}}, "", ip))
		check("refresh", e.Do("POST", "/auth/refresh", map[string]any{"refreshToken": h}, "", ip))
		check("perfil", e.Do("PATCH", "/me", map[string]any{"fullName": h}, tok, ip))
		check("correo nuevo", e.Do("POST", "/me/email-change", map[string]any{"newEmail": h, "authKey": h}, tok, ip))
		check("confirmar correo", e.Do("POST", "/me/email-change/confirm", map[string]any{"email": h, "code": h}, tok, ip))
		check("ajustes", e.Do("PATCH", "/settings", map[string]any{"theme": h}, tok, ip))
		check("sync cursor", e.Do("POST", "/sync", map[string]any{"cursor": h, "changes": []any{}}, tok, ip))
		check("sync cambio", e.Do("POST", "/sync", map[string]any{"cursor": nil, "changes": []any{map[string]any{
			"entity": h, "id": h, "op": h, "baseRevision": 0, "data": map[string]any{"payload": h, "wrappedKey": h, "folderId": h}}}}, tok, ip))
		check("compartir", e.Do("PUT", "/notes/"+note+"/share", map[string]any{"slug": h, "wrappedShareKey": h, "payload": h}, tok, ip))
		check("copia", e.Do("PUT", "/notes/"+note+"/share/payload", map[string]any{"payload": h}, tok, ip))
		// Parámetros de ruta y de consulta (codificados para que lleguen tal cual).
		enc := strings.NewReplacer("%", "%25", " ", "%20", "#", "%23", "?", "%3F", "\r", "%0D", "\n", "%0A", "\x00", "%00", "/", "%2F").Replace(h)
		if len(enc) > 2000 {
			enc = enc[:2000]
		}
		check("GET nota", e.Do("GET", "/notes/"+enc, nil, tok, ip))
		check("GET público", e.Do("GET", "/public/notes/"+enc, nil, "", ip))
		check("DELETE dispositivo", e.Do("DELETE", "/devices/"+enc, nil, tok, ip))
		check("lista", e.Do("GET", "/notes?trashed="+enc+"&updatedSince="+enc+"&cursor="+enc+"&limit="+enc, nil, tok, ip))
	}
	var users1 int
	_ = e.DB.Admin.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users1)
	if users1 != users0 {
		t.Fatalf("cambió el número de cuentas: %d → %d", users0, users1)
	}
	if r := e.Do("GET", "/notes/"+note, nil, tok, ""); r.Code != 200 {
		t.Fatalf("la nota original debe seguir intacta: %d", r.Code)
	}
}

// Cuerpos hostiles: anidamiento extremo, tamaño, tipos y JSON roto.
func TestHostileBodies(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	raw := func(path, ctype, body string) testutil.Resp { return e.DoRaw("POST", path, ctype, body, tok) }
	deep := strings.Repeat("[", 200_000) + strings.Repeat("]", 200_000)
	start := time.Now()
	for name, body := range map[string]string{
		"anidado":      `{"cursor":null,"changes":` + deep + `}`,
		"objeto vacío": `{}`,
		"null":         `null`,
		"array":        `[]`,
		"número":       `12345678901234567890123456789`,
		"roto":         `{"cursor":`,
		"basura":       "\x00\x01\x02",
		"duplicado":    `{"cursor":null,"cursor":"1","changes":[],"changes":[]}`,
	} {
		if r := raw("/sync", "application/json", body); r.Code >= 500 {
			t.Errorf("%s: %d", name, r.Code)
		}
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("procesar cuerpos hostiles tardó %v", time.Since(start))
	}
	// Tipo de contenido erróneo.
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/json; charset=\"\"\"", "multipart/form-data"} {
		if r := raw("/sync", ct, `{"cursor":null,"changes":[]}`); r.Code != 422 {
			t.Errorf("content-type %q: %d", ct, r.Code)
		}
	}
	// Cuerpos por encima del límite: 413, y /sync admite más que el resto pero no infinito.
	big := `{"x":"` + strings.Repeat("a", 2<<20) + `"}`
	if r := raw("/auth/login", "application/json", big); r.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("2 MiB en login: %d", r.Code)
	}
	huge := `{"cursor":null,"changes":[],"x":"` + strings.Repeat("a", 9<<20) + `"}`
	if r := raw("/sync", "application/json", huge); r.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("9 MiB en sync: %d", r.Code)
	}
}

// Las cabeceras de seguridad están en TODA respuesta, también en errores.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	for name, r := range map[string]testutil.Resp{
		"200": e.Do("GET", "/auth/session", nil, tok, ""), "401": e.Do("GET", "/auth/session", nil, "", ""),
		"404 ruta": e.Do("GET", "/no-existe", nil, "", ""), "404 recurso": e.Do("GET", "/public/notes/"+slug, nil, "", ""),
		"405": e.Do("DELETE", "/auth/login", nil, "", ""), "422": e.Do("POST", "/auth/login", map[string]any{}, "", ""),
	} {
		for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
			if r.Hdr.Get(h) != want {
				t.Errorf("%s: %s = %q", name, h, r.Hdr.Get(h))
			}
		}
		if !strings.Contains(r.Hdr.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: sin CSP", name)
		}
		if r.Hdr.Get("Server") != "" || r.Hdr.Get("X-Powered-By") != "" {
			t.Errorf("%s: revela el servidor", name)
		}
	}
}

// Un token de otra cuenta, manipulado o en un lugar inesperado nunca da acceso.
func TestAuthorizationHeaderAbuse(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	cases := map[string]string{"": "", "Basic": "Basic dXNlcjpwYXNz", "sin esquema": tok, "Bearer vacío": "Bearer ", "doble": "Bearer " + tok + " " + tok,
		"cortado": "Bearer " + tok[:len(tok)-3], "alg none": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.", "minúsculas con basura": "bearer x.y.z"}
	for name, h := range cases {
		r := e.DoRaw("GET", "/auth/session", "", "", "")
		_ = r
		if got := e.DoHeader("GET", "/auth/session", h); got.Code != 401 {
			t.Errorf("%s: %d", name, got.Code)
		}
	}
	// La query string no sirve como token.
	if r := e.Do("GET", "/auth/session?access_token="+tok, nil, "", ""); r.Code != 401 {
		t.Errorf("token en la URL aceptado: %d", r.Code)
	}
}
