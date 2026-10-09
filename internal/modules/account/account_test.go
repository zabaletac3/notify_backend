package account_test

import (
	"encoding/base32"
	"strings"
	"testing"

	"github.com/zabaletac3/notify_backend/internal/platform/security"
	"github.com/zabaletac3/notify_backend/internal/testutil"
)

func TestSettingsDefaultsAndPatch(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")

	g := e.Do("GET", "/settings", nil, tok, "")
	want := map[string]any{"theme": "system", "textSize": "medium", "noteOrder": "updated", "openWithNewNote": false, "showPreview": true,
		"language": "es", "autoSync": true, "wifiOnly": false, "biometricLock": true, "lockOnExit": true, "lockTimeout": "1m", "twoFactor": false}
	if g.Code != 200 || len(g.Body) != len(want) {
		t.Fatalf("GET: %d %s", g.Code, g.Raw)
	}
	for k, v := range want {
		if g.Body[k] != v {
			t.Errorf("%s: %v (esperado %v)", k, g.Body[k], v)
		}
	}

	p := e.Do("PATCH", "/settings", map[string]any{"theme": "dark", "textSize": "large", "autoSync": false}, tok, "")
	if p.Code != 200 || p.Body["theme"] != "dark" || p.Body["textSize"] != "large" || p.Body["autoSync"] != false || p.Body["showPreview"] != true {
		t.Fatalf("PATCH: %d %s", p.Code, p.Raw)
	}
	// Se conserva y se puede cambiar otro campo sin perder el anterior.
	e.Do("PATCH", "/settings", map[string]any{"lockTimeout": "5m"}, tok, "")
	g = e.Do("GET", "/settings", nil, tok, "")
	if g.Body["theme"] != "dark" || g.Body["lockTimeout"] != "5m" || g.Body["autoSync"] != false {
		t.Fatalf("persistencia: %s", g.Raw)
	}
}

func TestSettingsValidation(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	for name, b := range map[string]map[string]any{
		"vacío":             {},
		"tema inválido":     {"theme": "neon"},
		"idioma":            {"language": "en"},
		"tiempo":            {"lockTimeout": "1h"},
		"campo desconocido": {"isAdmin": true},
		"tipo erróneo":      {"autoSync": "si"},
		"2FA no disponible": {"twoFactor": true},
	} {
		if r := e.Do("PATCH", "/settings", b, tok, ""); r.Code != 422 {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	// `twoFactor` es de solo lectura: enviarlo, sea `true` o `false`, da 422.
	for _, v := range []bool{true, false} {
		if r := e.Do("PATCH", "/settings", map[string]any{"twoFactor": v}, tok, ""); r.Code != 422 {
			t.Errorf("twoFactor=%v: %d %s", v, r.Code, r.Raw)
		}
	}
	// Los fallos no cambian nada.
	if g := e.Do("GET", "/settings", nil, tok, ""); g.Body["theme"] != "system" {
		t.Fatalf("una petición inválida cambió los ajustes: %s", g.Raw)
	}
}

func TestSettingsReflectMfaState(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")

	r := e.Do("POST", "/mfa/totp/setup", map[string]any{"authKey": testutil.AuthKey}, tok, "")
	if r.Code != 200 {
		t.Fatalf("setup: %d %s", r.Code, r.Raw)
	}
	secret, _ := r.Body["secret"].(string)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	code := security.TOTPCode(raw, e.Now.Unix()/30)
	if en := e.Do("POST", "/mfa/totp/enable", map[string]any{"code": code}, tok, ""); en.Code != 200 {
		t.Fatalf("enable: %d %s", en.Code, en.Raw)
	}
	// `twoFactor` del contrato refleja el estado real (se calcula desde user_totp).
	g := e.Do("GET", "/settings", nil, tok, "")
	if g.Body["twoFactor"] != true {
		t.Fatalf("twoFactor debería ser true: %s", g.Raw)
	}
}

func TestSettingsAreIsolatedAndNeedAuth(t *testing.T) {
	e := testutil.New(t)
	ta, tb := e.Account("ana@example.com"), e.Account("luis@example.com")
	e.Do("PATCH", "/settings", map[string]any{"theme": "dark"}, ta, "")
	if g := e.Do("GET", "/settings", nil, tb, ""); g.Body["theme"] != "system" {
		t.Fatalf("Luis ve los ajustes de Ana: %s", g.Raw)
	}
	for _, m := range []string{"GET", "PATCH"} {
		if r := e.Do(m, "/settings", map[string]any{"theme": "dark"}, "", ""); r.Code != 401 {
			t.Errorf("%s sin token: %d", m, r.Code)
		}
	}
	if r := e.Do("GET", "/storage/usage", nil, "", ""); r.Code != 401 {
		t.Errorf("uso sin token: %d", r.Code)
	}
}

func TestStorageUsage(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	empty := e.Do("GET", "/storage/usage", nil, tok, "")
	if empty.Code != 200 || empty.Body["usedBytes"] != float64(0) || empty.Body["quotaBytes"] != float64(1<<30) || empty.Body["imagesBytes"] != float64(0) {
		t.Fatalf("vacío: %s", empty.Raw)
	}
	e.CreateNote(tok, false)
	e.CreateNote(tok, true) // en la papelera
	u := e.Do("GET", "/storage/usage", nil, tok, "")
	notes, trash, used := u.Body["notesBytes"].(float64), u.Body["trashBytes"].(float64), u.Body["usedBytes"].(float64)
	if notes <= 0 || trash <= 0 || used != notes+trash || notes != trash {
		t.Fatalf("uso: %s", u.Raw)
	}
	// Otra cuenta no suma lo ajeno.
	other := e.Account("luis@example.com")
	if o := e.Do("GET", "/storage/usage", nil, other, ""); o.Body["usedBytes"] != float64(0) {
		t.Fatalf("Luis ve el uso de Ana: %s", o.Raw)
	}
	if strings.Contains(u.Raw, "ana@") {
		t.Fatal("el uso no debe incluir datos personales")
	}
}
