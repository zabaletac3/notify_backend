package share_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zabaletac3/notify_backend/internal/testutil"
)

const (
	slug1 = "AbCdEfGhIjKlMnOpQrStUv" // 22 caracteres
	slug2 = "ZyXwVuTsRqPoNmLkJiHgFe"
	wrap  = "a1.WWWWWWWWWWWWWWWW.QUJDRA"
	copyA = "a1.PPPPPPPPPPPPPPPP.QUJDREVGRw"
	copyB = "a1.QQQQQQQQQQQQQQQQ.QUJDREVGRw"
)

func in(slug, payload string) map[string]any {
	return map[string]any{"slug": slug, "wrappedShareKey": wrap, "payload": payload}
}

func TestShareLifecycle(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	note := e.CreateNote(tok, false)

	// Sin enlace: GET devuelve null.
	if r := e.Do("GET", "/notes/"+note+"/share", nil, tok, ""); r.Code != 200 || strings.TrimSpace(r.Raw) != "null" {
		t.Fatalf("sin enlace: %d %q", r.Code, r.Raw)
	}
	// Crear.
	c := e.Do("PUT", "/notes/"+note+"/share", in(slug1, copyA), tok, "")
	if c.Code != 200 || c.Body["slug"] != slug1 || c.Body["noteId"] != note || c.Body["wrappedShareKey"] != wrap || c.Body["payload"] != copyA || c.Body["id"] == "" {
		t.Fatalf("crear: %d %s", c.Code, c.Raw)
	}
	// Idempotente: devuelve el existente e ignora lo enviado.
	again := e.Do("PUT", "/notes/"+note+"/share", in(slug2, copyB), tok, "")
	if again.Code != 200 || again.Body["slug"] != slug1 || again.Body["id"] != c.Body["id"] || again.Body["payload"] != copyA {
		t.Fatalf("segunda creación: %s", again.Raw)
	}
	if g := e.Do("GET", "/notes/"+note+"/share", nil, tok, ""); g.Code != 200 || g.Body["slug"] != slug1 {
		t.Fatalf("GET: %s", g.Raw)
	}

	// Lectura pública, sin sesión.
	p := e.Do("GET", "/public/notes/"+slug1, nil, "", "")
	if p.Code != 200 || p.Body["payload"] != copyA || p.Body["updatedAt"] == nil {
		t.Fatalf("público: %d %s", p.Code, p.Raw)
	}
	if len(p.Body) != 2 {
		t.Fatalf("la respuesta pública solo debe llevar payload y updatedAt: %s", p.Raw)
	}
	if p.Hdr.Get("Cache-Control") != "no-store" || p.Hdr.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(p.Hdr.Get("X-Robots-Tag"), "noindex") {
		t.Fatalf("cabeceras: %v", p.Hdr)
	}

	// Actualizar la copia.
	e.Now = e.Now.Add(time.Minute)
	if r := e.Do("PUT", "/notes/"+note+"/share/payload", map[string]any{"payload": copyB}, tok, ""); r.Code != 204 {
		t.Fatalf("actualizar: %d %s", r.Code, r.Raw)
	}
	if p := e.Do("GET", "/public/notes/"+slug1, nil, "", ""); p.Body["payload"] != copyB {
		t.Fatalf("la copia pública no cambió: %s", p.Raw)
	}

	// Revocar: 204, idempotente, y desde ese momento 404 igual que un enlace que nunca existió.
	if r := e.Do("DELETE", "/notes/"+note+"/share", nil, tok, ""); r.Code != 204 {
		t.Fatalf("revocar: %d", r.Code)
	}
	if r := e.Do("DELETE", "/notes/"+note+"/share", nil, tok, ""); r.Code != 204 {
		t.Fatalf("revocar dos veces: %d", r.Code)
	}
	revoked := e.Do("GET", "/public/notes/"+slug1, nil, "", "")
	never := e.Do("GET", "/public/notes/"+slug2, nil, "", "")
	bad := e.Do("GET", "/public/notes/corto", nil, "", "")
	if revoked.Code != 404 || revoked.Raw != never.Raw || never.Raw != bad.Raw || bad.Code != 404 {
		t.Fatalf("404 distinguibles: %q / %q / %q", revoked.Raw, never.Raw, bad.Raw)
	}
	// Volver a compartir crea uno nuevo (clave y slug nuevos).
	n := e.Do("PUT", "/notes/"+note+"/share", in(slug2, copyA), tok, "")
	if n.Code != 200 || n.Body["slug"] != slug2 || n.Body["id"] == c.Body["id"] {
		t.Fatalf("recompartir: %s", n.Raw)
	}
}

func TestShareValidation(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	note := e.CreateNote(tok, false)
	cases := map[string]map[string]any{
		"slug corto":      in("corto", copyA),
		"slug con signos": in(strings.Repeat("!", 22), copyA),
		"slug largo":      in(strings.Repeat("a", 23), copyA),
		"copia en claro":  in(slug1, "mi nota en claro"),
		"clave en claro":  {"slug": slug1, "wrappedShareKey": "clave", "payload": copyA},
	}
	for name, b := range cases {
		if r := e.Do("PUT", "/notes/"+note+"/share", b, tok, ""); r.Code != 422 || r.Body["kind"] != "validation" {
			t.Errorf("%s: %d %s", name, r.Code, r.Raw)
		}
	}
	if r := e.Do("PUT", "/notes/"+note+"/share", map[string]any{"slug": slug1, "wrappedShareKey": wrap, "payload": copyA, "extra": 1}, tok, ""); r.Code != 422 {
		t.Errorf("campo desconocido: %d", r.Code)
	}
	if g := e.Do("GET", "/notes/"+note+"/share", nil, tok, ""); strings.TrimSpace(g.Raw) != "null" {
		t.Fatalf("una creación inválida no debe dejar enlace: %s", g.Raw)
	}
	if r := e.Do("PUT", "/notes/"+note+"/share/payload", map[string]any{"payload": copyB}, tok, ""); r.Code != 404 {
		t.Fatalf("actualizar sin enlace: %d", r.Code)
	}
}

func TestShareRequiresSyncedNoteOutsideTrash(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	trashed := e.CreateNote(tok, true)
	for _, id := range []string{trashed, testutil.NewID(), "no-uuid"} {
		if r := e.Do("PUT", "/notes/"+id+"/share", in(slug1, copyA), tok, ""); r.Code != 404 {
			t.Errorf("nota %q: %d %s", id, r.Code, r.Raw)
		}
	}
}

func TestSlugCollisionAndCrossAccountIsolation(t *testing.T) {
	e := testutil.New(t)
	ta, tb := e.Account("ana@example.com"), e.Account("luis@example.com")
	na, nb := e.CreateNote(ta, false), e.CreateNote(tb, false)
	if r := e.Do("PUT", "/notes/"+na+"/share", in(slug1, copyA), ta, ""); r.Code != 200 {
		t.Fatalf("Ana: %d", r.Code)
	}
	// Luis intenta el mismo slug: 422 slug-taken.
	if r := e.Do("PUT", "/notes/"+nb+"/share", in(slug1, copyB), tb, ""); r.Code != 422 || r.Body["fields"].(map[string]any)["slug"] != "slug-taken" {
		t.Fatalf("slug repetido: %d %s", r.Code, r.Raw)
	}
	// Luis no puede ver, cambiar ni revocar el enlace de Ana, ni compartir su nota.
	if r := e.Do("GET", "/notes/"+na+"/share", nil, tb, ""); strings.TrimSpace(r.Raw) != "null" {
		t.Fatalf("Luis ve el enlace de Ana: %s", r.Raw)
	}
	if r := e.Do("PUT", "/notes/"+na+"/share", in(slug2, copyB), tb, ""); r.Code != 404 {
		t.Fatalf("Luis comparte la nota de Ana: %d", r.Code)
	}
	if r := e.Do("PUT", "/notes/"+na+"/share/payload", map[string]any{"payload": copyB}, tb, ""); r.Code != 404 {
		t.Fatalf("Luis edita la copia de Ana: %d", r.Code)
	}
	e.Do("DELETE", "/notes/"+na+"/share", nil, tb, "")
	if p := e.Do("GET", "/public/notes/"+slug1, nil, "", ""); p.Code != 200 || p.Body["payload"] != copyA {
		t.Fatalf("el enlace de Ana cambió: %s", p.Raw)
	}
	// Sin sesión no se gestionan enlaces.
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if r := e.Do(m, "/notes/"+na+"/share", in(slug2, copyB), "", ""); r.Code != 401 {
			t.Errorf("%s sin token: %d", m, r.Code)
		}
	}
}

func TestPublicEndpointOnlyExposesTheCopy(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	note := e.CreateNote(tok, false)
	e.Do("PUT", "/notes/"+note+"/share", in(slug1, copyA), tok, "")
	p := e.Do("GET", "/public/notes/"+slug1, nil, "", "")
	for _, secret := range []string{note, wrap, "ana@example.com", "userId", "noteId", "wrappedShareKey"} {
		if strings.Contains(p.Raw, secret) {
			t.Fatalf("la respuesta pública filtra %q: %s", secret, p.Raw)
		}
	}
}

func TestPublicReadIsRateLimitedPerIP(t *testing.T) {
	e := testutil.New(t)
	var last testutil.Resp
	for i := 0; i < 70; i++ {
		last = e.Do("GET", "/public/notes/"+slug2, nil, "", "203.0.113.50")
	}
	if last.Code != 429 || last.Hdr.Get("Retry-After") == "" {
		t.Fatalf("sin límite: %d", last.Code)
	}
	// Otra IP no se ve afectada.
	if r := e.Do("GET", "/public/notes/"+slug2, nil, "", "203.0.113.51"); r.Code != 404 {
		t.Fatalf("otra IP: %d", r.Code)
	}
}

func TestTrashingOrDeletingTheNoteKillsTheLink(t *testing.T) {
	e := testutil.New(t)
	tok := e.Account("ana@example.com")
	share := func(slug string) string {
		id := e.CreateNote(tok, false)
		if r := e.Do("PUT", "/notes/"+id+"/share", in(slug, copyA), tok, ""); r.Code != 200 {
			t.Fatalf("compartir: %d", r.Code)
		}
		return id
	}
	sync := func(change map[string]any) {
		if r := e.Do("POST", "/sync", map[string]any{"deviceId": "x", "deviceName": "x", "cursor": nil, "changes": []map[string]any{change}}, tok, ""); r.Code != 200 {
			t.Fatalf("sync: %d %s", r.Code, r.Raw)
		}
	}
	// Mover a la papelera revoca el enlace.
	a := share(slug1)
	sync(map[string]any{"entity": "note", "id": a, "op": "upsert", "baseRevision": 1, "data": map[string]any{
		"folderId": nil, "createdAt": "2026-03-01T10:00:00Z", "updatedAt": "2026-03-02T10:00:00Z", "deletedAt": "2026-03-02T10:00:00Z",
		"wrappedKey": testutil.SealedKey, "payload": testutil.SealedB}})
	if p := e.Do("GET", "/public/notes/"+slug1, nil, "", ""); p.Code != 404 {
		t.Fatalf("una nota en la papelera sigue pública: %d", p.Code)
	}
	// Borrar la nota definitivamente también.
	b := share(slug2)
	sync(map[string]any{"entity": "note", "id": b, "op": "delete", "baseRevision": 1})
	if p := e.Do("GET", "/public/notes/"+slug2, nil, "", ""); p.Code != 404 {
		t.Fatalf("una nota borrada sigue pública: %d", p.Code)
	}
	var n int
	if err := e.DB.Admin.QueryRow(context.Background(), `SELECT count(*) FROM share_links`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("quedan enlaces: %d %v", n, err)
	}
}
