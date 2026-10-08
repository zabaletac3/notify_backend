package notesync_test

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestSyncCreatesAndOtherDeviceDownloadsFoldersFirst(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	b := e.login("ana@example.com", "Móvil")
	folder, note := newID(), newID()

	r := a.sync(nil, noteUpsert(note, 0, folder, sealedPl), folderUpsert(folder, 0, sealedPl))
	if r.Code != 200 || len(list(r, "applied")) != 2 || r.cursor() == "" {
		t.Fatalf("subida: %s", r)
	}
	for _, ap := range list(r, "applied") {
		if ap["revision"] != float64(1) {
			t.Fatalf("revisión inicial: %v", ap)
		}
	}
	if len(list(r, "remoteChanges")) != 0 {
		t.Fatalf("lo propio no debe volver como remoto: %s", r)
	}

	d := b.sync(nil)
	remote := list(d, "remoteChanges")
	if d.Code != 200 || len(remote) != 2 || remote[0]["entity"] != "folder" || remote[1]["entity"] != "note" {
		t.Fatalf("descarga (carpetas antes que notas): %s", d)
	}
	n := remote[1]["note"].(map[string]any)
	if n["payload"] != sealedPl || n["folderId"] != folder || n["revision"] != float64(1) || n["lastEditedDeviceId"] != a.id {
		t.Fatalf("nota remota: %v", n)
	}
	// Sin cambios nuevos, el siguiente sync con el cursor no trae nada.
	if again := b.sync(d.cursor()); len(list(again, "remoteChanges")) != 0 || again.cursor() != d.cursor() {
		t.Fatalf("sync sin cambios: %s", again)
	}
}

func TestSyncUpdateBumpsRevisionAndPropagates(t *testing.T) {
	e := newEnv(t, Limits{})
	a, b := e.account("ana@example.com"), (*device)(nil)
	b = e.login("ana@example.com", "Móvil")
	id := newID()
	a.sync(nil, noteUpsert(id, 0, nil, sealedPl))
	first := b.sync(nil)

	r := a.sync(nil, noteUpsert(id, 1, nil, sealedPl2))
	if ap := list(r, "applied"); len(ap) != 1 || ap[0]["revision"] != float64(2) {
		t.Fatalf("actualización: %s", r)
	}
	got := b.sync(first.cursor())
	remote := list(got, "remoteChanges")
	if len(remote) != 1 || remote[0]["revision"] != float64(2) || remote[0]["note"].(map[string]any)["payload"] != sealedPl2 {
		t.Fatalf("propagación: %s", got)
	}
}

func TestSyncConflictDoesNotOverwrite(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	b := e.login("ana@example.com", "Pixel 8")
	id := newID()
	a.sync(nil, noteUpsert(id, 0, nil, sealedPl))
	cur := b.sync(nil).cursor()

	// A y B parten de la revisión 1. A gana; B recibe el conflicto con la versión de A y su nombre de dispositivo.
	a.sync(nil, noteUpsert(id, 1, nil, sealedPl2))
	r := b.sync(cur, noteUpsert(id, 1, nil, "a1.DDDDDDDDDDDDDDDD.QUJDREVGRw"))
	conf := list(r, "conflicts")
	if r.Code != 200 || len(conf) != 1 || len(list(r, "applied")) != 0 {
		t.Fatalf("conflicto: %s", r)
	}
	if conf[0]["noteId"] != id || conf[0]["remoteDeviceName"] != "Portátil" || conf[0]["remote"].(map[string]any)["payload"] != sealedPl2 {
		t.Fatalf("detalle del conflicto: %v", conf[0])
	}
	// El servidor conserva la versión de A.
	got := e.do("GET", "/notes/"+id, nil, b.token)
	if got.Body["payload"] != sealedPl2 || got.Body["revision"] != float64(2) {
		t.Fatalf("el servidor no debía cambiar: %s", got)
	}
	// B resuelve eligiendo "local": vuelve a subir sobre la revisión del servidor.
	ok := b.sync(r.cursor(), noteUpsert(id, 2, nil, "a1.DDDDDDDDDDDDDDDD.QUJDREVGRw"))
	if ap := list(ok, "applied"); len(ap) != 1 || ap[0]["revision"] != float64(3) {
		t.Fatalf("resolución local: %s", ok)
	}
}

func TestSyncDeleteTombstoneAndResurrection(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	b := e.login("ana@example.com", "Móvil")
	id := newID()
	a.sync(nil, noteUpsert(id, 0, nil, sealedPl))
	cur := b.sync(nil).cursor()

	r := a.sync(nil, del("note", id, 1))
	if ap := list(r, "applied"); len(ap) != 1 || ap[0]["revision"] != float64(1) {
		t.Fatalf("borrado: %s", r)
	}
	got := b.sync(cur)
	remote := list(got, "remoteChanges")
	if len(remote) != 1 || remote[0]["deleted"] != true || remote[0]["id"] != id {
		t.Fatalf("lápida: %s", got)
	}
	if g := e.do("GET", "/notes/"+id, nil, a.token); g.Code != 404 {
		t.Fatalf("la nota borrada debe dar 404: %d", g.Code)
	}
	// Borrar algo que no existe es idempotente.
	if r := a.sync(nil, del("note", newID(), 0)); r.Code != 200 || list(r, "applied")[0]["revision"] != float64(0) {
		t.Fatalf("borrado idempotente: %s", r)
	}
	// Recrear el mismo id limpia la lápida.
	a.sync(nil, noteUpsert(id, 0, nil, sealedPl2))
	var tombs int
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT count(*) FROM tombstones WHERE id = $1`, id).Scan(&tombs); err != nil || tombs != 0 {
		t.Fatalf("la lápida debía desaparecer: %d %v", tombs, err)
	}
}

func TestFolderDeleteUnlinksNotesAndLastWriteWins(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	b := e.login("ana@example.com", "Móvil")
	folder, note := newID(), newID()
	a.sync(nil, folderUpsert(folder, 0, sealedPl), noteUpsert(note, 0, folder, sealedPl))
	cur := b.sync(nil).cursor()

	// Carpetas: sin conflictos; cada escritura sube la revisión aunque baseRevision no coincida.
	r1 := a.sync(nil, folderUpsert(folder, 99, sealedPl2))
	if ap := list(r1, "applied"); ap[0]["revision"] != float64(2) {
		t.Fatalf("carpeta rev 2: %s", r1)
	}
	if len(list(r1, "conflicts")) != 0 {
		t.Fatal("las carpetas no tienen conflictos")
	}

	r := a.sync(nil, del("folder", folder, 0))
	if len(list(r, "applied")) != 1 {
		t.Fatalf("borrar carpeta: %s", r)
	}
	got := b.sync(cur)
	var sawTomb, sawNote bool
	for _, c := range list(got, "remoteChanges") {
		if c["entity"] == "folder" && c["deleted"] == true {
			sawTomb = true
		}
		if c["entity"] == "note" && c["id"] == note {
			sawNote = true
			n := c["note"].(map[string]any)
			if n["folderId"] != nil || n["revision"] != float64(2) {
				t.Fatalf("la nota debía quedar sin carpeta con revisión 2: %v", n)
			}
		}
	}
	if !sawTomb || !sawNote {
		t.Fatalf("faltan cambios remotos tras borrar la carpeta: %s", got)
	}
}

func TestSyncIsAtomicAndValidatesEverything(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	good := newID()
	bad := noteUpsert(newID(), 0, nil, "texto sin cifrar")

	r := a.sync(nil, noteUpsert(good, 0, nil, sealedPl), bad)
	if r.Code != 422 || r.Body["kind"] != "validation" {
		t.Fatalf("debía rechazar: %s", r)
	}
	if g := e.do("GET", "/notes/"+good, nil, a.token); g.Code != 404 {
		t.Fatalf("no debe quedar nada a medias: %d", g.Code)
	}

	huge := "a1.AAAAAAAAAAAAAAAA." + strings.Repeat("A", 1_500_001)
	cases := map[string][]map[string]any{
		"id inválido":       {noteUpsert("no-uuid", 0, nil, sealedPl)},
		"entidad":           {{"entity": "tag", "id": newID(), "op": "upsert", "baseRevision": 0}},
		"operación":         {{"entity": "note", "id": newID(), "op": "merge", "baseRevision": 0}},
		"upsert sin datos":  {{"entity": "note", "id": newID(), "op": "upsert", "baseRevision": 0}},
		"revisión negativa": {noteUpsert(newID(), -1, nil, sealedPl)},
		"carpeta inválida":  {noteUpsert(newID(), 0, "x", sealedPl)},
		"nota enorme":       {noteUpsert(newID(), 0, nil, huge)},
		"carpeta enorme":    {folderUpsert(newID(), 0, "a1.AAAAAAAAAAAAAAAA."+strings.Repeat("A", 70_000))},
	}
	for name, ch := range cases {
		if r := a.sync(nil, ch...); r.Code != 422 && r.Code != 413 {
			t.Errorf("%s: %s", name, r)
		}
	}
	// Campo desconocido dentro de data, cursor inválido y demasiados cambios.
	extra := noteUpsert(newID(), 0, nil, sealedPl)
	extra["data"].(map[string]any)["isAdmin"] = true
	if r := a.sync(nil, extra); r.Code != 422 {
		t.Errorf("campo desconocido: %s", r)
	}
	if r := a.sync("abc"); r.Code != 422 {
		t.Errorf("cursor inválido: %s", r)
	}
	if r := a.sync("-5"); r.Code != 422 {
		t.Errorf("cursor negativo: %s", r)
	}
	many := make([]map[string]any, 501)
	for i := range many {
		many[i] = del("note", newID(), 0)
	}
	if r := a.sync(nil, many...); r.Code != 422 {
		t.Errorf("más de 500 cambios: %s", r)
	}
}

func TestSyncRejectsIDsOfOtherAccountsAndNeverLeaksThem(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	b := e.account("luis@example.com")
	id := newID()
	a.sync(nil, noteUpsert(id, 0, nil, sealedPl))

	// Luis intenta crear/actualizar/borrar con el id de Ana.
	for name, c := range map[string]map[string]any{
		"crear":      noteUpsert(id, 0, nil, sealedPl2),
		"actualizar": noteUpsert(id, 1, nil, sealedPl2),
	} {
		if r := b.sync(nil, c); r.Code != 422 && r.Code != 200 {
			t.Errorf("%s: %s", name, r)
		} else if r.Code == 200 && len(list(r, "applied")) != 0 && name == "actualizar" {
			t.Errorf("%s: se aplicó sobre una nota ajena: %s", name, r)
		}
	}
	b.sync(nil, del("note", id, 1))
	// La nota de Ana sigue intacta.
	got := e.do("GET", "/notes/"+id, nil, a.token)
	if got.Code != 200 || got.Body["payload"] != sealedPl || got.Body["revision"] != float64(1) {
		t.Fatalf("la nota de Ana cambió: %s", got)
	}
	// Luis no la ve ni por lectura ni por sync.
	if g := e.do("GET", "/notes/"+id, nil, b.token); g.Code != 404 {
		t.Fatalf("lectura ajena: %d", g.Code)
	}
	if r := b.sync(nil); strings.Contains(r.Raw, id) {
		t.Fatalf("sync de Luis filtra la nota de Ana: %s", r)
	}
	if l := e.do("GET", "/notes", nil, b.token); strings.Contains(l.Raw, id) {
		t.Fatalf("listado de Luis filtra la nota de Ana: %s", l)
	}
}

func TestSyncUsesTheTokenDeviceNotTheBody(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	id := newID()
	a.sync(nil, noteUpsert(id, 0, nil, sealedPl)) // el cuerpo dice deviceId "ignorado"
	n := e.do("GET", "/notes/"+id, nil, a.token)
	if n.Body["lastEditedDeviceId"] != a.id {
		t.Fatalf("debía usar el dispositivo del token: %v", n.Body["lastEditedDeviceId"])
	}
}

func TestSyncRequiresAuthAndLiveDevice(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	b := e.login("ana@example.com", "Móvil")
	if r := e.do("POST", "/sync", map[string]any{"cursor": nil, "changes": []any{}}, ""); r.Code != 401 {
		t.Fatalf("sin token: %d", r.Code)
	}
	for _, p := range []string{"/notes", "/folders"} {
		if r := e.do("GET", p, nil, ""); r.Code != 401 {
			t.Fatalf("%s sin token: %d", p, r.Code)
		}
	}
	if r := e.do("DELETE", "/devices/"+b.id, nil, a.token); r.Code != 204 {
		t.Fatalf("quitar dispositivo: %d", r.Code)
	}
	if r := b.sync(nil); r.Code != 401 || r.Body["kind"] != "device-revoked" {
		t.Fatalf("dispositivo quitado: %s", r)
	}
}

func TestQuotaLimits(t *testing.T) {
	e := newEnv(t, Limits{MaxChanges: 500, MaxNotes: 3, MaxFolders: 1})
	a := e.account("ana@example.com")
	if r := a.sync(nil, noteUpsert(newID(), 0, nil, sealedPl), noteUpsert(newID(), 0, nil, sealedPl), noteUpsert(newID(), 0, nil, sealedPl)); r.Code != 200 {
		t.Fatalf("hasta el límite: %s", r)
	}
	if r := a.sync(nil, noteUpsert(newID(), 0, nil, sealedPl)); r.Code != 403 || r.Body["code"] != "limit-reached" {
		t.Fatalf("pasado el límite: %s", r)
	}
	// Actualizar y borrar no cuentan como crear.
	n := newID()
	if r := a.sync(nil, del("note", n, 0)); r.Code != 200 {
		t.Fatalf("borrar con la cuenta llena: %s", r)
	}
	if r := a.sync(nil, folderUpsert(newID(), 0, sealedPl), folderUpsert(newID(), 0, sealedPl)); r.Code != 403 {
		t.Fatalf("límite de carpetas: %s", r)
	}
}

func TestReadEndpointsPaginateAndFilter(t *testing.T) {
	e := newEnv(t, Limits{})
	a := e.account("ana@example.com")
	var ids []string
	for i := 0; i < 5; i++ {
		id := newID()
		ids = append(ids, id)
		c := noteUpsert(id, 0, nil, sealedPl)
		if i%2 == 1 { // dos en la papelera
			c["data"].(map[string]any)["deletedAt"] = ts
		}
		a.sync(nil, c)
	}
	a.sync(nil, folderUpsert(newID(), 0, sealedPl))

	p1 := e.do("GET", "/notes?limit=2", nil, a.token)
	items := list(p1, "items")
	if p1.Code != 200 || len(items) != 2 || p1.Body["nextCursor"] == nil {
		t.Fatalf("página 1: %s", p1)
	}
	p2 := e.do("GET", "/notes?limit=2&cursor="+p1.Body["nextCursor"].(string), nil, a.token)
	p3 := e.do("GET", "/notes?limit=2&cursor="+p2.Body["nextCursor"].(string), nil, a.token)
	if len(list(p2, "items")) != 2 || len(list(p3, "items")) != 1 || p3.Body["nextCursor"] != nil {
		t.Fatalf("paginación: %s | %s | %s", p1, p2, p3)
	}
	trashed := e.do("GET", "/notes?trashed=true", nil, a.token)
	active := e.do("GET", "/notes?trashed=false", nil, a.token)
	if len(list(trashed, "items")) != 2 || len(list(active, "items")) != 3 {
		t.Fatalf("filtro de papelera: %s | %s", trashed, active)
	}
	for _, q := range []string{"limit=0", "limit=999", "trashed=quizas", "updatedSince=ayer", "cursor=x"} {
		if r := e.do("GET", "/notes?"+q, nil, a.token); r.Code != 422 {
			t.Errorf("%s: %d", q, r.Code)
		}
	}
	if r := e.do("GET", "/notes/no-uuid", nil, a.token); r.Code != 404 {
		t.Fatalf("id inválido: %d", r.Code)
	}
	if f := e.do("GET", "/folders", nil, a.token); f.Code != 200 || !strings.HasPrefix(f.Raw, "[") {
		t.Fatalf("carpetas: %s", f)
	}
	_ = ids
}

// Muchos dispositivos escribiendo a la vez: el cursor nunca salta nada.
func TestConcurrentSyncNeverLosesChanges(t *testing.T) {
	e := newEnv(t, Limits{})
	e.account("ana@example.com")
	const writers, perWriter = 4, 5
	devs := make([]*device, writers)
	for i := range devs {
		devs[i] = e.login("ana@example.com", "Dispositivo")
	}
	reader := e.login("ana@example.com", "Lector")

	seen := map[string]bool{}
	var mu sync.Mutex
	cursor := ""
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // el lector sincroniza sin parar mientras los demás escriben
		defer close(done)
		for {
			var cur any
			if cursor != "" {
				cur = cursor
			}
			r := reader.sync(cur)
			if r.Code == 200 {
				cursor = r.cursor()
				mu.Lock()
				for _, c := range list(r, "remoteChanges") {
					seen[c["id"].(string)] = true
				}
				mu.Unlock()
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	var wg sync.WaitGroup
	want := map[string]bool{}
	var wmu sync.Mutex
	for _, d := range devs {
		wg.Add(1)
		go func(d *device) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := newID()
				wmu.Lock()
				want[id] = true
				wmu.Unlock()
				if r := d.sync(nil, noteUpsert(id, 0, nil, sealedPl)); r.Code != 200 {
					t.Errorf("escritura: %s", r)
				}
			}
		}(d)
	}
	wg.Wait()
	close(stop)
	<-done
	// Una última pasada con el cursor del lector recoge lo que faltara.
	r := reader.sync(cursor)
	mu.Lock()
	for _, c := range list(r, "remoteChanges") {
		seen[c["id"].(string)] = true
	}
	mu.Unlock()
	for id := range want {
		if !seen[id] {
			t.Fatalf("el lector se perdió la nota %s (cursor saltó un cambio)", id)
		}
	}
	var dup int
	if err := e.db.Admin.QueryRow(context.Background(), `SELECT count(*) - count(DISTINCT seq) FROM notes`).Scan(&dup); err != nil || dup != 0 {
		t.Fatalf("seq repetidos: %d %v", dup, err)
	}
}

func TestStorageQuotaBlocksUploads(t *testing.T) {
	// Cada nota de prueba pesa ~60 bytes cifrados: una cuota de 100 admite una y rechaza la segunda.
	e := newEnv(t, Limits{MaxChanges: 500, MaxNotes: 100, MaxFolders: 10, QuotaBytes: 100})
	a := e.account("ana@example.com")
	if r := a.sync(nil, noteUpsert(newID(), 0, nil, sealedPl)); r.Code != 200 {
		t.Fatalf("primera nota: %s", r)
	}
	if r := a.sync(nil, noteUpsert(newID(), 0, nil, sealedPl), noteUpsert(newID(), 0, nil, sealedPl)); r.Code != 403 || r.Body["code"] != "quota-exceeded" {
		t.Fatalf("pasada la cuota: %s", r)
	}
	// Borrar siempre se permite aunque la cuenta esté llena.
	if r := a.sync(nil, del("note", newID(), 0)); r.Code != 200 {
		t.Fatalf("borrar con la cuota llena: %s", r)
	}
}
