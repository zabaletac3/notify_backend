package database_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

const sealed = "a1.AAAAAAAAAAAAAAAA.QUJDRA"

var ctx = context.Background()

func newUser(t *testing.T, db *testdb.DB, email string) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	_, err := db.Admin.Exec(ctx,
		`INSERT INTO users (id, email, full_name, kdf, auth_key_hash, keys) VALUES ($1, $2, 'Test', '{}', '\x01', '{}')`, id, email)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func insertNote(tx pgx.Tx, id, owner string) error {
	_, err := tx.Exec(ctx, `INSERT INTO notes (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload)
		VALUES ($1, $2, 1, 1, now(), now(), $3, $3)`, id, owner, sealed)
	return err
}

func TestMigrationsUpDownUp(t *testing.T) {
	db := testdb.New(t)
	url := db.Admin.Config().ConnString()
	if err := database.Migrate(ctx, url, "up"); err != nil { // idempotente
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, url, "down"); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, url, "up"); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"users", "notes", "folders", "tombstones", "devices", "share_links",
		"refresh_tokens", "verification_codes", "rate_limits", "audit_log"} {
		var ok bool
		if err := db.Admin.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, tbl).Scan(&ok); err != nil || !ok {
			t.Errorf("falta la tabla %s", tbl)
		}
	}
}

func TestRowLevelSecurityIsEnabledEverywhere(t *testing.T) {
	db := testdb.New(t)
	for _, tbl := range []string{"notes", "folders", "tombstones", "devices", "share_links"} {
		var on bool
		if err := db.Admin.QueryRow(ctx, `SELECT relrowsecurity FROM pg_class WHERE oid = $1::regclass`, tbl).Scan(&on); err != nil || !on {
			t.Errorf("RLS apagado en %s", tbl)
		}
	}
}

func TestAppRoleIsNotPrivileged(t *testing.T) {
	db := testdb.New(t)
	var super, bypass, createdb, createrole bool
	err := db.App.QueryRow(ctx, `SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user`).
		Scan(&super, &bypass, &createdb, &createrole)
	if err != nil || super || bypass || createdb || createrole {
		t.Fatalf("el rol de la API tiene privilegios de más: %v %v %v %v %v", super, bypass, createdb, createrole, err)
	}
	// Sin DDL.
	if _, err := db.App.Exec(ctx, `CREATE TABLE evil (x int)`); pgCode(err) != "42501" {
		t.Errorf("la API pudo crear tablas: %v", err)
	}
	if _, err := db.App.Exec(ctx, `DROP TABLE notes`); err == nil {
		t.Error("la API pudo borrar tablas")
	}
	// No puede borrar cuentas ni leer la auditoría.
	if _, err := db.App.Exec(ctx, `DELETE FROM users`); pgCode(err) != "42501" {
		t.Errorf("la API pudo borrar usuarios: %v", err)
	}
	if _, err := db.App.Exec(ctx, `SELECT * FROM audit_log`); pgCode(err) != "42501" {
		t.Errorf("la API pudo leer la auditoría: %v", err)
	}
	if _, err := db.App.Exec(ctx, `INSERT INTO audit_log (event) VALUES ('login')`); err != nil {
		t.Errorf("la API debe poder escribir en la auditoría: %v", err)
	}
}

func TestRLSIsolatesAccounts(t *testing.T) {
	db := testdb.New(t)
	a, b := newUser(t, db, "a@example.com"), newUser(t, db, "b@example.com")
	noteA := uuid.Must(uuid.NewV7()).String()

	if err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error { return insertNote(tx, noteA, a) }); err != nil {
		t.Fatal(err)
	}

	// B no ve, no modifica y no borra la nota de A.
	err := database.WithUser(ctx, db.App, b, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notes`).Scan(&n); err != nil || n != 0 {
			t.Errorf("B ve %d notas de A (%v)", n, err)
		}
		up, err := tx.Exec(ctx, `UPDATE notes SET revision = 99 WHERE id = $1`, noteA)
		if err != nil || up.RowsAffected() != 0 {
			t.Errorf("B modificó la nota de A: %v %v", up.RowsAffected(), err)
		}
		del, err := tx.Exec(ctx, `DELETE FROM notes WHERE id = $1`, noteA)
		if err != nil || del.RowsAffected() != 0 {
			t.Errorf("B borró la nota de A: %v %v", del.RowsAffected(), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// B no puede escribir filas a nombre de A (WITH CHECK).
	err = database.WithUser(ctx, db.App, b, func(tx pgx.Tx) error {
		return insertNote(tx, uuid.Must(uuid.NewV7()).String(), a)
	})
	if pgCode(err) != "42501" {
		t.Errorf("B pudo insertar a nombre de A: %v", err)
	}

	// B no puede reutilizar el id de una nota de A (clave primaria global).
	err = database.WithUser(ctx, db.App, b, func(tx pgx.Tx) error { return insertNote(tx, noteA, b) })
	if pgCode(err) != "23505" {
		t.Errorf("B pudo reutilizar el id de A: %v", err)
	}

	// A sigue viendo su nota intacta.
	var rev int
	if err := db.Admin.QueryRow(ctx, `SELECT revision FROM notes WHERE id = $1`, noteA).Scan(&rev); err != nil || rev != 1 {
		t.Errorf("la nota de A cambió: %d %v", rev, err)
	}
}

func TestRLSFailsClosedWithoutUser(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	noteA := uuid.Must(uuid.NewV7()).String()
	if err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error { return insertNote(tx, noteA, a) }); err != nil {
		t.Fatal(err)
	}
	err := database.WithoutUser(ctx, db.App, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notes`).Scan(&n); err != nil || n != 0 {
			t.Errorf("sin cuenta se ven %d notas (%v)", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.WithoutUser(ctx, db.App, func(tx pgx.Tx) error { return insertNote(tx, uuid.NewString(), a) }); pgCode(err) != "42501" {
		t.Errorf("sin cuenta se pudo insertar: %v", err)
	}
}

func TestEveryRLSTableIsolated(t *testing.T) {
	db := testdb.New(t)
	a, b := newUser(t, db, "a@example.com"), newUser(t, db, "b@example.com")
	inserts := map[string]string{
		"folders":    `INSERT INTO folders (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload) VALUES (gen_random_uuid(), $1, 1, 1, now(), now(), '` + sealed + `', '` + sealed + `')`,
		"tombstones": `INSERT INTO tombstones (user_id, entity, id, revision, seq) VALUES ($1, 'note', gen_random_uuid(), 1, 1)`,
		"devices":    `INSERT INTO devices (id, user_id, name) VALUES (gen_random_uuid(), $1, 'Portátil')`,
	}
	for tbl, q := range inserts {
		if err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, q, a); return err }); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		err := database.WithUser(ctx, db.App, b, func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s: B ve %d filas de A (%v)", tbl, n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNextSeqOnlyTouchesOwnAccount(t *testing.T) {
	db := testdb.New(t)
	a, b := newUser(t, db, "a@example.com"), newUser(t, db, "b@example.com")
	var s1, s2 int64
	_ = database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT next_seq()`).Scan(&s1); err != nil {
			t.Fatal(err)
		}
		return tx.QueryRow(ctx, `SELECT next_seq()`).Scan(&s2)
	})
	if s1 != 1 || s2 != 2 {
		t.Fatalf("secuencia %d,%d", s1, s2)
	}
	var seqB int64
	if err := db.Admin.QueryRow(ctx, `SELECT account_seq FROM users WHERE id = $1`, b).Scan(&seqB); err != nil || seqB != 0 {
		t.Fatalf("next_seq tocó otra cuenta: %d %v", seqB, err)
	}
	// Sin cuenta no devuelve nada.
	err := database.WithoutUser(ctx, db.App, func(tx pgx.Tx) error {
		var s *int64
		if err := tx.QueryRow(ctx, `SELECT next_seq()`).Scan(&s); err != nil || s != nil {
			t.Errorf("next_seq sin cuenta devolvió %v (%v)", s, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNextSeqIsConcurrentSafe(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	const n = 20
	seen := make(chan int64, n)
	for i := 0; i < n; i++ {
		go func() {
			var s int64
			_ = database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT next_seq()`).Scan(&s) })
			seen <- s
		}()
	}
	uniq := map[int64]bool{}
	for i := 0; i < n; i++ {
		uniq[<-seen] = true
	}
	if len(uniq) != n {
		t.Fatalf("hubo secuencias repetidas: %d únicas de %d", len(uniq), n)
	}
}

func TestPublicShareReadIsScoped(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	note := uuid.Must(uuid.NewV7()).String()
	slug, other := strings.Repeat("a", 22), strings.Repeat("b", 22)
	if err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error {
		if err := insertNote(tx, note, a); err != nil {
			return err
		}
		for _, s := range []string{slug, other} {
			nid := note
			if s == other {
				nid = uuid.Must(uuid.NewV7()).String()
				if err := insertNote(tx, nid, a); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO share_links (slug, note_id, user_id, payload) VALUES ($1, $2, $3, $4)`, s, nid, a, sealed); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	err := database.WithPublicSlug(ctx, db.App, slug, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM share_links`).Scan(&n); err != nil || n != 1 {
			t.Errorf("con el slug se ven %d enlaces (debía ser 1): %v", n, err)
		}
		// Solo lectura: no puede modificar ni borrar.
		if up, err := tx.Exec(ctx, `UPDATE share_links SET payload = $1`, sealed); err != nil || up.RowsAffected() != 0 {
			t.Errorf("el acceso público pudo modificar: %v %v", up.RowsAffected(), err)
		}
		if del, err := tx.Exec(ctx, `DELETE FROM share_links`); err != nil || del.RowsAffected() != 0 {
			t.Errorf("el acceso público pudo borrar: %v %v", del.RowsAffected(), err)
		}
		// Y no ve las notas.
		var notes int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notes`).Scan(&notes); err != nil || notes != 0 {
			t.Errorf("el acceso público ve notas: %d %v", notes, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestShareLinkDiesWithNote(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	note, slug := uuid.Must(uuid.NewV7()).String(), strings.Repeat("c", 22)
	err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error {
		if err := insertNote(tx, note, a); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO share_links (slug, note_id, user_id, payload) VALUES ($1, $2, $3, $4)`, slug, note, a, sealed); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM notes WHERE id = $1`, note)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.Admin.QueryRow(ctx, `SELECT count(*) FROM share_links`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("el enlace sobrevivió a la nota: %d %v", n, err)
	}
}

func TestCheckConstraintsRejectBadData(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	bad := map[string]string{
		"texto sin cifrar":    "hola mundo",
		"versión desconocida": "a2.AAAA.BBBB",
		"base64 inválido":     "a1.AA AA.BBBB",
		"sin texto cifrado":   "a1.AAAA.",
	}
	for name, payload := range bad {
		err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO notes (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload)
				VALUES (gen_random_uuid(), $1, 1, 1, now(), now(), $2, $3)`, a, sealed, payload)
			return err
		})
		if pgCode(err) != "23514" {
			t.Errorf("%s: se aceptó (%v)", name, err)
		}
	}
	// Correo en mayúsculas y slug de longitud incorrecta.
	if _, err := db.Admin.Exec(ctx, `INSERT INTO users (id, email, full_name, kdf, auth_key_hash, keys) VALUES (gen_random_uuid(), 'Ana@Example.com', 'Test', '{}', '\x01', '{}')`); pgCode(err) != "23514" {
		t.Errorf("correo en mayúsculas aceptado: %v", err)
	}
	if _, err := db.Admin.Exec(ctx, `INSERT INTO share_links (slug, note_id, user_id, payload) VALUES ('corto', gen_random_uuid(), $1, $2)`, a, sealed); pgCode(err) != "23514" {
		t.Errorf("slug corto aceptado: %v", err)
	}
	// Tamaño máximo de carpeta.
	big := "a1.AAAA." + strings.Repeat("A", 65537)
	err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO folders (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload)
			VALUES (gen_random_uuid(), $1, 1, 1, now(), now(), $2, $3)`, a, sealed, big)
		return err
	})
	if pgCode(err) != "23514" {
		t.Errorf("carpeta gigante aceptada: %v", err)
	}
}

func TestWithUserRejectsBadIDAndRollsBack(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	if err := database.WithUser(ctx, db.App, "no-es-uuid'; DROP TABLE notes;--", func(pgx.Tx) error { return nil }); !errors.Is(err, database.ErrInvalidUser) {
		t.Fatalf("id inválido aceptado: %v", err)
	}
	boom := errors.New("boom")
	note := uuid.Must(uuid.NewV7()).String()
	err := database.WithUser(ctx, db.App, a, func(tx pgx.Tx) error {
		if err := insertNote(tx, note, a); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("error inesperado: %v", err)
	}
	var n int
	if err := db.Admin.QueryRow(ctx, `SELECT count(*) FROM notes`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("no se revirtió: %d %v", n, err)
	}
}

func TestUserContextDoesNotLeakThroughThePool(t *testing.T) {
	db := testdb.New(t)
	a := newUser(t, db, "a@example.com")
	// Una sola conexión: si el valor se filtrara, lo veríamos en la siguiente consulta.
	one, err := pgxPoolMax1(db)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	if err := database.WithUser(ctx, one, a, func(tx pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var v string
	if err := one.QueryRow(ctx, `SELECT coalesce(current_setting('app.user_id', true), '')`).Scan(&v); err != nil || v != "" {
		t.Fatalf("app.user_id se filtró a la conexión: %q %v", v, err)
	}
}

func TestDiscardUnverifiedOnlyTouchesUnverified(t *testing.T) {
	db := testdb.New(t)
	verified := newUser(t, db, "ok@example.com")
	if _, err := db.Admin.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, verified); err != nil {
		t.Fatal(err)
	}
	newUser(t, db, "pending@example.com")
	var n int
	if err := db.App.QueryRow(ctx, `SELECT discard_unverified_user('ok@example.com')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("borró una cuenta verificada: %d %v", n, err)
	}
	if err := db.App.QueryRow(ctx, `SELECT discard_unverified_user('pending@example.com')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("no borró la cuenta sin verificar: %d %v", n, err)
	}
	var left int
	if err := db.Admin.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("quedan %d cuentas", left)
	}
}
