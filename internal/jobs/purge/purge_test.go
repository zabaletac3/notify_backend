package purge_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zabaletac3/notify_backend/internal/jobs/purge"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

var (
	ctx    = context.Background()
	log    = slog.New(slog.NewJSONHandler(io.Discard, nil))
	sealed = "a1.AAAAAAAAAAAAAAAA.QUJDRA"
)

func day(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

type fixture struct {
	t     *testing.T
	db    *testdb.DB
	now   time.Time
	alive string // cuenta activa
	gone  string // cuenta eliminada hace 31 días
	grace string // cuenta eliminada hace 5 días
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Admin.Exec(ctx, sql, args...); err != nil {
		f.t.Fatalf("%v\n%s", err, sql)
	}
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.Admin.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) user(email string, deletedAgo time.Duration) string {
	id := uuid.Must(uuid.NewV7()).String()
	var deleted *time.Time
	if deletedAgo > 0 {
		d := f.now.Add(-deletedAgo)
		deleted = &d
	}
	f.exec(`INSERT INTO users (id, email, full_name, kdf, auth_key_hash, keys, deleted_at) VALUES ($1, $2, 'Test', '{}', '\x01', '{}', $3)`, id, email, deleted)
	return id
}

func (f *fixture) note(user string, trashedAgo time.Duration) string {
	id := uuid.Must(uuid.NewV7()).String()
	var deleted *time.Time
	if trashedAgo > 0 {
		d := f.now.Add(-trashedAgo)
		deleted = &d
	}
	f.exec(`INSERT INTO notes (id, user_id, revision, seq, created_at, updated_at, deleted_at, wrapped_key, payload) VALUES ($1, $2, 3, 1, now(), now(), $3, $4, $4)`, id, user, deleted, sealed)
	return id
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, db: testdb.New(t), now: time.Now().UTC()}
	f.alive = f.user("alive@example.com", 0)
	f.gone = f.user("gone@example.com", day(31))
	f.grace = f.user("grace@example.com", day(5))
	return f
}

func (f *fixture) run() purge.Report {
	f.t.Helper()
	cfg := purge.Defaults()
	cfg.Now = func() time.Time { return f.now }
	cfg.BatchSize = 2
	rep, err := purge.Run(ctx, f.db.Maint, cfg, log)
	if err != nil {
		f.t.Fatal(err)
	}
	return rep
}

func TestPurgeDeletesTrashPastRetentionAndLeavesTombstones(t *testing.T) {
	f := newFixture(t)
	old1, old2, old3 := f.note(f.alive, day(40)), f.note(f.alive, day(31)), f.note(f.alive, day(45))
	recent, active := f.note(f.alive, day(10)), f.note(f.alive, 0)
	f.exec(`UPDATE users SET account_seq = 7 WHERE id = $1`, f.alive)

	rep := f.run()
	if rep.Notes != 3 {
		t.Fatalf("notas purgadas: %d", rep.Notes)
	}
	for _, id := range []string{old1, old2, old3} {
		if f.count(`SELECT count(*) FROM notes WHERE id = $1`, id) != 0 {
			t.Errorf("la nota %s debía borrarse", id)
		}
		if f.count(`SELECT count(*) FROM tombstones WHERE id = $1 AND entity = 'note' AND seq > 7 AND revision = 3`, id) != 1 {
			t.Errorf("falta la lápida de %s con un seq nuevo", id)
		}
	}
	for _, id := range []string{recent, active} {
		if f.count(`SELECT count(*) FROM notes WHERE id = $1`, id) != 1 {
			t.Errorf("la nota %s no debía borrarse", id)
		}
	}
	// Un seq nuevo por lápida (único por cuenta): 7 + 3 notas = 10.
	if seq := f.count(`SELECT account_seq FROM users WHERE id = $1`, f.alive); seq != 10 {
		t.Fatalf("seq de la cuenta: %d", seq)
	}
	if f.count(`SELECT count(DISTINCT seq) FROM tombstones WHERE user_id = $1`, f.alive) != 3 {
		t.Fatal("las lápidas deben tener seq distintos")
	}
}

func TestPurgeAccountsAfterGraceWithCascade(t *testing.T) {
	f := newFixture(t)
	f.note(f.gone, 0)
	f.note(f.grace, 0)
	f.exec(`INSERT INTO devices (id, user_id, name) VALUES (gen_random_uuid(), $1, 'Portátil')`, f.gone)

	rep := f.run()
	if rep.Accounts != 1 {
		t.Fatalf("cuentas purgadas: %d", rep.Accounts)
	}
	if f.count(`SELECT count(*) FROM users WHERE id = $1`, f.gone) != 0 || f.count(`SELECT count(*) FROM notes WHERE user_id = $1`, f.gone) != 0 ||
		f.count(`SELECT count(*) FROM devices WHERE user_id = $1`, f.gone) != 0 {
		t.Fatal("la cuenta eliminada y sus datos debían borrarse en cascada")
	}
	if f.count(`SELECT count(*) FROM users WHERE id = ANY($1)`, []string{f.alive, f.grace}) != 2 || f.count(`SELECT count(*) FROM notes WHERE user_id = $1`, f.grace) != 1 {
		t.Fatal("las cuentas activa y en gracia no se tocan")
	}
}

func TestPurgeHousekeeping(t *testing.T) {
	f := newFixture(t)
	old, recent := f.now.Add(-day(100)), f.now.Add(-day(10))
	// Lápidas.
	for i, at := range []time.Time{old, recent} {
		f.exec(`INSERT INTO tombstones (user_id, entity, id, revision, seq, created_at) VALUES ($1, 'note', gen_random_uuid(), 1, $2, $3)`, f.alive, i+1, at)
	}
	// Dispositivos cerrados hace mucho / hace poco / vigente.
	dev := func(revoked *time.Time) string {
		id := uuid.Must(uuid.NewV7()).String()
		f.exec(`INSERT INTO devices (id, user_id, name, revoked_at) VALUES ($1, $2, 'D', $3)`, id, f.alive, revoked)
		return id
	}
	oldRev, newRev := f.now.Add(-day(40)), f.now.Add(-day(2))
	dOld, dNew, dLive := dev(&oldRev), dev(&newRev), dev(nil)
	// Tokens de renovación: uno caducado hace 10 días y uno vigente.
	f.exec(`INSERT INTO refresh_tokens (id, user_id, device_id, family_id, token_hash, expires_at) VALUES
		(gen_random_uuid(), $1, $2, gen_random_uuid(), '\x01', $3), (gen_random_uuid(), $1, $2, gen_random_uuid(), '\x02', $4)`, f.alive, dLive, f.now.Add(-day(10)), f.now.Add(day(10)))
	// Códigos.
	f.exec(`INSERT INTO verification_codes (user_id, purpose, code_hash, expires_at) VALUES ($1, 'verify-email', '\x01', $2)`, f.alive, f.now.Add(-day(2)))
	f.exec(`INSERT INTO verification_codes (user_id, purpose, code_hash, expires_at) VALUES ($1, 'password-reset', '\x02', $2)`, f.alive, f.now.Add(time.Hour))
	// Límites y auditoría.
	f.exec(`INSERT INTO rate_limits (key, count, window_start) VALUES ('viejo', 3, $1), ('nuevo', 3, $2)`, f.now.Add(-day(3)), f.now.Add(-time.Hour))
	f.exec(`INSERT INTO rate_limits (key, count, window_start, blocked_until) VALUES ('bloqueado', 0, $1, $2)`, f.now.Add(-day(3)), f.now.Add(time.Hour))
	f.exec(`INSERT INTO audit_log (user_id, event, at) VALUES ($1, 'viejo', $2), ($1, 'nuevo', $3)`, f.alive, f.now.Add(-day(400)), f.now.Add(-day(5)))

	rep := f.run()
	if rep.Tombstones != 1 || rep.Devices != 1 || rep.RefreshTokens != 1 || rep.Codes != 1 || rep.RateLimits != 1 || rep.Audit != 1 {
		t.Fatalf("informe: %s", rep)
	}
	if f.count(`SELECT count(*) FROM devices WHERE id = $1`, dOld) != 0 || f.count(`SELECT count(*) FROM devices WHERE id = ANY($1)`, []string{dNew, dLive}) != 2 {
		t.Fatal("dispositivos")
	}
	if f.count(`SELECT count(*) FROM rate_limits WHERE key IN ('nuevo', 'bloqueado')`) != 2 {
		t.Fatal("no debe borrar contadores recientes ni bloqueos vigentes")
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE event = 'nuevo'`) != 1 {
		t.Fatal("auditoría reciente")
	}
}

func TestPurgeIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.note(f.alive, day(40))
	first := f.run()
	second := f.run()
	if first.Notes != 1 || first.Accounts != 1 {
		t.Fatalf("primera pasada: %s", first)
	}
	if (second != purge.Report{}) {
		t.Fatalf("la segunda pasada no debía borrar nada: %s", second)
	}
}

func TestMaintenanceRoleIsNotThePrivilegedOne(t *testing.T) {
	f := newFixture(t)
	var super, bypass bool
	if err := f.db.Maint.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil || super || bypass {
		t.Fatalf("el rol de mantenimiento tiene privilegios de más: %v %v %v", super, bypass, err)
	}
	if _, err := f.db.Maint.Exec(ctx, `CREATE TABLE evil (x int)`); err == nil {
		t.Fatal("el rol de mantenimiento pudo crear tablas")
	}
	if _, err := f.db.Maint.Exec(ctx, `UPDATE users SET email = 'x@y.com'`); err == nil {
		t.Fatal("el rol de mantenimiento pudo modificar correos")
	}
	if _, err := f.db.Maint.Exec(ctx, `UPDATE notes SET payload = 'a1.x.y'`); err == nil {
		t.Fatal("el rol de mantenimiento pudo modificar notas")
	}
	// Y la API no puede ejecutar la purga.
	if _, err := f.db.App.Exec(ctx, `DELETE FROM users`); err == nil {
		t.Fatal("la API pudo borrar usuarios")
	}
}
