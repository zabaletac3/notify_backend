// Package purge borra lo que ya cumplió su plazo de conservación (D7): notas en la papelera,
// cuentas eliminadas, lápidas, sesiones y códigos caducados, contadores de límites y auditoría vieja.
// Es idempotente: se puede ejecutar cuantas veces haga falta (cron diario).
package purge

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config son los plazos de conservación.
type Config struct {
	TrashRetention    time.Duration // notas en la papelera
	AccountGrace      time.Duration // cuentas eliminadas
	TombstoneRetain   time.Duration // lápidas
	RevokedDeviceKeep time.Duration // dispositivos cerrados (se conservan un tiempo para reconocer `device-revoked`)
	AuditRetention    time.Duration
	BatchSize         int
	Now               func() time.Time
}

// Defaults devuelve los plazos del plan 0006 (§4, D7).
func Defaults() Config {
	day := 24 * time.Hour
	return Config{TrashRetention: 30 * day, AccountGrace: 30 * day, TombstoneRetain: 90 * day,
		RevokedDeviceKeep: 30 * day, AuditRetention: 365 * day, BatchSize: 1000, Now: time.Now}
}

// Report cuenta lo borrado.
type Report struct {
	Notes, Accounts, Tombstones, Devices, RefreshTokens, Codes, RateLimits, Audit int64
}

func (r Report) String() string {
	return fmt.Sprintf("notas=%d cuentas=%d lapidas=%d dispositivos=%d renovaciones=%d codigos=%d limites=%d auditoria=%d",
		r.Notes, r.Accounts, r.Tombstones, r.Devices, r.RefreshTokens, r.Codes, r.RateLimits, r.Audit)
}

// Run ejecuta todas las purgas. Si una falla, devuelve el error con lo hecho hasta ese momento.
func Run(ctx context.Context, pool *pgxpool.Pool, cfg Config, log *slog.Logger) (Report, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1000
	}
	now := cfg.Now()
	var rep Report
	steps := []struct {
		name string
		fn   func() (int64, error)
		dst  *int64
	}{
		{"cuentas", func() (int64, error) { return purgeAccounts(ctx, pool, now.Add(-cfg.AccountGrace), cfg.BatchSize) }, &rep.Accounts},
		{"notas", func() (int64, error) { return purgeTrash(ctx, pool, now, now.Add(-cfg.TrashRetention), cfg.BatchSize) }, &rep.Notes},
		{"lápidas", func() (int64, error) {
			return execCount(ctx, pool, `DELETE FROM tombstones WHERE created_at < $1`, now.Add(-cfg.TombstoneRetain))
		}, &rep.Tombstones},
		{"dispositivos", func() (int64, error) {
			return execCount(ctx, pool, `DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at < $1`, now.Add(-cfg.RevokedDeviceKeep))
		}, &rep.Devices},
		{"renovaciones", func() (int64, error) {
			// Se conservan 7 días tras caducar o revocarse: la detección de reutilización necesita ver los gastados.
			return execCount(ctx, pool, `DELETE FROM refresh_tokens WHERE expires_at < $1 OR revoked_at < $1`, now.Add(-7*24*time.Hour))
		}, &rep.RefreshTokens},
		{"códigos", func() (int64, error) {
			return execCount(ctx, pool, `DELETE FROM verification_codes WHERE expires_at < $1 OR consumed_at < $1`, now.Add(-24*time.Hour))
		}, &rep.Codes},
		{"límites", func() (int64, error) {
			// Contadores sin actividad ni bloqueo vigente desde hace 2 días (la reincidencia decae a las 24 h).
			return execCount(ctx, pool, `DELETE FROM rate_limits WHERE window_start < $1 AND (blocked_until IS NULL OR blocked_until < $1)`, now.Add(-48*time.Hour))
		}, &rep.RateLimits},
		{"auditoría", func() (int64, error) {
			return execCount(ctx, pool, `DELETE FROM audit_log WHERE at < $1`, now.Add(-cfg.AuditRetention))
		}, &rep.Audit},
	}
	for _, st := range steps {
		n, err := st.fn()
		*st.dst = n
		if err != nil {
			return rep, fmt.Errorf("purga de %s: %w", st.name, err)
		}
		log.Info("purga", "paso", st.name, "borrados", n)
	}
	return rep, nil
}

func execCount(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) (int64, error) {
	tag, err := pool.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

// purgeAccounts borra las cuentas eliminadas hace más que el plazo (las claves foráneas en cascada se
// llevan sus notas, carpetas, enlaces, dispositivos, sesiones y códigos).
func purgeAccounts(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time, batch int) (int64, error) {
	var total int64
	for {
		tag, err := pool.Exec(ctx, `DELETE FROM users WHERE id IN (SELECT id FROM users WHERE deleted_at < $1 LIMIT $2)`, cutoff, batch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			return total, nil
		}
	}
}

// purgeTrash borra las notas que llevan más del plazo en la papelera y deja una lápida por cada una con
// un seq nuevo de su cuenta, para que los dispositivos que aún las tengan las eliminen al sincronizar.
func purgeTrash(ctx context.Context, pool *pgxpool.Pool, now, cutoff time.Time, batch int) (int64, error) {
	var total int64
	for {
		var n, scanned int64
		err := inTx(ctx, pool, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id::text, user_id::text, revision FROM notes WHERE deleted_at < $1 ORDER BY user_id LIMIT $2`, cutoff, batch)
			if err != nil {
				return err
			}
			type victim struct {
				id, user string
				rev      int
			}
			var vs []victim
			for rows.Next() {
				var v victim
				if err := rows.Scan(&v.id, &v.user, &v.rev); err != nil {
					rows.Close()
					return err
				}
				vs = append(vs, v)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, v := range vs {
				// Mismo orden de bloqueos que la API (primero la cuenta, luego la nota): evita interbloqueos.
				// Un seq nuevo por lápida: el cursor de /sync necesita que sean únicos para paginar sin perder cambios.
				var seq int64
				if err := tx.QueryRow(ctx, `UPDATE users SET account_seq = account_seq + 1 WHERE id = $1 RETURNING account_seq`, v.user).Scan(&seq); err != nil {
					return err
				}
				// Se vuelve a comprobar el plazo al borrar: si la persona la restauró entre tanto, no se toca.
				tag, err := tx.Exec(ctx, `DELETE FROM notes WHERE id = $1 AND deleted_at < $2`, v.id, cutoff)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					continue
				}
				n++
				if _, err := tx.Exec(ctx, `INSERT INTO tombstones (user_id, entity, id, revision, seq, created_at) VALUES ($1, 'note', $2, $3, $4, $5)
					ON CONFLICT (user_id, entity, id) DO UPDATE SET revision = EXCLUDED.revision, seq = EXCLUDED.seq, created_at = EXCLUDED.created_at`,
					v.user, v.id, v.rev, seq, now); err != nil {
					return err
				}
			}
			scanned = int64(len(vs))
			return nil
		})
		if err != nil {
			return total, err
		}
		total += n
		if scanned < int64(batch) {
			return total, nil
		}
	}
}

func inTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
