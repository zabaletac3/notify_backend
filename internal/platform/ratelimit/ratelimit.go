// Package ratelimit limita intentos con estado en PostgreSQL: funciona igual con una o varias
// réplicas y sobrevive a reinicios. Falla cerrado: si la base de datos falla, el llamador debe
// denegar la operación.
package ratelimit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

const (
	maxStrikes   = 6
	maxBlock     = 24 * time.Hour
	strikesDecay = 24 * time.Hour
)

// Rule: tras Max intentos dentro de Window se bloquea Block (que se duplica en cada reincidencia,
// hasta 24 h). Un día sin bloqueos borra la reincidencia.
type Rule struct {
	Max    int
	Window time.Duration
	Block  time.Duration
}

// Reglas de la API (ver plan 0006, §5).
var (
	LoginByAccount = Rule{Max: 5, Window: 15 * time.Minute, Block: 15 * time.Minute}
	LoginByIP      = Rule{Max: 20, Window: time.Hour, Block: time.Hour}
	CodeResend     = Rule{Max: 5, Window: time.Hour, Block: time.Hour}
	CodeAttempt    = Rule{Max: 5, Window: 10 * time.Minute, Block: 15 * time.Minute}
	PreLogin       = Rule{Max: 30, Window: time.Minute, Block: 5 * time.Minute}
	PublicShare    = Rule{Max: 60, Window: time.Minute, Block: 5 * time.Minute}
)

// Result es la decisión de un intento.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration // si no está permitido: cuánto falta para poder reintentar
}

// Limiter guarda los contadores en la tabla rate_limits.
type Limiter struct {
	pool *pgxpool.Pool
	key  []byte
	// Now permite fijar el reloj en las pruebas.
	Now func() time.Time
}

// New crea el limitador. Las claves se guardan como HMAC (con el pepper): ni correos ni IP quedan en claro.
func New(pool *pgxpool.Pool, pepper []byte) *Limiter {
	return &Limiter{pool: pool, key: security.DeriveKey(pepper, "ratelimit"), Now: time.Now}
}

// Key construye la clave de un contador a partir de un tipo y sus partes (correo, IP...).
func (l *Limiter) Key(kind string, parts ...string) string {
	h := security.HashToken(strings.Join(append([]string{string(l.key)}, parts...), "\x00"))
	return kind + ":" + hex.EncodeToString(h[:16])
}

// Take cuenta un intento y lo permite si no supera Max (para operaciones que cuentan siempre:
// reenviar un código, abrir un enlace público).
func (l *Limiter) Take(ctx context.Context, key string, r Rule) (Result, error) {
	return l.hit(ctx, key, r, false)
}

// Fail cuenta un fallo (para el login). Al llegar a Max fallos bloquea.
func (l *Limiter) Fail(ctx context.Context, key string, r Rule) (Result, error) {
	return l.hit(ctx, key, r, true)
}

// Blocked indica si la clave está bloqueada ahora, sin contar nada.
func (l *Limiter) Blocked(ctx context.Context, key string) (Result, error) {
	var until *time.Time
	err := l.pool.QueryRow(ctx, `SELECT blocked_until FROM rate_limits WHERE key = $1`, key).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Allowed: true}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: %w", err)
	}
	now := l.Now()
	if until != nil && until.After(now) {
		return Result{RetryAfter: until.Sub(now)}, nil
	}
	return Result{Allowed: true}, nil
}

// Reset borra el contador (tras un login correcto).
func (l *Limiter) Reset(ctx context.Context, key string) error {
	if _, err := l.pool.Exec(ctx, `DELETE FROM rate_limits WHERE key = $1`, key); err != nil {
		return fmt.Errorf("ratelimit: %w", err)
	}
	return nil
}

func (l *Limiter) hit(ctx context.Context, key string, r Rule, blockAtMax bool) (Result, error) {
	if r.Max < 1 || r.Window <= 0 || r.Block <= 0 {
		return Result{}, errors.New("ratelimit: regla no válida")
	}
	now := l.Now()
	var res Result
	err := database.WithoutUser(ctx, l.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO rate_limits (key, count, window_start, strikes) VALUES ($1, 0, $2, 0) ON CONFLICT (key) DO NOTHING`,
			key, now); err != nil {
			return err
		}
		var (
			count, strikes int
			windowStart    time.Time
			blockedUntil   *time.Time
		)
		if err := tx.QueryRow(ctx,
			`SELECT count, window_start, blocked_until, strikes FROM rate_limits WHERE key = $1 FOR UPDATE`, key).
			Scan(&count, &windowStart, &blockedUntil, &strikes); err != nil {
			return err
		}

		if blockedUntil != nil && blockedUntil.After(now) {
			res = Result{RetryAfter: blockedUntil.Sub(now)}
			return nil // bloqueado: no se cuenta nada más
		}
		// Un día sin actividad ni bloqueos borra la reincidencia (se mide antes de reiniciar la ventana).
		last := windowStart
		if blockedUntil != nil && blockedUntil.After(last) {
			last = *blockedUntil
		}
		if now.Sub(last) >= strikesDecay {
			strikes = 0
		}
		if now.Sub(windowStart) >= r.Window {
			count, windowStart = 0, now
		}
		count++

		blocked := (blockAtMax && count >= r.Max) || (!blockAtMax && count > r.Max)
		if !blocked {
			res = Result{Allowed: true}
			_, err := tx.Exec(ctx, `UPDATE rate_limits SET count = $2, window_start = $3, blocked_until = NULL, strikes = $4 WHERE key = $1`,
				key, count, windowStart, strikes)
			return err
		}

		if strikes < maxStrikes {
			strikes++
		}
		d := r.Block << (strikes - 1)
		if d > maxBlock || d <= 0 {
			d = maxBlock
		}
		until := now.Add(d)
		res = Result{RetryAfter: d}
		_, err := tx.Exec(ctx,
			`UPDATE rate_limits SET count = 0, window_start = $2, blocked_until = $3, strikes = $4 WHERE key = $1`,
			key, now, until, strikes)
		return err
	})
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: %w", err)
	}
	return res, nil
}
