// Package database abre el pool de conexiones a PostgreSQL.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect abre el pool y comprueba la conexión con reintentos cortos, para no
// morir en la carrera de arranque entre contenedores.
func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database: URL no válida")
	}
	cfg.MaxConns = 10
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	backoffs := []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}
	var last error
	for i := 0; i <= len(backoffs); i++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		last = pool.Ping(pingCtx)
		cancel()
		if last == nil {
			return pool, nil
		}
		if i < len(backoffs) {
			select {
			case <-time.After(backoffs[i]):
			case <-ctx.Done():
				pool.Close()
				return nil, ctx.Err()
			}
		}
	}
	pool.Close()
	return nil, fmt.Errorf("database: sin conexión: %w", last)
}
