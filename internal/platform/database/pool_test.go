package database_test

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

// pgxPoolMax1 abre un pool de una sola conexión con las mismas credenciales que la API.
func pgxPoolMax1(db *testdb.DB) (*pgxpool.Pool, error) {
	cfg := db.App.Config()
	cfg.MaxConns = 1
	return pgxpool.NewWithConfig(ctx, cfg)
}
