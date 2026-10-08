package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/zabaletac3/notify_backend/migrations"
)

// Migrate aplica o consulta las migraciones con goose. Debe ejecutarse con el rol dueño de las
// tablas (nunca con el rol de la API).
func Migrate(ctx context.Context, url, command string) error {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return fmt.Errorf("migrate: URL no válida")
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("migrate: sin conexión: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	switch command {
	case "up":
		_, err = provider.Up(ctx)
	case "down":
		_, err = provider.Down(ctx)
	case "status":
		var st []*goose.MigrationStatus
		if st, err = provider.Status(ctx); err == nil {
			for _, s := range st {
				fmt.Printf("%-6d %-12s %s\n", s.Source.Version, s.State, s.Source.Path)
			}
		}
	default:
		return fmt.Errorf("migrate: comando desconocido %q (up|down|status)", command)
	}
	if err != nil {
		return fmt.Errorf("migrate %s: %w", command, err)
	}
	return nil
}

var _ = stdlib.GetDefaultDriver // registra el driver "pgx"
