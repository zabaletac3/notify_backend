// Command migrate aplica las migraciones de la base de datos.
//
// Usa MIGRATE_DATABASE_URL (rol dueño de las tablas), distinta de DATABASE_URL (rol de la API,
// sin permisos de DDL).
package main

import (
	"context"
	"fmt"
	"github.com/zabaletac3/notify_backend/internal/platform/config"
	"os"
	"os/signal"

	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := config.LoadDotEnv(".env"); err != nil { // solo desarrollo: el entorno del proceso manda
		return err
	}
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		return fmt.Errorf("falta MIGRATE_DATABASE_URL")
	}
	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return database.Migrate(ctx, url, cmd)
}
