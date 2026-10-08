// Package testdb crea bases de datos PostgreSQL desechables para las pruebas de integración.
//
// Necesita TEST_DATABASE_URL con un usuario administrador (en CI es el servicio postgres).
// Sin la variable, las pruebas se omiten en local y fallan en CI (CI=true) para no ocultar nada.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

// DB agrupa los dos pools de una base de pruebas.
type DB struct {
	Admin *pgxpool.Pool // dueño de las tablas (omite RLS)
	App   *pgxpool.Pool // rol de la API: sujeto a permisos y RLS
}

// New crea la base, aplica las migraciones y devuelve los pools. Se limpia sola al terminar.
func New(t *testing.T) *DB {
	t.Helper()
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("TEST_DATABASE_URL es obligatoria en CI")
		}
		t.Skip("TEST_DATABASE_URL no definida: se omiten las pruebas con PostgreSQL")
	}
	ctx := context.Background()
	suffix := randHex(6)
	dbName, role, pass := "apunte_t_"+suffix, "apunte_api_"+suffix, randHex(16)

	root, err := pgxpool.New(ctx, adminURL)
	must(t, err)
	t.Cleanup(root.Close)
	_, err = root.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, dbName))
	must(t, err)

	dbURL := withDB(t, adminURL, dbName, "", "")
	must(t, database.Migrate(ctx, dbURL, "up"))

	// Rol de login de la API: miembro de apunte_app (creado por la migración).
	_, err = root.Exec(ctx, fmt.Sprintf(`CREATE ROLE %q LOGIN PASSWORD '%s' IN ROLE apunte_app`, role, pass))
	must(t, err)

	admin, err := pgxpool.New(ctx, dbURL)
	must(t, err)
	app, err := pgxpool.New(ctx, withDB(t, adminURL, dbName, role, pass))
	must(t, err)

	t.Cleanup(func() {
		app.Close()
		admin.Close()
		_, _ = root.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, dbName))
		_, _ = root.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %q`, role))
	})
	return &DB{Admin: admin, App: app}
}

func withDB(t *testing.T, raw, db, user, pass string) string {
	t.Helper()
	u, err := url.Parse(raw)
	must(t, err)
	u.Path = "/" + db
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
