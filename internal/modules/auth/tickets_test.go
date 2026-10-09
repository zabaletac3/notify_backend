package auth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

// newTicketService monta un Service mínimo sobre una base de pruebas; el reloj es el que devuelva now.
func newTicketService(t *testing.T, now *time.Time) (*Service, *testdb.DB) {
	t.Helper()
	db := testdb.New(t)
	return &Service{Deps: Deps{Pool: db.App, Now: func() time.Time { return *now }}}, db
}

func withTx(ctx context.Context, t *testing.T, db *testdb.DB, fn func(tx pgx.Tx) error) {
	t.Helper()
	if err := database.WithoutUser(ctx, db.App, fn); err != nil {
		t.Fatalf("transacción: %v", err)
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, db := newTicketService(t, &now)

	var token string
	withTx(ctx, t, db, func(tx pgx.Tx) error {
		var err error
		token, err = s.newTicket(ctx, tx, "mfa-login", nil, map[string]any{"method": "password"}, 5*time.Minute)
		return err
	})
	if token == "" {
		t.Fatal("no se creó el ticket")
	}

	var firstID string
	withTx(ctx, t, db, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, "mfa-login", token)
		if err != nil || tk == nil {
			t.Fatalf("debía encontrar el ticket: %v %v", tk, err)
		}
		firstID = tk.ID
		return s.consumeTicket(ctx, tx, tk.ID)
	})

	withTx(ctx, t, db, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, "mfa-login", token)
		if err != nil || tk != nil {
			t.Fatalf("un ticket consumido no debe volver a servirse: %v %v", tk, err)
		}
		if firstID == "" {
			t.Fatal("sin id del primer uso")
		}
		return nil
	})
}

func TestTicketExpires(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, db := newTicketService(t, &now)

	var token string
	withTx(ctx, t, db, func(tx pgx.Tx) error {
		var err error
		token, err = s.newTicket(ctx, tx, "mfa-login", nil, map[string]any{}, time.Minute)
		return err
	})

	now = now.Add(2 * time.Minute)
	withTx(ctx, t, db, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, "mfa-login", token)
		if err != nil || tk != nil {
			t.Fatalf("un ticket caducado no debe servirse: %v %v", tk, err)
		}
		return nil
	})
}

func TestTicketPurposeIsCrossedOut(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, db := newTicketService(t, &now)

	var token string
	withTx(ctx, t, db, func(tx pgx.Tx) error {
		var err error
		token, err = s.newTicket(ctx, tx, "google-state", nil, map[string]any{}, time.Minute)
		return err
	})

	withTx(ctx, t, db, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, "google-result", token)
		if err != nil || tk != nil {
			t.Fatalf("un ticket no debe servir para otra finalidad: %v %v", tk, err)
		}
		return nil
	})
}

func TestTicketAttemptsCap(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, db := newTicketService(t, &now)

	var token string
	withTx(ctx, t, db, func(tx pgx.Tx) error {
		var err error
		token, err = s.newTicket(ctx, tx, "mfa-login", nil, map[string]any{}, time.Minute)
		return err
	})

	// Cinco intentos agotados en transacciones separadas (como haría el flujo real).
	for i := 0; i < ticketMaxAttempts; i++ {
		withTx(ctx, t, db, func(tx pgx.Tx) error {
			tk, err := s.takeTicket(ctx, tx, "mfa-login", token)
			if err != nil {
				return err
			}
			if tk == nil {
				t.Fatalf("intento %d: el ticket debía seguir vivo", i)
			}
			return s.bumpTicket(ctx, tx, tk.ID)
		})
	}

	withTx(ctx, t, db, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, "mfa-login", token)
		if err != nil || tk != nil {
			t.Fatalf("con el tope de intentos no debe servirse: %v %v", tk, err)
		}
		return nil
	})
}

func TestTicketMalformedToken(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	s, db := newTicketService(t, &now)

	withTx(ctx, t, db, func(tx pgx.Tx) error {
		for _, bad := range []string{"", "corto", string(make([]byte, 500))} {
			tk, err := s.takeTicket(ctx, tx, "mfa-login", bad)
			if err != nil || tk != nil {
				t.Fatalf("token mal formado %q: %v %v", bad, tk, err)
			}
		}
		return nil
	})
}
