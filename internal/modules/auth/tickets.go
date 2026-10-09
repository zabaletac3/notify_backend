package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

// Los tickets son filas de un solo uso y corta vida para pasos intermedios (segundo factor MFA,
// estados y resultados de Google). Nunca guardan secretos que den acceso por sí solos: solo datos
// para continuar el flujo, y siempre ligados a una finalidad.
const (
	ticketMaxAttempts = 5
	ticketMinLen      = 20
	ticketMaxLen      = 200
)

// ticket es una fila de auth_tickets viva (no consumida, sin caducar y por debajo del tope de intentos).
type ticket struct {
	ID        string
	UserID    *string // nil cuando el ticket es anterior a tener cuenta
	Payload   []byte
	Attempts  int
	ExpiresAt time.Time
}

// newTicket crea un ticket y devuelve el token en claro (solo se guarda su hash). tx no necesita la
// cuenta fijada cuando userID es nil.
func (s *Service) newTicket(ctx context.Context, tx pgx.Tx, purpose string, userID *string, payload any, ttl time.Duration) (string, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	now := s.Now()
	if _, err := tx.Exec(ctx, `INSERT INTO auth_tickets (purpose, token_hash, user_id, payload, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		purpose, security.HashToken(token), userID, raw, now.Add(ttl), now); err != nil {
		return "", err
	}
	return token, nil
}

// takeTicket busca y bloquea un ticket vigente de esa finalidad. Devuelve nil (sin error) si no
// existe, venció, ya se consumió o superó el tope de intentos; en esos casos no se distingue cuál.
func (s *Service) takeTicket(ctx context.Context, tx pgx.Tx, purpose, token string) (*ticket, error) {
	if len(token) < ticketMinLen || len(token) > ticketMaxLen {
		return nil, nil
	}
	var (
		t        ticket
		userID   *string
		consumed *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT id::text, user_id::text, payload, attempts, expires_at, consumed_at
		FROM auth_tickets WHERE token_hash = $1 AND purpose = $2 FOR UPDATE`,
		security.HashToken(token), purpose).
		Scan(&t.ID, &userID, &t.Payload, &t.Attempts, &t.ExpiresAt, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if consumed != nil || !t.ExpiresAt.After(s.Now()) || t.Attempts >= ticketMaxAttempts {
		return nil, nil
	}
	t.UserID = userID
	return &t, nil
}

// consumeTicket marca el ticket como usado.
func (s *Service) consumeTicket(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE auth_tickets SET consumed_at = $2 WHERE id = $1`, id, s.Now())
	return err
}

// bumpTicket suma un intento fallido (el tope lo aplica takeTicket).
func (s *Service) bumpTicket(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE auth_tickets SET attempts = attempts + 1 WHERE id = $1`, id)
	return err
}
