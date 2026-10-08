package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInvalidUser indica un id de cuenta que no es un UUID.
var ErrInvalidUser = errors.New("database: invalid user id")

// WithUser ejecuta fn en una transacción con la cuenta fijada para la seguridad por fila (RLS).
// `set_config(..., true)` limita el valor a la transacción: no puede quedar en la conexión
// cuando vuelve al pool. Si fn falla, se revierte todo.
func WithUser(ctx context.Context, pool *pgxpool.Pool, userID string, fn func(tx pgx.Tx) error) error {
	id, err := uuid.Parse(userID)
	if err != nil {
		return ErrInvalidUser
	}
	return inTx(ctx, pool, map[string]string{"app.user_id": id.String()}, fn)
}

// WithPublicSlug ejecuta fn con permiso de lectura únicamente sobre el enlace compartido de ese slug.
func WithPublicSlug(ctx context.Context, pool *pgxpool.Pool, slug string, fn func(tx pgx.Tx) error) error {
	return inTx(ctx, pool, map[string]string{"app.public_slug": slug}, fn)
}

// WithoutUser ejecuta fn sin cuenta fijada: para lo que ocurre antes de saber quién es la persona
// (registro, login, refresh, límites). Las tablas con RLS no devuelven filas en este contexto.
func WithoutUser(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	return inTx(ctx, pool, nil, fn)
}

func inTx(ctx context.Context, pool *pgxpool.Pool, settings map[string]string, fn func(tx pgx.Tx) error) (err error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("database: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	for k, v := range settings {
		if _, err = tx.Exec(ctx, "SELECT set_config($1, $2, true)", k, v); err != nil {
			return fmt.Errorf("database: set %s: %w", k, err)
		}
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit: %w", err)
	}
	return nil
}
