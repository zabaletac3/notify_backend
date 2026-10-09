package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type userRow struct {
	ID               string
	Email            string
	FullName         string
	VerifiedAt       *time.Time
	CreatedAt        time.Time
	DeletedAt        *time.Time
	AuthKeyHash      []byte
	RecoveryAuthHash []byte
	Kdf              KdfParams
	WrappedMK        string
	RecoveryMK       string
	KeysVersion      int
	HasGoogle        bool
}

func (u *userRow) view() User {
	return User{ID: u.ID, Email: u.Email, FullName: u.FullName, EmailVerified: u.VerifiedAt != nil, CreatedAt: u.CreatedAt, HasGoogle: u.HasGoogle}
}

func (u *userRow) keys() *KeyBundle {
	return &KeyBundle{Kdf: u.Kdf, WrappedMasterKey: u.WrappedMK, RecoveryWrappedMasterKey: u.RecoveryMK, KeysVersion: u.KeysVersion}
}

// userCols se usa siempre contra la tabla `users` (sin alias): el EXISTS de la última columna liga la
// identidad de Google a esa fila. `user_identities` no tiene RLS, así que funciona también sin cuenta
// fijada.
const userCols = `id::text, email, full_name, email_verified_at, created_at, deleted_at, auth_key_hash, recovery_auth_hash, kdf, keys, keys_version,
	EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = users.id AND ui.provider = 'google')`

func scanUser(row pgx.Row) (*userRow, error) {
	var (
		u         userRow
		kdf, keys []byte
	)
	err := row.Scan(&u.ID, &u.Email, &u.FullName, &u.VerifiedAt, &u.CreatedAt, &u.DeletedAt, &u.AuthKeyHash, &u.RecoveryAuthHash, &kdf, &keys, &u.KeysVersion, &u.HasGoogle)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(kdf, &u.Kdf); err != nil {
		return nil, err
	}
	var k struct {
		WrappedMasterKey         string `json:"wrappedMasterKey"`
		RecoveryWrappedMasterKey string `json:"recoveryWrappedMasterKey"`
	}
	if err := json.Unmarshal(keys, &k); err != nil {
		return nil, err
	}
	u.WrappedMK, u.RecoveryMK = k.WrappedMasterKey, k.RecoveryWrappedMasterKey
	return &u, nil
}

func userByEmail(ctx context.Context, tx pgx.Tx, email string, forUpdate bool) (*userRow, error) {
	q := `SELECT ` + userCols + ` FROM users WHERE email = $1`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	return scanUser(tx.QueryRow(ctx, q, email))
}

func userByID(ctx context.Context, tx pgx.Tx, id string) (*userRow, error) {
	return scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}
