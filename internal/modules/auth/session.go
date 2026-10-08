package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

var refreshRule = ratelimit.Rule{Max: 60, Window: time.Minute, Block: 5 * time.Minute}

// Refresh intercambia un token de renovación por un par nuevo (rotación). Reusar un token ya
// gastado indica robo: se revoca toda la familia de esa sesión.
func (s *Service) Refresh(ctx context.Context, ip, token string) (*Session, error) {
	if len(token) < 20 || len(token) > 200 {
		return nil, apperrors.SessionExpired()
	}
	if err := s.take(ctx, s.Limiter.Key("refresh", ip), refreshRule); err != nil {
		return nil, err
	}
	var (
		sess    *Session
		failure error
	)
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		var (
			id, userID, deviceID, familyID string
			expires                        time.Time
			used, revoked                  *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT id::text, user_id::text, device_id::text, family_id::text, expires_at, used_at, revoked_at
			FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, security.HashToken(token)).
			Scan(&id, &userID, &deviceID, &familyID, &expires, &used, &revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			failure = apperrors.SessionExpired()
			return nil
		}
		if err != nil {
			return err
		}
		now := s.Now()
		if revoked != nil || !expires.After(now) {
			failure = apperrors.SessionExpired()
			return nil
		}
		if used != nil {
			// Reutilización: quien lo presenta no es quien lo recibió. Se cierra toda la sesión.
			failure = apperrors.SessionExpired()
			if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, familyID, now); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, deviceID, now); err != nil {
				return err
			}
			return s.audit(ctx, tx, userID, "refresh-reuse")
		}
		if err = database.SetUser(ctx, tx, userID); err != nil {
			return err
		}
		var devRevoked *time.Time
		err = tx.QueryRow(ctx, `SELECT revoked_at FROM devices WHERE id = $1`, deviceID).Scan(&devRevoked)
		if errors.Is(err, pgx.ErrNoRows) {
			failure = apperrors.SessionExpired()
			return nil
		}
		if err != nil {
			return err
		}
		if devRevoked != nil {
			failure = apperrors.DeviceRevoked()
			return nil
		}
		u, err := userByID(ctx, tx, userID)
		if err != nil {
			return err
		}
		if u == nil || u.DeletedAt != nil || u.VerifiedAt == nil {
			failure = apperrors.SessionExpired()
			return nil
		}
		if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE id = $1`, id, now); err != nil {
			return err
		}
		next, err := s.insertRefresh(ctx, tx, userID, deviceID, familyID)
		if err != nil {
			return err
		}
		access, exp, err := s.Signer.Issue(userID, deviceID)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE devices SET last_seen_at = $2 WHERE id = $1`, deviceID, now); err != nil {
			return err
		}
		sess = &Session{User: u.view(), ExpiresAt: exp, AccessToken: access, RefreshToken: next}
		return nil
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	return sess, nil
}

func (s *Service) audit(ctx context.Context, tx pgx.Tx, userID, event string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_log (user_id, event, at) VALUES ($1, $2, $3)`, userID, event, s.Now())
	return err
}

// Authenticate valida el token de acceso y que el dispositivo siga vigente. Es lo que usa el
// middleware en cada petición protegida.
func (s *Service) Authenticate(ctx context.Context, token string) (Principal, error) {
	claims, err := s.Signer.Parse(token)
	if err != nil {
		return Principal{}, apperrors.SessionExpired()
	}
	var (
		revoked    *time.Time
		lastSeen   time.Time
		userGone   bool
		deviceSeen bool
	)
	err = database.WithUser(ctx, s.Pool, claims.UserID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT d.revoked_at, d.last_seen_at, (u.deleted_at IS NOT NULL OR u.email_verified_at IS NULL)
			FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1`, claims.DeviceID).Scan(&revoked, &lastSeen, &userGone)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		deviceSeen = true
		if revoked == nil && s.Now().Sub(lastSeen) > time.Minute {
			_, err = tx.Exec(ctx, `UPDATE devices SET last_seen_at = $2 WHERE id = $1`, claims.DeviceID, s.Now())
		}
		return err
	})
	if err != nil {
		return Principal{}, apperrors.Unavailable(err)
	}
	switch {
	case !deviceSeen || userGone:
		return Principal{}, apperrors.SessionExpired()
	case revoked != nil:
		return Principal{}, apperrors.DeviceRevoked()
	}
	return Principal{UserID: claims.UserID, DeviceID: claims.DeviceID, Expires: claims.ExpiresAt}, nil
}

// CurrentSession devuelve la sesión vigente (sin tokens).
func (s *Service) CurrentSession(ctx context.Context, p Principal) (*Session, error) {
	var u *userRow
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) (err error) {
		u, err = userByID(ctx, tx, p.UserID)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if u == nil {
		return nil, apperrors.SessionExpired()
	}
	return &Session{User: u.view(), ExpiresAt: p.Expires}, nil
}

// Logout cierra la sesión de este dispositivo: revoca el dispositivo y sus tokens de renovación.
func (s *Service) Logout(ctx context.Context, p Principal) error {
	return s.revokeDevice(ctx, p.UserID, p.DeviceID)
}

// LogoutByRefreshToken cierra la sesión a la que pertenece un token de renovación (modo cookie en
// `POST /auth/logout`, que debe funcionar aunque el token de acceso haya vencido). Es idempotente:
// un token ausente, inválido, gastado o ya revocado no es un error ni revela nada.
func (s *Service) LogoutByRefreshToken(ctx context.Context, token string) error {
	if len(token) < 20 || len(token) > 200 {
		return nil
	}
	var (
		userID, deviceID string
		found            bool
	)
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT user_id::text, device_id::text FROM refresh_tokens WHERE token_hash = $1`,
			security.HashToken(token)).Scan(&userID, &deviceID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if !found {
		return nil
	}
	return s.revokeDevice(ctx, userID, deviceID)
}

func (s *Service) revokeDevice(ctx context.Context, userID, deviceID string) error {
	err := database.WithUser(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		now := s.Now()
		if _, err := tx.Exec(ctx, `UPDATE devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, deviceID, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE device_id = $1 AND revoked_at IS NULL`, deviceID, now)
		return err
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	return nil
}

// ListDevices devuelve los dispositivos con sesión activa.
func (s *Service) ListDevices(ctx context.Context, p Principal) ([]Device, error) {
	out := []Device{}
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name, platform, last_seen_at FROM devices WHERE revoked_at IS NULL ORDER BY last_seen_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			if err := rows.Scan(&d.ID, &d.Name, &d.Platform, &d.LastActiveAt); err != nil {
				return err
			}
			d.Current = d.ID == p.DeviceID
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return out, nil
}

// RemoveDevice cierra la sesión de otro dispositivo de la misma cuenta.
func (s *Service) RemoveDevice(ctx context.Context, p Principal, deviceID string) error {
	if !validUUID(deviceID) {
		return apperrors.NotFound("device")
	}
	if deviceID == p.DeviceID {
		return apperrors.Validation(map[string]string{"device": "invalid-payload"})
	}
	var found bool
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		now := s.Now()
		tag, err := tx.Exec(ctx, `UPDATE devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, deviceID, now)
		if err != nil {
			return err
		}
		found = tag.RowsAffected() == 1
		if !found {
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE device_id = $1 AND revoked_at IS NULL`, deviceID, now)
		return err
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if !found {
		return apperrors.NotFound("device")
	}
	return nil
}
