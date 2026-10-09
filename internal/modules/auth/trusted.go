package auth

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

// T3/S6: tope de dispositivos de confianza vigentes por cuenta.
const maxTrustedDevices = 10

// trustedSealedRe es la forma que admite la migración 00011 (`a1.<iv>.<ct>`).
var trustedSealedRe = regexp.MustCompile(`^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// ListTrustedDevices devuelve solo los dispositivos vigentes de la cuenta (RLS).
func (s *Service) ListTrustedDevices(ctx context.Context, p Principal) ([]TrustedDevice, error) {
	out := []TrustedDevice{}
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name, platform, created_at, last_used_at
			FROM trusted_devices WHERE revoked_at IS NULL ORDER BY last_used_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d TrustedDevice
			if err := rows.Scan(&d.ID, &d.Name, &d.Platform, &d.CreatedAt, &d.LastUsedAt); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return out, nil
}

// AddTrustedDevice da de alta un dispositivo de confianza. Exige Google vinculado (T1) y el tope de
// 10 vigentes (S6). Un `id` que ya existe (de esta u otra cuenta) es un 422 sin detalles.
func (s *Service) AddTrustedDevice(ctx context.Context, p Principal, req *TrustedDeviceInput) error {
	if fields := validateTrustedDevice(req); len(fields) > 0 {
		return apperrors.Validation(fields)
	}
	var failure error
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		var hasGoogle bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identities WHERE user_id = $1 AND provider = 'google')`, p.UserID).Scan(&hasGoogle); err != nil {
			return err
		}
		if !hasGoogle {
			failure = apperrors.Forbidden("google-not-linked")
			return nil
		}
		var vigentes int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM trusted_devices WHERE revoked_at IS NULL`).Scan(&vigentes); err != nil {
			return err
		}
		if vigentes >= maxTrustedDevices {
			failure = apperrors.Forbidden("limit-reached")
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO trusted_devices (id, user_id, name, platform, wrapped_master_key)
			VALUES ($1, $2, $3, $4, $5)`,
			req.ID, p.UserID, strings.TrimSpace(req.Name), req.Platform, req.WrappedMasterKey)
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, p.UserID, "trusted-device-add")
	})
	if isUniqueViolation(err) {
		// Un id que ya existe (de esta u otra cuenta): 422 sin detalles. El error aborta la
		// transacción, así que la clave primaria global hace el trabajo de detección.
		return apperrors.Validation(map[string]string{"id": "invalid-payload"})
	}
	if err != nil {
		return apperrors.Internal(err)
	}
	return failure
}

// GetTrustedDevice entrega la clave maestra cifrada de un dispositivo vigente de la cuenta y marca su
// uso. Cualquier otro id (ajeno, revocado o inexistente) da el mismo 404 (RLS).
func (s *Service) GetTrustedDevice(ctx context.Context, p Principal, id string) (string, error) {
	if !validUUID(id) {
		return "", apperrors.NotFound("trusted-device")
	}
	var (
		wrapped string
		found   bool
	)
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE trusted_devices SET last_used_at = $2
			WHERE id = $1 AND revoked_at IS NULL RETURNING wrapped_master_key`, id, s.Now()).Scan(&wrapped)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return s.audit(ctx, tx, p.UserID, "trusted-device-use")
	})
	if err != nil {
		return "", apperrors.Internal(err)
	}
	if !found {
		return "", apperrors.NotFound("trusted-device")
	}
	return wrapped, nil
}

// RevokeTrustedDevice marca un dispositivo de la cuenta como revocado. Un id ajeno, revocado o
// inexistente da el mismo 404.
func (s *Service) RevokeTrustedDevice(ctx context.Context, p Principal, id string) error {
	if !validUUID(id) {
		return apperrors.NotFound("trusted-device")
	}
	var found bool
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE trusted_devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, s.Now())
		if err != nil {
			return err
		}
		found = tag.RowsAffected() == 1
		if !found {
			return nil
		}
		return s.audit(ctx, tx, p.UserID, "trusted-device-revoke")
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if !found {
		return apperrors.NotFound("trusted-device")
	}
	return nil
}

// revokeTrustedDevices revoca todos los dispositivos de confianza de la cuenta. tx debe tener la
// cuenta fijada (database.SetUser). Se llama al cambiar o restablecer la contraseña y al desvincular
// Google: el dispositivo actual vuelve a darse de alta con la contraseña.
func (s *Service) revokeTrustedDevices(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `UPDATE trusted_devices SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, s.Now())
	return err
}

// validateTrustedDevice comprueba la forma del alta (el servidor no puede comprobar nada más).
func validateTrustedDevice(req *TrustedDeviceInput) map[string]string {
	f := map[string]string{}
	if !validUUID(req.ID) {
		f["id"] = "invalid-payload"
	}
	name := strings.TrimSpace(req.Name)
	if len(name) == 0 || len([]rune(name)) > 100 {
		f["name"] = "invalid-payload"
	}
	if !platforms[req.Platform] {
		f["platform"] = "invalid-payload"
	}
	if len(req.WrappedMasterKey) > maxSealedLen || !trustedSealedRe.MatchString(req.WrappedMasterKey) {
		f["wrappedMasterKey"] = "invalid-payload"
	}
	return f
}
