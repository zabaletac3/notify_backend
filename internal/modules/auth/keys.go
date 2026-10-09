package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

const accountDeletionDays = 30

// Cuenta como un fallo cada prueba de contraseña errónea en operaciones sensibles de una sesión abierta.
var sensitiveRule = ratelimit.LoginByAccount

// Keys devuelve el paquete de claves cifradas de la cuenta (no sirve sin la contraseña).
func (s *Service) Keys(ctx context.Context, p Principal) (*KeyBundle, error) {
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
	return u.keys(), nil
}

// proveAuthKey comprueba la prueba de contraseña de una sesión abierta con límite de fallos.
// Devuelve (nil) si es correcta; si no, un error de validación en el campo indicado.
func (s *Service) proveAuthKey(ctx context.Context, u *userRow, authKey, field string) error {
	key := s.Limiter.Key("sensitive", u.ID)
	if err := s.blocked(ctx, key); err != nil {
		return err
	}
	ok, _ := s.Hasher.Verify(u.AuthKeyHash, authKey)
	if ok {
		return nil
	}
	if _, err := s.Limiter.Fail(ctx, key, sensitiveRule); err != nil {
		return apperrors.Unavailable(err)
	}
	return apperrors.Validation(map[string]string{field: "wrong-password"})
}

// ChangePassword cambia la contraseña: la clave maestra no cambia, solo se vuelve a envolver con la
// clave derivada de la contraseña nueva. Cierra las demás sesiones.
func (s *Service) ChangePassword(ctx context.Context, p Principal, req *PasswordChangeRequest) error {
	fields := map[string]string{}
	if !security.ValidAuthKey(req.CurrentAuthKey) {
		fields["currentPassword"] = "required"
	}
	if !security.ValidAuthKey(req.NewAuthKey) {
		fields["newPassword"] = "required"
	} else if req.NewAuthKey == req.CurrentAuthKey {
		fields["newPassword"] = "same-password"
	}
	if code := validateKeys(&req.Keys); code != "" {
		fields["keys"] = code
	}
	if len(fields) > 0 {
		return apperrors.Validation(fields)
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if err := s.proveAuthKey(ctx, u, req.CurrentAuthKey, "currentPassword"); err != nil {
		return err
	}
	newHash, err := s.Hasher.Hash(req.NewAuthKey)
	if err != nil {
		return apperrors.Internal(err)
	}
	kdf, _ := json.Marshal(req.Keys.Kdf)
	// La clave de recuperación no la decide el cliente aquí: se conserva la guardada.
	keys, _ := json.Marshal(map[string]string{"wrappedMasterKey": req.Keys.WrappedMasterKey, "recoveryWrappedMasterKey": u.RecoveryMK})

	err = database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET auth_key_hash = $2, kdf = $3, keys = $4, keys_version = keys_version + 1 WHERE id = $1`,
			p.UserID, newHash, kdf, keys); err != nil {
			return err
		}
		if err := s.revokeSessions(ctx, tx, p.UserID, p.DeviceID); err != nil {
			return err
		}
		if err := s.revokeTrustedDevices(ctx, tx, p.UserID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p.UserID, "password-change")
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("sensitive", u.ID))
	s.send(passwordChangedMail(u.Email))
	return nil
}

// RotateRecoveryKey cambia la clave de recuperación; la anterior deja de servir.
func (s *Service) RotateRecoveryKey(ctx context.Context, p Principal, req *RecoveryKeyRotation) error {
	fields := map[string]string{}
	if !security.ValidAuthKey(req.AuthKey) {
		fields["password"] = "required"
	}
	if !security.ValidAuthKey(req.RecoveryAuth) || req.RecoveryAuth == req.AuthKey {
		fields["recoveryAuth"] = "invalid-payload"
	}
	if len(req.RecoveryWrappedMasterKey) > maxSealedLen || !sealedRe.MatchString(req.RecoveryWrappedMasterKey) {
		fields["recoveryWrappedMasterKey"] = "invalid-payload"
	}
	if len(fields) > 0 {
		return apperrors.Validation(fields)
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if err := s.proveAuthKey(ctx, u, req.AuthKey, "password"); err != nil {
		return err
	}
	recHash, err := s.Hasher.Hash(req.RecoveryAuth)
	if err != nil {
		return apperrors.Internal(err)
	}
	keys, _ := json.Marshal(map[string]string{"wrappedMasterKey": u.WrappedMK, "recoveryWrappedMasterKey": req.RecoveryWrappedMasterKey})
	err = database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET recovery_auth_hash = $2, keys = $3, keys_version = keys_version + 1 WHERE id = $1`,
			p.UserID, recHash, keys); err != nil {
			return err
		}
		return s.audit(ctx, tx, p.UserID, "recovery-key-rotate")
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("sensitive", u.ID))
	return nil
}

// DeleteAccount programa la eliminación tras comprobar la prueba de la contraseña. Mismo error y
// mismo límite `sensitive` que las demás operaciones que exigen la contraseña.
func (s *Service) DeleteAccount(ctx context.Context, p Principal, req *DeleteAccountRequest) error {
	if !security.ValidAuthKey(req.AuthKey) {
		return apperrors.Validation(map[string]string{"password": "required"})
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if err := s.proveAuthKey(ctx, u, req.AuthKey, "password"); err != nil {
		return err
	}
	return s.deleteAccount(ctx, p)
}

// DeleteAccountLegacy atiende DELETE /me sin prueba de contraseña; se elimina junto con esa ruta
// al cumplirse el Sunset (ver legacyDeleteSunset).
func (s *Service) DeleteAccountLegacy(ctx context.Context, p Principal) error {
	return s.deleteAccount(ctx, p)
}

// deleteAccount programa la eliminación: se marca la cuenta, se cierran todas las sesiones y los datos
// se conservan 30 días (la purga los borra). Restablecer la contraseña dentro del plazo la recupera.
func (s *Service) deleteAccount(ctx context.Context, p Principal) error {
	var email string
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE users SET deleted_at = $2 WHERE id = $1 RETURNING email`, p.UserID, s.Now()).Scan(&email); err != nil {
			return err
		}
		if err := s.revokeSessions(ctx, tx, p.UserID, ""); err != nil {
			return err
		}
		return s.audit(ctx, tx, p.UserID, "account-delete")
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	s.send(accountDeletedMail(email, accountDeletionDays))
	return nil
}

// loadUser lee la cuenta del principal; si ya no existe o fue eliminada, la sesión no es válida.
func (s *Service) loadUser(ctx context.Context, userID string) (*userRow, error) {
	var u *userRow
	err := database.WithUser(ctx, s.Pool, userID, func(tx pgx.Tx) (err error) {
		u, err = userByID(ctx, tx, userID)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if u == nil || u.DeletedAt != nil {
		return nil, apperrors.SessionExpired()
	}
	return u, nil
}

// revokeSessions cierra todas las sesiones de la cuenta salvo la de `keepDevice` (vacío = todas).
// tx debe tener la cuenta fijada.
func (s *Service) revokeSessions(ctx context.Context, tx pgx.Tx, userID, keepDevice string) error {
	now := s.Now()
	if _, err := tx.Exec(ctx, `UPDATE devices SET revoked_at = $2 WHERE revoked_at IS NULL AND ($1 = '' OR id::text <> $1)`, keepDevice, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $3 WHERE user_id = $1 AND revoked_at IS NULL AND ($2 = '' OR device_id::text <> $2)`, userID, keepDevice, now)
	return err
}

var errInvalidToken = apperrors.Validation(map[string]string{"token": "invalid-token"})

const resetTTL = time.Hour

var resetAttemptRule = ratelimit.Rule{Max: 20, Window: 15 * time.Minute, Block: 15 * time.Minute}

// ForgotPassword envía el enlace de recuperación. Siempre responde igual.
func (s *Service) ForgotPassword(ctx context.Context, ip, email string) error {
	email = security.NormalizeEmail(email)
	if !validEmail(email) {
		return apperrors.Validation(map[string]string{"email": "invalid-email"})
	}
	if err := s.take(ctx, s.Limiter.Key("forgot", email, ip), ratelimit.CodeResend); err != nil {
		return err
	}
	if err := s.take(ctx, s.Limiter.Key("forgot-ip", ip), ratelimit.LoginByIP); err != nil {
		return err
	}
	token, err := security.RandomToken(32)
	if err != nil {
		return apperrors.Internal(err)
	}
	now := s.Now()
	sent := false
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		u, err := userByEmail(ctx, tx, email, true)
		if err != nil || u == nil || u.VerifiedAt == nil {
			return err
		}
		var last time.Time
		err = tx.QueryRow(ctx, `SELECT created_at FROM verification_codes WHERE user_id = $1 AND purpose = 'password-reset' AND consumed_at IS NULL`, u.ID).Scan(&last)
		if err == nil && now.Sub(last) < resendMinGap {
			return nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM verification_codes WHERE user_id = $1 AND purpose = 'password-reset' AND consumed_at IS NULL`, u.ID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO verification_codes (user_id, purpose, code_hash, expires_at, created_at) VALUES ($1, 'password-reset', $2, $3, $4)`,
			u.ID, security.HashToken(token), now.Add(resetTTL), now); err != nil {
			return err
		}
		sent = true
		return nil
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if sent {
		s.send(resetMail(email, s.Config.WebBaseURL, token, resetTTL))
	}
	return nil
}

// resetTarget localiza la cuenta de un token de restablecimiento vigente y la bloquea.
func (s *Service) resetTarget(ctx context.Context, tx pgx.Tx, token string) (codeID string, u *userRow, err error) {
	if len(token) < 20 || len(token) > 200 {
		return "", nil, nil
	}
	var userID string
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT id::text, user_id::text, expires_at FROM verification_codes
		WHERE purpose = 'password-reset' AND consumed_at IS NULL AND code_hash = $1 FOR UPDATE`, security.HashToken(token)).
		Scan(&codeID, &userID, &expires)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !expires.After(s.Now())) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	u, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1 FOR UPDATE`, userID))
	return codeID, u, err
}

// ResetBundle entrega, con el token del correo, lo necesario para restablecer conservando las notas.
func (s *Service) ResetBundle(ctx context.Context, ip, token string) (*PasswordResetBundle, error) {
	if err := s.take(ctx, s.Limiter.Key("reset", ip), resetAttemptRule); err != nil {
		return nil, err
	}
	var out *PasswordResetBundle
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		_, u, err := s.resetTarget(ctx, tx, token)
		if err != nil || u == nil {
			return err
		}
		out = &PasswordResetBundle{UserID: u.ID, RecoveryWrappedMasterKey: u.RecoveryMK, Kdf: u.Kdf}
		// user_totp está protegida por RLS: hace falta fijar la cuenta antes de leerla.
		if err := database.SetUser(ctx, tx, u.ID); err != nil {
			return err
		}
		out.MFAEnabled, err = mfaEnabled(ctx, tx, u.ID)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if out == nil {
		return nil, errInvalidToken
	}
	return out, nil
}

// ResetPassword crea una contraseña nueva con el token del correo. keep exige la prueba de la clave
// de recuperación vigente; wipe borra todos los datos de la cuenta. En ambos casos cierra todas las
// sesiones y, si la cuenta estaba en periodo de gracia por eliminación, la recupera.
func (s *Service) ResetPassword(ctx context.Context, ip string, req *PasswordResetRequest) error {
	fields := map[string]string{}
	if req.Mode != "keep" && req.Mode != "wipe" {
		fields["mode"] = "invalid-payload"
	}
	if !security.ValidAuthKey(req.NewAuthKey) {
		fields["newPassword"] = "required"
	}
	if !security.ValidAuthKey(req.RecoveryAuth) {
		fields["recoveryKey"] = "required"
	}
	if code := validateKeys(&req.Keys); code != "" {
		fields["keys"] = code
	}
	if req.Mode == "wipe" && req.DisableMFA {
		fields["disableMfa"] = "invalid-payload"
	}
	if len(fields) > 0 {
		return apperrors.Validation(fields)
	}
	if err := s.take(ctx, s.Limiter.Key("reset", ip), resetAttemptRule); err != nil {
		return err
	}
	newHash, err := s.Hasher.Hash(req.NewAuthKey)
	if err != nil {
		return apperrors.Internal(err)
	}
	var recHash []byte
	if req.Mode == "wipe" {
		if recHash, err = s.Hasher.Hash(req.RecoveryAuth); err != nil {
			return apperrors.Internal(err)
		}
	}
	kdf, _ := json.Marshal(req.Keys.Kdf)

	var (
		failure     error
		email       string
		disabledMFA bool
	)
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		codeID, u, err := s.resetTarget(ctx, tx, req.Token)
		if err != nil {
			return err
		}
		if u == nil {
			failure = errInvalidToken
			return nil
		}
		email = u.Email
		recKey := "reset-recovery:" + u.ID
		if req.Mode == "keep" {
			// Los intentos con una clave de recuperación equivocada se limitan por cuenta.
			if err := s.blocked(ctx, s.Limiter.Key(recKey)); err != nil {
				failure = err
				return nil
			}
			ok := u.RecoveryAuthHash != nil
			if ok {
				ok, _ = s.Hasher.Verify(u.RecoveryAuthHash, req.RecoveryAuth)
			} else {
				s.Hasher.VerifyDummy(req.RecoveryAuth)
			}
			if !ok {
				if _, err := s.Limiter.Fail(ctx, s.Limiter.Key(recKey), ratelimit.Rule{Max: 5, Window: time.Hour, Block: time.Hour}); err != nil {
					failure = apperrors.Unavailable(err)
					return nil
				}
				failure = apperrors.Validation(map[string]string{"recoveryKey": "invalid-recovery-key"})
				return nil
			}
		}
		if err := database.SetUser(ctx, tx, u.ID); err != nil {
			return err
		}
		mfaOn, err := mfaEnabled(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if mfaOn && req.Mode == "wipe" {
			// Borrar las notas sin el segundo factor sería una puerta trasera: exigimos código.
			if strings.TrimSpace(req.MFACode) == "" {
				failure = apperrors.Validation(map[string]string{"mfaCode": "required"})
				return nil
			}
			if err := s.blocked(ctx, s.Limiter.Key("mfa", u.ID)); err != nil {
				failure = err
				return nil
			}
			ok, err := s.verifySecondFactor(ctx, tx, u.ID, req.MFACode)
			if err != nil {
				return err
			}
			if !ok {
				if _, ferr := s.Limiter.Fail(ctx, s.Limiter.Key("mfa", u.ID), mfaAccountRule); ferr != nil {
					failure = apperrors.Unavailable(ferr)
					return nil
				}
				failure = apperrors.Validation(map[string]string{"mfaCode": "invalid-code"})
				return nil
			}
		}
		if req.Mode == "keep" && req.DisableMFA && mfaOn {
			if _, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, u.ID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, u.ID); err != nil {
				return err
			}
			if err := s.audit(ctx, tx, u.ID, "mfa-disable-recovery"); err != nil {
				return err
			}
			disabledMFA = true
		}
		now := s.Now()
		if req.Mode == "keep" {
			keys, _ := json.Marshal(map[string]string{"wrappedMasterKey": req.Keys.WrappedMasterKey, "recoveryWrappedMasterKey": u.RecoveryMK})
			_, err = tx.Exec(ctx, `UPDATE users SET auth_key_hash = $2, kdf = $3, keys = $4, keys_version = keys_version + 1, deleted_at = NULL WHERE id = $1`,
				u.ID, newHash, kdf, keys)
		} else {
			// Empezar de cero: lo cifrado con la clave anterior ya no se podría leer.
			for _, q := range []string{`DELETE FROM share_links`, `DELETE FROM notes`, `DELETE FROM folders`, `DELETE FROM tombstones`, `DELETE FROM trusted_devices`} {
				if _, err = tx.Exec(ctx, q); err != nil {
					return err
				}
			}
			keys, _ := json.Marshal(map[string]string{"wrappedMasterKey": req.Keys.WrappedMasterKey, "recoveryWrappedMasterKey": req.Keys.RecoveryWrappedMasterKey})
			_, err = tx.Exec(ctx, `UPDATE users SET auth_key_hash = $2, recovery_auth_hash = $3, kdf = $4, keys = $5, keys_version = keys_version + 1, deleted_at = NULL WHERE id = $1`,
				u.ID, newHash, recHash, kdf, keys)
		}
		if err != nil {
			return err
		}
		if req.Mode == "keep" {
			// La MK no cambia, pero cambiar la contraseña invalida la confianza existente.
			if err = s.revokeTrustedDevices(ctx, tx, u.ID); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE verification_codes SET consumed_at = $2 WHERE id = $1`, codeID, now); err != nil {
			return err
		}
		if err = s.revokeSessions(ctx, tx, u.ID, ""); err != nil {
			return err
		}
		return s.audit(ctx, tx, u.ID, "password-reset-"+req.Mode)
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if failure != nil {
		return failure
	}
	s.send(passwordChangedMailMFA(email, disabledMFA))
	return nil
}
