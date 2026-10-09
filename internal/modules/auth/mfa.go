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

const (
	ticketMFALogin = "mfa-login"
	mfaTicketTTL   = 5 * time.Minute
)

// Intentos de segundo paso por cuenta, sea cual sea la IP: 10^6 códigos no se adivinan repartiendo el
// ataque. La regla por IP de la regla de login cubre el resto.
var (
	mfaAccountRule = ratelimit.Rule{Max: 5, Window: 10 * time.Minute, Block: 15 * time.Minute}
	mfaIPRule      = ratelimit.LoginByIP
)

// mfaTicketPayload es lo único que guarda el ticket `mfa-login`: el dispositivo y el primer factor.
type mfaTicketPayload struct {
	Device DeviceInfo `json:"device"`
	Method string     `json:"method"`
}

// mfaEnabled es la fuente única de verdad de «MFA activo». tx debe tener la cuenta fijada (RLS).
func mfaEnabled(ctx context.Context, tx pgx.Tx, userID string) (bool, error) {
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_totp WHERE user_id = $1 AND enabled_at IS NOT NULL)`, userID).Scan(&enabled)
	return enabled, err
}

// MFAStatus devuelve el estado del segundo factor de la cuenta.
func (s *Service) MFAStatus(ctx context.Context, p Principal) (*MFAStatus, error) {
	out := &MFAStatus{}
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		var enabledAt *time.Time
		err := tx.QueryRow(ctx, `SELECT enabled_at FROM user_totp WHERE user_id = $1`, p.UserID).Scan(&enabledAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.Enabled = enabledAt != nil
		out.EnabledAt = enabledAt
		return tx.QueryRow(ctx, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, p.UserID).Scan(&out.RecoveryCodesLeft)
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return out, nil
}

// SetupTOTP genera un secreto TOTP pendiente de confirmar. Exige la prueba de la contraseña con el
// mismo límite que las demás operaciones sensibles. Un segundo setup sustituye el pendiente.
func (s *Service) SetupTOTP(ctx context.Context, p Principal, authKey string) (*MfaSetupResult, error) {
	if !security.ValidAuthKey(authKey) {
		return nil, apperrors.Validation(map[string]string{"password": "required"})
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.proveAuthKey(ctx, u, authKey, "password"); err != nil {
		return nil, err
	}
	raw, b32, err := security.NewTOTPSecret()
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	sealed, err := security.SealTOTP(s.Config.Pepper, p.UserID, raw)
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	var alreadyEnabled bool
	err = database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO user_totp (user_id, secret_enc) VALUES ($1, $2)
			ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, enabled_at = NULL, last_step = 0, created_at = now()
			WHERE user_totp.enabled_at IS NULL`, p.UserID, sealed)
		if err != nil {
			return err
		}
		alreadyEnabled = tag.RowsAffected() == 0
		return nil
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if alreadyEnabled {
		return nil, apperrors.Conflict("mfa-already-enabled")
	}
	return &MfaSetupResult{Secret: b32, OTPAuthURI: security.OTPAuthURI("AxoNote", u.Email, b32)}, nil
}

// EnableTOTP confirma un código TOTP contra el secreto pendiente, activa el MFA, genera los 10 códigos
// de respaldo (se devuelven en claro **una sola vez**) y cierra las demás sesiones (S3).
func (s *Service) EnableTOTP(ctx context.Context, p Principal, code string) (*MfaRecoveryCodes, error) {
	if err := s.take(ctx, s.Limiter.Key("mfa", p.UserID), mfaAccountRule); err != nil {
		return nil, err
	}
	var (
		codes      []string
		email      string
		notPending bool
		already    bool
		badCode    bool
	)
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		var (
			secretEnc string
			enabledAt *time.Time
			lastStep  int64
		)
		err := tx.QueryRow(ctx, `SELECT secret_enc, enabled_at, last_step FROM user_totp WHERE user_id = $1 FOR UPDATE`, p.UserID).
			Scan(&secretEnc, &enabledAt, &lastStep)
		if errors.Is(err, pgx.ErrNoRows) {
			notPending = true
			return nil
		}
		if err != nil {
			return err
		}
		if enabledAt != nil {
			already = true
			return nil
		}
		secret, err := security.OpenTOTP(s.Config.Pepper, p.UserID, secretEnc)
		if err != nil {
			return err
		}
		step, ok := security.VerifyTOTP(secret, strings.TrimSpace(code), s.Now(), lastStep)
		if !ok {
			badCode = true
			return nil
		}
		if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, p.UserID).Scan(&email); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE user_totp SET enabled_at = $2, last_step = $3 WHERE user_id = $1`, p.UserID, s.Now(), step); err != nil {
			return err
		}
		if codes, err = s.replaceRecoveryCodes(ctx, tx, p.UserID); err != nil {
			return err
		}
		if err := s.revokeSessions(ctx, tx, p.UserID, p.DeviceID); err != nil { // S3: cerrar las demás sesiones
			return err
		}
		return s.audit(ctx, tx, p.UserID, "mfa-enable")
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	switch {
	case notPending:
		return nil, apperrors.Conflict("mfa-not-pending")
	case already:
		return nil, apperrors.Conflict("mfa-already-enabled")
	case badCode:
		return nil, apperrors.Validation(map[string]string{"code": "invalid-code"})
	}
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("mfa", p.UserID))
	s.send(mfaEnabledMail(email))
	return &MfaRecoveryCodes{RecoveryCodes: codes}, nil
}

// DisableTOTP desactiva el segundo factor: exige la prueba de la contraseña **y** un código vigente.
func (s *Service) DisableTOTP(ctx context.Context, p Principal, authKey, code string) error {
	if !security.ValidAuthKey(authKey) {
		return apperrors.Validation(map[string]string{"password": "required"})
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if err := s.proveAuthKey(ctx, u, authKey, "password"); err != nil {
		return err
	}
	return s.removeMFA(ctx, p.UserID, code, "mfa-disable", func() { s.send(mfaDisabledMail(u.Email)) })
}

// RegenerateRecoveryCodes sustituye los 10 códigos de respaldo. Exige la prueba de la contraseña **y**
// un código vigente.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, p Principal, authKey, code string) (*MfaRecoveryCodes, error) {
	if !security.ValidAuthKey(authKey) {
		return nil, apperrors.Validation(map[string]string{"password": "required"})
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.proveAuthKey(ctx, u, authKey, "password"); err != nil {
		return nil, err
	}
	if err := s.take(ctx, s.Limiter.Key("mfa", p.UserID), mfaAccountRule); err != nil {
		return nil, err
	}
	var (
		codes      []string
		notEnabled bool
		badCode    bool
	)
	err = database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		enabled, err := mfaEnabled(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if !enabled {
			notEnabled = true
			return nil
		}
		ok, err := s.verifySecondFactor(ctx, tx, p.UserID, code)
		if err != nil {
			return err
		}
		if !ok {
			badCode = true
			return nil
		}
		if codes, err = s.replaceRecoveryCodes(ctx, tx, p.UserID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p.UserID, "mfa-recovery-codes")
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if notEnabled {
		return nil, apperrors.Conflict("mfa-not-enabled")
	}
	if badCode {
		return nil, apperrors.Validation(map[string]string{"code": "invalid-code"})
	}
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("mfa", p.UserID))
	return &MfaRecoveryCodes{RecoveryCodes: codes}, nil
}

// removeMFA borra el segundo factor tras verificar el código. onSuccess se ejecuta fuera de la
// transacción (para enviar el correo).
func (s *Service) removeMFA(ctx context.Context, userID, code, event string, onSuccess func()) error {
	if err := s.take(ctx, s.Limiter.Key("mfa", userID), mfaAccountRule); err != nil {
		return err
	}
	var (
		notEnabled bool
		badCode    bool
	)
	err := database.WithUser(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		enabled, err := mfaEnabled(ctx, tx, userID)
		if err != nil {
			return err
		}
		if !enabled {
			notEnabled = true
			return nil
		}
		ok, err := s.verifySecondFactor(ctx, tx, userID, code)
		if err != nil {
			return err
		}
		if !ok {
			badCode = true
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		return s.audit(ctx, tx, userID, event)
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if notEnabled {
		return apperrors.Conflict("mfa-not-enabled")
	}
	if badCode {
		return apperrors.Validation(map[string]string{"code": "invalid-code"})
	}
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("mfa", userID))
	if onSuccess != nil {
		onSuccess()
	}
	return nil
}

// verifySecondFactor comprueba un código TOTP o de respaldo dentro de la transacción que aplica el
// efecto. Un código de 6 dígitos actualiza `last_step` (anti-reutilización); un código de respaldo se
// marca como usado. Devuelve false (sin error) si el código no vale.
func (s *Service) verifySecondFactor(ctx context.Context, tx pgx.Tx, userID, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if codeRe.MatchString(code) {
		var (
			secretEnc string
			lastStep  int64
		)
		err := tx.QueryRow(ctx, `SELECT secret_enc, last_step FROM user_totp WHERE user_id = $1 AND enabled_at IS NOT NULL FOR UPDATE`, userID).
			Scan(&secretEnc, &lastStep)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret, err := security.OpenTOTP(s.Config.Pepper, userID, secretEnc)
		if err != nil {
			return false, err
		}
		step, ok := security.VerifyTOTP(secret, code, s.Now(), lastStep)
		if !ok {
			return false, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE user_totp SET last_step = $2 WHERE user_id = $1`, userID, step); err != nil {
			return false, err
		}
		return true, nil
	}
	norm, ok := security.NormalizeRecoveryCode(code)
	if !ok {
		return false, nil
	}
	hash := security.HashCode(s.Config.Pepper, "mfa-recovery", userID, norm)
	var (
		id   string
		used *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT id::text, used_at FROM mfa_recovery_codes WHERE user_id = $1 AND code_hash = $2 FOR UPDATE`, userID, hash).
		Scan(&id, &used)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if used != nil {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at = $2 WHERE id = $1`, id, s.Now()); err != nil {
		return false, err
	}
	return true, nil
}

// replaceRecoveryCodes sustituye los 10 códigos por otros nuevos y devuelve los nuevos en claro.
func (s *Service) replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return nil, err
	}
	codes, err := security.NewRecoveryCodes(10)
	if err != nil {
		return nil, err
	}
	for _, c := range codes {
		norm, ok := security.NormalizeRecoveryCode(c)
		if !ok {
			return nil, errors.New("auth: código de respaldo mal formado")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, security.HashCode(s.Config.Pepper, "mfa-recovery", userID, norm)); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// LoginMFA completa un login que devolvió un reto. El ticket es de un solo uso y el intento se confirma
// aunque el código sea erróneo (para que cuente).
func (s *Service) LoginMFA(ctx context.Context, ip, mfaToken, code string) (*Session, error) {
	if err := s.take(ctx, s.Limiter.Key("mfa-ip", ip), mfaIPRule); err != nil {
		return nil, err
	}
	code = strings.TrimSpace(code)
	if !validSecondFactorShape(code) {
		return nil, apperrors.Validation(map[string]string{"code": "invalid-code"})
	}
	var (
		sess    *Session
		userID  string
		failure error
	)
	invalidToken := apperrors.Validation(map[string]string{"mfaToken": "invalid-token"})
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, ticketMFALogin, mfaToken)
		if err != nil {
			return err
		}
		if tk == nil || tk.UserID == nil {
			failure = invalidToken
			return nil
		}
		userID = *tk.UserID
		if err := s.blocked(ctx, s.Limiter.Key("mfa", userID)); err != nil {
			failure = err
			return nil
		}
		if err := database.SetUser(ctx, tx, userID); err != nil {
			return err
		}
		u, err := userByID(ctx, tx, userID)
		if err != nil {
			return err
		}
		if u == nil || u.DeletedAt != nil || u.VerifiedAt == nil {
			failure = invalidToken
			return nil
		}
		ok, err := s.verifySecondFactor(ctx, tx, userID, code)
		if err != nil {
			return err
		}
		if !ok {
			if err := s.bumpTicket(ctx, tx, tk.ID); err != nil {
				return err
			}
			for _, k := range []struct {
				key  string
				rule ratelimit.Rule
			}{{s.Limiter.Key("mfa", userID), mfaAccountRule}, {s.Limiter.Key("mfa-ip", ip), mfaIPRule}} {
				if _, err := s.Limiter.Fail(ctx, k.key, k.rule); err != nil {
					failure = apperrors.Unavailable(err)
					return nil
				}
			}
			if err := s.audit(ctx, tx, userID, "mfa-fail"); err != nil {
				return err
			}
			failure = apperrors.Validation(map[string]string{"code": "invalid-code"})
			return nil // se confirma para que el intento cuente
		}
		if err := s.consumeTicket(ctx, tx, tk.ID); err != nil {
			return err
		}
		var payload mfaTicketPayload
		if len(tk.Payload) > 0 {
			if err := json.Unmarshal(tk.Payload, &payload); err != nil {
				return err
			}
		}
		sess, err = s.newSession(ctx, tx, u, cleanDevice(&payload.Device), true)
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, userID, "login-mfa")
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("mfa", userID))
	_ = s.Limiter.Reset(ctx, s.Limiter.Key("mfa-ip", ip))
	return sess, nil
}

// validSecondFactorShape acepta un TOTP de 6 dígitos o un código de respaldo bien formado.
func validSecondFactorShape(code string) bool {
	if codeRe.MatchString(code) {
		return true
	}
	_, ok := security.NormalizeRecoveryCode(code)
	return ok
}
