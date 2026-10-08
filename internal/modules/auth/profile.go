package auth

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

// Me devuelve el perfil de la cuenta actual.
func (s *Service) Me(ctx context.Context, p Principal) (*User, error) {
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	v := u.view()
	return &v, nil
}

// UpdateProfile cambia el nombre visible.
func (s *Service) UpdateProfile(ctx context.Context, p Principal, in *ProfileUpdate) (*User, error) {
	name := trimSpace(in.FullName)
	switch n := utf8.RuneCountInString(name); {
	case n < 2:
		return nil, apperrors.Validation(map[string]string{"fullName": "name-too-short"})
	case n > maxNameLen:
		return nil, apperrors.Validation(map[string]string{"fullName": "name-too-long"})
	}
	var u *userRow
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET full_name = $2 WHERE id = $1 AND deleted_at IS NULL`, p.UserID, name)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		u, err = userByID(ctx, tx, p.UserID)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if u == nil {
		return nil, apperrors.SessionExpired()
	}
	v := u.view()
	return &v, nil
}

var emailChangeRule = ratelimit.Rule{Max: 5, Window: time.Hour, Block: time.Hour}

func emailChangeSubject(userID, newEmail string) string { return userID + ":" + newEmail }

// RequestEmailChange pide cambiar el correo: exige la prueba de la contraseña y envía un código al
// correo nuevo. Si ese correo ya tiene cuenta responde igual (no revela cuentas) y avisa a su dueño.
func (s *Service) RequestEmailChange(ctx context.Context, p Principal, in *EmailChangeRequest) (string, error) {
	newEmail := security.NormalizeEmail(in.NewEmail)
	if !validEmail(newEmail) {
		return "", apperrors.Validation(map[string]string{"newEmail": "invalid-email"})
	}
	if !security.ValidAuthKey(in.AuthKey) {
		return "", apperrors.Validation(map[string]string{"password": "required"})
	}
	u, err := s.loadUser(ctx, p.UserID)
	if err != nil {
		return "", err
	}
	if newEmail == u.Email {
		return "", apperrors.Validation(map[string]string{"newEmail": "email-taken"})
	}
	if err := s.take(ctx, s.Limiter.Key("email-change", u.ID), emailChangeRule); err != nil {
		return "", err
	}
	if err := s.proveAuthKey(ctx, u, in.AuthKey, "password"); err != nil {
		return "", err
	}
	code, err := security.NumericCode(codeDigits)
	if err != nil {
		return "", apperrors.Internal(err)
	}
	now := s.Now()
	taken := false
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		other, err := userByEmail(ctx, tx, newEmail, false)
		if err != nil {
			return err
		}
		if other != nil {
			taken = true
			return nil
		}
		if _, err = tx.Exec(ctx, `DELETE FROM verification_codes WHERE user_id = $1 AND purpose = 'email-change' AND consumed_at IS NULL`, u.ID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO verification_codes (user_id, purpose, code_hash, new_email, expires_at, created_at) VALUES ($1, 'email-change', $2, $3, $4, $5)`,
			u.ID, security.HashCode(s.Config.Pepper, "email-change", emailChangeSubject(u.ID, newEmail), code), newEmail, now.Add(codeTTL), now)
		return err
	})
	if err != nil {
		return "", apperrors.Internal(err)
	}
	if taken {
		s.send(emailTakenMail(newEmail))
	} else {
		s.send(emailChangeCodeMail(newEmail, code, codeTTL))
	}
	return newEmail, nil
}

// ConfirmEmailChange aplica el cambio con el código recibido en el correo nuevo.
func (s *Service) ConfirmEmailChange(ctx context.Context, p Principal, in *EmailChangeConfirm) (*User, error) {
	email := security.NormalizeEmail(in.Email)
	invalid := apperrors.Validation(map[string]string{"code": "invalid-code"})
	if !validEmail(email) || !codeRe.MatchString(in.Code) {
		return nil, invalid
	}
	if err := s.take(ctx, s.Limiter.Key("email-confirm", p.UserID), ratelimit.CodeAttempt); err != nil {
		return nil, err
	}
	var (
		out      *User
		oldEmail string
		failure  error
	)
	err := database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		var (
			id       string
			hash     []byte
			newEmail string
			attempts int
			expires  time.Time
		)
		err := tx.QueryRow(ctx, `SELECT id::text, code_hash, new_email, attempts, expires_at FROM verification_codes
			WHERE user_id = $1 AND purpose = 'email-change' AND consumed_at IS NULL FOR UPDATE`, p.UserID).Scan(&id, &hash, &newEmail, &attempts, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			failure = invalid
			return nil
		}
		if err != nil {
			return err
		}
		now := s.Now()
		if attempts >= codeMaxAttempts || !expires.After(now) || newEmail != email {
			failure = invalid
			return nil
		}
		if !security.Equal(hash, security.HashCode(s.Config.Pepper, "email-change", emailChangeSubject(p.UserID, newEmail), in.Code)) {
			failure = invalid
			_, err = tx.Exec(ctx, `UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1`, id)
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, p.UserID).Scan(&oldEmail); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, p.UserID, newEmail); err != nil {
			if isUniqueViolation(err) {
				failure = apperrors.Validation(map[string]string{"email": "email-taken"})
				return nil
			}
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE verification_codes SET consumed_at = $2 WHERE id = $1`, id, now); err != nil {
			return err
		}
		if err = s.audit(ctx, tx, p.UserID, "email-change"); err != nil {
			return err
		}
		u, err := userByID(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		v := u.view()
		out = &v
		return nil
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, apperrors.Validation(map[string]string{"email": "email-taken"})
		}
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	s.send(emailChangedMail(oldEmail, email))
	return out, nil
}
