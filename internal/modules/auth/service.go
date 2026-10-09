package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
	"github.com/zabaletac3/notify_backend/internal/platform/oidc"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

const (
	codeDigits      = 6
	codeTTL         = 10 * time.Minute
	codeMaxAttempts = 5
	resendMinGap    = 60 * time.Second
	maxPendingMails = 64
)

// Reglas propias de este módulo (las de login y códigos están en ratelimit).
var (
	registerRule = ratelimit.Rule{Max: 10, Window: time.Hour, Block: time.Hour}
	// Intentos de login (buenos o malos) por IP.
	loginHitRule = ratelimit.Rule{Max: 60, Window: time.Minute, Block: 5 * time.Minute}
	// Intentos de código por cuenta, sea cual sea la IP: un atacante repartido no puede adivinar 10^6 códigos.
	verifyAccountRule = ratelimit.Rule{Max: 15, Window: time.Hour, Block: time.Hour}
)

// Config son los valores que necesita el servicio.
type Config struct {
	Pepper     []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	WebBaseURL string
}

// Deps agrupa las dependencias; todas son obligatorias.
type Deps struct {
	Pool    *pgxpool.Pool
	Hasher  *security.AuthKeyHasher
	Signer  *security.Signer
	Limiter *ratelimit.Limiter
	Mailer  mailer.Mailer
	OIDC    oidc.Provider // nil = Google deshabilitado (GOOGLE_PROVIDER=off)
	Log     *slog.Logger
	Config  Config
	Now     func() time.Time // opcional (pruebas)
}

// Service contiene la lógica de cuentas y sesión.
type Service struct {
	Deps
	wg   sync.WaitGroup
	mail chan struct{}
}

func NewService(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{Deps: d, mail: make(chan struct{}, maxPendingMails)}
}

// Close espera a que terminen los correos en vuelo.
func (s *Service) Close() { s.wg.Wait() }

// send envía en segundo plano: así el tiempo de respuesta no revela si se envió algo (p. ej. si el
// correo ya tenía cuenta). Los fallos se registran sin datos personales.
func (s *Service) send(msg mailer.Message) {
	select {
	case s.mail <- struct{}{}:
	default:
		s.Log.Warn("cola de correo llena: se descarta un envío")
		return
	}
	s.wg.Add(1)
	go func() {
		defer func() { <-s.mail; s.wg.Done() }()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.Mailer.Send(ctx, msg); err != nil {
			s.Log.Warn("no se pudo enviar el correo", "to", mailer.MaskEmail(msg.To),
				"temporal", errors.Is(err, mailer.ErrTemporary))
		}
	}()
}

// ── Límites ─────────────────────────────────────────────────────

func (s *Service) take(ctx context.Context, key string, r ratelimit.Rule) error {
	res, err := s.Limiter.Take(ctx, key, r)
	if err != nil {
		return apperrors.Unavailable(err)
	}
	if !res.Allowed {
		return apperrors.RateLimited(res.RetryAfter)
	}
	return nil
}

func (s *Service) blocked(ctx context.Context, keys ...string) error {
	for _, k := range keys {
		res, err := s.Limiter.Blocked(ctx, k)
		if err != nil {
			return apperrors.Unavailable(err)
		}
		if !res.Allowed {
			return apperrors.RateLimited(res.RetryAfter)
		}
	}
	return nil
}

// ── Prelogin ────────────────────────────────────────────────────

func (s *Service) PreLogin(ctx context.Context, ip, email string) (KdfParams, error) {
	email = security.NormalizeEmail(email)
	if !validEmail(email) {
		return KdfParams{}, apperrors.Validation(map[string]string{"email": "invalid-email"})
	}
	if err := s.take(ctx, s.Limiter.Key("prelogin", ip), ratelimit.PreLogin); err != nil {
		return KdfParams{}, err
	}
	var u *userRow
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) (err error) {
		u, err = userByEmail(ctx, tx, email, false)
		return err
	})
	if err != nil {
		return KdfParams{}, apperrors.Internal(err)
	}
	if u == nil || u.DeletedAt != nil {
		return security.FakeKDF(s.Config.Pepper, email), nil
	}
	return u.Kdf, nil
}

// ── Registro ────────────────────────────────────────────────────

// Register crea la cuenta sin verificar. Responde igual exista o no el correo (no revela cuentas).
func (s *Service) Register(ctx context.Context, ip string, req *RegisterRequest) error {
	if f := validateRegister(req); len(f) > 0 {
		return apperrors.Validation(f)
	}
	email := security.NormalizeEmail(req.Email)
	if err := s.take(ctx, s.Limiter.Key("register", ip), registerRule); err != nil {
		return err
	}
	authHash, err := s.Hasher.Hash(req.AuthKey)
	if err != nil {
		return apperrors.Internal(err)
	}
	recHash, err := s.Hasher.Hash(req.RecoveryAuth)
	if err != nil {
		return apperrors.Internal(err)
	}
	kdf, _ := json.Marshal(req.Keys.Kdf)
	keys, _ := json.Marshal(map[string]string{
		"wrappedMasterKey": req.Keys.WrappedMasterKey, "recoveryWrappedMasterKey": req.Keys.RecoveryWrappedMasterKey})
	code, err := security.NumericCode(codeDigits)
	if err != nil {
		return apperrors.Internal(err)
	}
	now := s.Now()

	var notify *mailer.Message
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		existing, err := userByEmail(ctx, tx, email, true)
		if err != nil {
			return err
		}
		if existing != nil && existing.VerifiedAt != nil {
			m := existingAccountMail(email)
			notify = &m // cuenta real (o en periodo de gracia): no se toca; se avisa a su dueño
			return nil
		}
		if existing != nil {
			// Registro sin verificar: se sustituye; quien lo creó no era dueño del correo.
			if _, err := tx.Exec(ctx, `SELECT discard_unverified_user($1)`, email); err != nil {
				return err
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO users (id, email, full_name, accepted_terms_at, kdf, auth_key_hash, recovery_auth_hash, keys, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $4) ON CONFLICT (id) DO NOTHING`,
			req.UserID, email, trimName(req.FullName), now, kdf, authHash, recHash, keys)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil // el id ya existe: se ignora en silencio
		}
		if _, err := tx.Exec(ctx, `INSERT INTO verification_codes (user_id, purpose, code_hash, expires_at, created_at)
			VALUES ($1, 'verify-email', $2, $3, $4)`,
			req.UserID, security.HashCode(s.Config.Pepper, "verify-email", req.UserID, code), now.Add(codeTTL), now); err != nil {
			return err
		}
		m := verificationMail(email, code, codeTTL)
		notify = &m
		return nil
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil // carrera con otro registro del mismo correo
		}
		return apperrors.Internal(err)
	}
	if notify != nil {
		s.send(*notify)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// ── Verificación y reenvío ──────────────────────────────────────

func (s *Service) VerifyEmail(ctx context.Context, ip, email, code string) (*Session, error) {
	email = security.NormalizeEmail(email)
	if !validEmail(email) || !codeRe.MatchString(code) {
		return nil, apperrors.Validation(map[string]string{"code": "invalid-code"})
	}
	if err := s.take(ctx, s.Limiter.Key("verify", email, ip), ratelimit.CodeAttempt); err != nil {
		return nil, err
	}
	if err := s.take(ctx, s.Limiter.Key("verify-account", email), verifyAccountRule); err != nil {
		return nil, err
	}
	invalid := apperrors.Validation(map[string]string{"code": "invalid-code"})
	var (
		sess    *Session
		failure error
	)
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		u, err := userByEmail(ctx, tx, email, true)
		if err != nil {
			return err
		}
		if u == nil || u.VerifiedAt != nil || u.DeletedAt != nil {
			failure = invalid
			return nil
		}
		var (
			id       string
			hash     []byte
			attempts int
			expires  time.Time
		)
		err = tx.QueryRow(ctx, `SELECT id::text, code_hash, attempts, expires_at FROM verification_codes
			WHERE user_id = $1 AND purpose = 'verify-email' AND consumed_at IS NULL FOR UPDATE`, u.ID).
			Scan(&id, &hash, &attempts, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			failure = invalid
			return nil
		}
		if err != nil {
			return err
		}
		now := s.Now()
		if attempts >= codeMaxAttempts || !expires.After(now) {
			failure = invalid
			return nil
		}
		if !security.Equal(hash, security.HashCode(s.Config.Pepper, "verify-email", u.ID, code)) {
			failure = invalid
			_, err = tx.Exec(ctx, `UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1`, id)
			return err // se confirma para que el intento cuente
		}
		if _, err = tx.Exec(ctx, `UPDATE verification_codes SET consumed_at = $2 WHERE id = $1`, id, now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET email_verified_at = $2 WHERE id = $1`, u.ID, now); err != nil {
			return err
		}
		u.VerifiedAt = &now
		if err = database.SetUser(ctx, tx, u.ID); err != nil {
			return err
		}
		// Una cuenta recién verificada no puede tener MFA (nunca se activó), así que aquí se puede
		// seguir llamando a newSession directamente en vez de a completeLogin.
		sess, err = s.newSession(ctx, tx, u, DeviceInfo{}, false)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	return sess, nil
}

// ResendCode reenvía el código (como mucho uno cada 60 s). Siempre responde igual.
func (s *Service) ResendCode(ctx context.Context, ip, email string) error {
	email = security.NormalizeEmail(email)
	if !validEmail(email) {
		return apperrors.Validation(map[string]string{"email": "invalid-email"})
	}
	if err := s.take(ctx, s.Limiter.Key("resend", email, ip), ratelimit.CodeResend); err != nil {
		return err
	}
	code, err := security.NumericCode(codeDigits)
	if err != nil {
		return apperrors.Internal(err)
	}
	now := s.Now()
	var notify *mailer.Message
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		u, err := userByEmail(ctx, tx, email, true)
		if err != nil || u == nil || u.VerifiedAt != nil || u.DeletedAt != nil {
			return err
		}
		var last time.Time
		err = tx.QueryRow(ctx, `SELECT created_at FROM verification_codes WHERE user_id = $1 AND purpose = 'verify-email' AND consumed_at IS NULL`, u.ID).Scan(&last)
		if err == nil && now.Sub(last) < resendMinGap {
			return nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM verification_codes WHERE user_id = $1 AND purpose = 'verify-email' AND consumed_at IS NULL`, u.ID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO verification_codes (user_id, purpose, code_hash, expires_at, created_at) VALUES ($1, 'verify-email', $2, $3, $4)`,
			u.ID, security.HashCode(s.Config.Pepper, "verify-email", u.ID, code), now.Add(codeTTL), now); err != nil {
			return err
		}
		m := verificationMail(email, code, codeTTL)
		notify = &m
		return nil
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if notify != nil {
		s.send(*notify)
	}
	return nil
}

// ── Login ───────────────────────────────────────────────────────

func (s *Service) Login(ctx context.Context, ip string, req *LoginRequest) (*loginOutcome, error) {
	// Tope de intentos por IP ANTES de cualquier hash: Argon2id cuesta memoria y CPU, y sin esto bastaría
	// inundar el login para agotar el servidor.
	if err := s.take(ctx, s.Limiter.Key("login-hit", ip), loginHitRule); err != nil {
		return nil, err
	}
	email := security.NormalizeEmail(req.Email)
	if !validEmail(email) || !security.ValidAuthKey(req.AuthKey) {
		// Misma respuesta que unas credenciales incorrectas. Sin hash: una entrada mal formada no revela
		// nada de ninguna cuenta y no debe poder gastar el presupuesto de CPU.
		return nil, apperrors.InvalidCredentials()
	}
	acct, byIP := s.Limiter.Key("login", email, ip), s.Limiter.Key("login-ip", ip)
	if err := s.blocked(ctx, acct, byIP); err != nil {
		return nil, err
	}

	var u *userRow
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) (err error) {
		u, err = userByEmail(ctx, tx, email, false)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	ok, rehash := false, false
	if u == nil || u.DeletedAt != nil {
		s.Hasher.VerifyDummy(req.AuthKey)
	} else {
		ok, rehash = s.Hasher.Verify(u.AuthKeyHash, req.AuthKey)
	}
	if !ok {
		for _, k := range []struct {
			key  string
			rule ratelimit.Rule
		}{{acct, ratelimit.LoginByAccount}, {byIP, ratelimit.LoginByIP}} {
			if _, err := s.Limiter.Fail(ctx, k.key, k.rule); err != nil {
				return nil, apperrors.Unavailable(err)
			}
		}
		return nil, apperrors.InvalidCredentials()
	}
	if u.VerifiedAt == nil {
		return nil, apperrors.Forbidden("email-not-verified")
	}
	if err := s.Limiter.Reset(ctx, acct); err != nil {
		return nil, apperrors.Unavailable(err)
	}

	var newHash []byte
	if rehash {
		newHash, _ = s.Hasher.Hash(req.AuthKey)
	}
	dev := cleanDevice(req.Device)
	var outcome *loginOutcome
	err = database.WithUser(ctx, s.Pool, u.ID, func(tx pgx.Tx) error {
		if newHash != nil {
			if _, err := tx.Exec(ctx, `UPDATE users SET auth_key_hash = $2 WHERE id = $1`, u.ID, newHash); err != nil {
				return err
			}
		}
		var err error
		outcome, err = s.completeLogin(ctx, tx, u, dev, "password")
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return outcome, nil
}

// loginOutcome es el resultado del primer factor: una sesión nueva o un reto de segundo paso (MFA).
type loginOutcome struct {
	Session  *Session
	MFAToken string
	MFAExp   time.Time
}

// completeLogin es el ÚNICO camino hacia una sesión nueva tras el primer factor (contraseña o
// Google). Unifica el control del segundo paso: si la cuenta tiene MFA activo, no emite sesión sino
// un ticket `mfa-login`. Google no puede saltarse el MFA (M3). tx debe tener la cuenta fijada
// (database.SetUser).
func (s *Service) completeLogin(ctx context.Context, tx pgx.Tx, u *userRow, dev DeviceInfo, method string) (*loginOutcome, error) {
	enabled, err := mfaEnabled(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	if enabled {
		token, err := s.newTicket(ctx, tx, ticketMFALogin, &u.ID,
			mfaTicketPayload{Device: dev, Method: method}, mfaTicketTTL)
		if err != nil {
			return nil, err
		}
		return &loginOutcome{MFAToken: token, MFAExp: s.Now().Add(mfaTicketTTL)}, nil
	}
	sess, err := s.newSession(ctx, tx, u, dev, true)
	if err != nil {
		return nil, err
	}
	return &loginOutcome{Session: sess}, nil
}

// newSession registra el dispositivo y emite los dos tokens. tx debe tener la cuenta fijada.
func (s *Service) newSession(ctx context.Context, tx pgx.Tx, u *userRow, dev DeviceInfo, withKeys bool) (*Session, error) {
	if dev.Name == "" {
		dev = cleanDevice(nil)
	}
	deviceID := uuid.Must(uuid.NewV7()).String()
	if _, err := tx.Exec(ctx, `INSERT INTO devices (id, user_id, name, platform) VALUES ($1, $2, $3, $4)`,
		deviceID, u.ID, dev.Name, dev.Platform); err != nil {
		return nil, err
	}
	refresh, err := s.insertRefresh(ctx, tx, u.ID, deviceID, uuid.Must(uuid.NewV7()).String())
	if err != nil {
		return nil, err
	}
	access, exp, err := s.Signer.Issue(u.ID, deviceID)
	if err != nil {
		return nil, err
	}
	sess := &Session{User: u.view(), ExpiresAt: exp, AccessToken: access, RefreshToken: refresh}
	if withKeys {
		sess.Keys = u.keys()
	}
	return sess, nil
}

func (s *Service) insertRefresh(ctx context.Context, tx pgx.Tx, userID, deviceID, familyID string) (string, error) {
	tok, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	now := s.Now()
	_, err = tx.Exec(ctx, `INSERT INTO refresh_tokens (id, user_id, device_id, family_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		uuid.Must(uuid.NewV7()).String(), userID, deviceID, familyID, security.HashToken(tok), now.Add(s.Config.RefreshTTL), now)
	return tok, err
}

func trimName(n string) string {
	return string([]rune(trimSpace(n)))
}
