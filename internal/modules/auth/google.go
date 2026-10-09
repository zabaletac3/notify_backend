package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

// Finalidades de los tickets del flujo de Google (ver migración 00008).
const (
	ticketGoogleState  = "google-state"
	ticketGoogleResult = "google-result"
	ticketGoogleLink   = "google-link"
	ticketGoogleSignup = "google-signup"

	googleStateTTL  = 10 * time.Minute
	googleResultTTL = 5 * time.Minute
	googleLinkTTL   = 10 * time.Minute
	googleSignupTTL = 15 * time.Minute
)

// Tope de inicios de flujo por IP (genera tickets y llama a la red en el callback).
var googleStartRule = ratelimit.Rule{Max: 30, Window: time.Minute, Block: 5 * time.Minute}

// El `challenge` de la web es base64url de 32 bytes (SHA-256 de su verifier).
var googleChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type googleStatePayload struct {
	Challenge    string `json:"challenge"`
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkceVerifier"`
}

type googleResultPayload struct {
	Sub       string `json:"sub"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Challenge string `json:"challenge"`
}

type googleLinkPayload struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

type googleSignupPayload struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// googleDisabled es el error de toda ruta de Google con el proveedor apagado.
func googleDisabled() error { return apperrors.Forbidden("google-disabled") }

// pkceChallenge calcula b64url(SHA-256(verifier)).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GoogleStart inicia el flujo: valida el challenge de la web, crea el ticket de estado (con el nonce
// y el verifier PKCE del servidor, que nunca salen) y devuelve la URL de autorización.
func (s *Service) GoogleStart(ctx context.Context, ip, challenge string) (*GoogleStartResult, error) {
	if s.OIDC == nil {
		return nil, googleDisabled()
	}
	if !googleChallengeRe.MatchString(challenge) {
		return nil, apperrors.Validation(map[string]string{"challenge": "invalid-payload"})
	}
	if err := s.take(ctx, s.Limiter.Key("google-start", ip), googleStartRule); err != nil {
		return nil, err
	}
	nonce, err := security.RandomToken(16)
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	verifier, err := security.RandomToken(32)
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	var state string
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		state, err = s.newTicket(ctx, tx, ticketGoogleState, nil,
			googleStatePayload{Challenge: challenge, Nonce: nonce, PKCEVerifier: verifier}, googleStateTTL)
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return &GoogleStartResult{URL: s.OIDC.AuthURL(state, nonce, pkceChallenge(verifier))}, nil
}

// GoogleCallback atiende el retorno del navegador desde Google. Nunca responde JSON: devuelve
// siempre una URL de la web con `#code=` o `#error=` (el fragmento no viaja al servidor ni en el
// Referer). Consume el ticket de estado, canjea el código y crea el ticket de resultado.
func (s *Service) GoogleCallback(ctx context.Context, ip, code, state, errParam string) string {
	base := strings.TrimRight(s.Config.WebBaseURL, "/") + "/auth/google"
	fail := func(short string) string { return base + "#error=" + short }
	if s.OIDC == nil {
		return fail("google-disabled")
	}
	if errParam != "" {
		return fail("access-denied")
	}
	if state == "" || code == "" {
		return fail("invalid-state")
	}
	var payload googleStatePayload
	found := false
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, ticketGoogleState, state)
		if err != nil || tk == nil {
			return err
		}
		if err := json.Unmarshal(tk.Payload, &payload); err != nil {
			return err
		}
		if err := s.consumeTicket(ctx, tx, tk.ID); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		s.Log.Error("google callback: ticket de estado", "err", err)
		return fail("server")
	}
	if !found {
		return fail("invalid-state")
	}
	id, err := s.OIDC.Exchange(ctx, code, payload.PKCEVerifier, payload.Nonce)
	if err != nil {
		s.Log.Warn("google callback: canje", "err", err)
		return fail("unavailable")
	}
	if !id.EmailVerified {
		return fail("email-unverified")
	}
	email := security.NormalizeEmail(id.Email)
	if !validEmail(email) {
		return fail("invalid-email")
	}
	var result string
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.newTicket(ctx, tx, ticketGoogleResult, nil,
			googleResultPayload{Sub: id.Subject, Email: email, Name: id.Name, Challenge: payload.Challenge}, googleResultTTL)
		return err
	})
	if err != nil {
		s.Log.Error("google callback: ticket de resultado", "err", err)
		return fail("server")
	}
	return base + "#code=" + result
}

// GoogleExchange canjea el resultado: ata el verifier del navegador al challenge guardado y decide
// entre iniciar sesión, pedir el segundo paso, vincular una cuenta existente o crear una nueva.
func (s *Service) GoogleExchange(ctx context.Context, ip string, req *GoogleExchangeRequest) (*GoogleOutcome, error) {
	if s.OIDC == nil {
		return nil, googleDisabled()
	}
	if !googleChallengeRe.MatchString(req.Verifier) {
		return nil, apperrors.Validation(map[string]string{"verifier": "invalid-payload"})
	}
	var (
		out     *GoogleOutcome
		failure error
	)
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, ticketGoogleResult, req.Code)
		if err != nil {
			return err
		}
		if tk == nil {
			failure = googleInvalidResult()
			return nil
		}
		var payload googleResultPayload
		if err := json.Unmarshal(tk.Payload, &payload); err != nil {
			return err
		}
		// Tiempo constante: el challenge ata el resultado al navegador que empezó el flujo (anti login-CSRF).
		if !security.Equal([]byte(pkceChallenge(req.Verifier)), []byte(payload.Challenge)) {
			failure = apperrors.Validation(map[string]string{"verifier": "invalid-payload"})
			return nil
		}
		if err := s.consumeTicket(ctx, tx, tk.ID); err != nil {
			return err
		}

		// 1. Identidad ya vinculada: se entra por `sub`, sin mirar el correo.
		userID, err := identityUser(ctx, tx, payload.Sub)
		if err != nil {
			return err
		}
		if userID != "" {
			u, err := userByID(ctx, tx, userID)
			if err != nil {
				return err
			}
			if u == nil {
				failure = googleInvalidResult()
				return nil
			}
			if u.DeletedAt != nil { // S5: en periodo de gracia no se entra
				failure = apperrors.Forbidden("account-deleted")
				return nil
			}
			if err := database.SetUser(ctx, tx, userID); err != nil {
				return err
			}
			outcome, err := s.completeLogin(ctx, tx, u, cleanDevice(req.Device), "google")
			if err != nil {
				return err
			}
			out = googleOutcomeFromLogin(outcome)
			return nil
		}

		// 2/3. Sin identidad: cuenta verificada => vincular; sin cuenta (o sin verificar) => registro.
		u, err := userByEmail(ctx, tx, payload.Email, false)
		if err != nil {
			return err
		}
		switch {
		case u != nil && u.DeletedAt != nil: // S5
			failure = apperrors.Forbidden("account-deleted")
			return nil
		case u != nil && u.VerifiedAt != nil:
			token, err := s.newTicket(ctx, tx, ticketGoogleLink, &u.ID,
				googleLinkPayload{Sub: payload.Sub, Email: payload.Email}, googleLinkTTL)
			if err != nil {
				return err
			}
			kdf := u.Kdf
			out = &GoogleOutcome{Status: "link-required", LinkToken: token, Email: u.Email, Kdf: &kdf}
			return nil
		default:
			token, err := s.newTicket(ctx, tx, ticketGoogleSignup, nil,
				googleSignupPayload{Sub: payload.Sub, Email: payload.Email, Name: payload.Name}, googleSignupTTL)
			if err != nil {
				return err
			}
			out = &GoogleOutcome{Status: "signup-required", SignupToken: token, Email: payload.Email, FullName: payload.Name}
			return nil
		}
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	return out, nil
}

// GoogleLink vincula Google con una cuenta existente. A efectos de seguridad es un login con
// contraseña: mismos límites (por cuenta+IP y por IP) y mismo error. Vincula por `sub`, nunca por
// correo, y nunca de forma automática.
func (s *Service) GoogleLink(ctx context.Context, ip string, req *GoogleLinkRequest) (*loginOutcome, error) {
	if s.OIDC == nil {
		return nil, googleDisabled()
	}
	if err := s.take(ctx, s.Limiter.Key("login-hit", ip), loginHitRule); err != nil {
		return nil, err
	}
	var (
		outcome    *loginOutcome
		failure    error
		email      string
		acct, byIP string
	)
	err := database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, ticketGoogleLink, req.LinkToken)
		if err != nil {
			return err
		}
		if tk == nil || tk.UserID == nil {
			failure = googleInvalidLink()
			return nil
		}
		u, err := userByID(ctx, tx, *tk.UserID)
		if err != nil {
			return err
		}
		if u == nil || u.DeletedAt != nil || u.VerifiedAt == nil {
			failure = googleInvalidLink()
			return nil
		}
		email = u.Email
		acct, byIP = s.Limiter.Key("login", email, ip), s.Limiter.Key("login-ip", ip)
		if err := s.blocked(ctx, acct, byIP); err != nil {
			failure = err
			return nil
		}
		var ok bool
		if security.ValidAuthKey(req.AuthKey) {
			ok, _ = s.Hasher.Verify(u.AuthKeyHash, req.AuthKey)
		} else {
			s.Hasher.VerifyDummy(req.AuthKey)
		}
		if !ok {
			if err := s.bumpTicket(ctx, tx, tk.ID); err != nil {
				return err
			}
			for _, k := range []struct {
				key  string
				rule ratelimit.Rule
			}{{acct, ratelimit.LoginByAccount}, {byIP, ratelimit.LoginByIP}} {
				if _, err := s.Limiter.Fail(ctx, k.key, k.rule); err != nil {
					failure = apperrors.Unavailable(err)
					return nil
				}
			}
			failure = apperrors.InvalidCredentials()
			return nil // se confirma para que el intento cuente
		}
		var payload googleLinkPayload
		if err := json.Unmarshal(tk.Payload, &payload); err != nil {
			return err
		}
		if err := s.consumeTicket(ctx, tx, tk.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_identities (provider, subject, user_id, email) VALUES ('google', $1, $2, $3)
			ON CONFLICT (provider, subject) DO NOTHING`, payload.Sub, u.ID, payload.Email); err != nil {
			return err
		}
		var owner string
		if err := tx.QueryRow(ctx, `SELECT user_id::text FROM user_identities WHERE provider = 'google' AND subject = $1`, payload.Sub).Scan(&owner); err != nil {
			return err
		}
		if owner != u.ID {
			failure = googleInvalidLink()
			return nil
		}
		if err := database.SetUser(ctx, tx, u.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, u.ID, "google-link"); err != nil {
			return err
		}
		outcome, err = s.completeLogin(ctx, tx, u, cleanDevice(req.Device), "google")
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	if err := s.Limiter.Reset(ctx, acct); err != nil {
		return nil, apperrors.Unavailable(err)
	}
	s.send(googleLinkedMail(email))
	return outcome, nil
}

// GoogleRegister crea la cuenta con Google: el correo viene ya verificado por Google (no hay código
// de 6 dígitos). La persona crea su contraseña (G2). Si había un registro sin verificar con ese
// correo, se descarta; una carrera de unicidad se responde como ticket inválido.
func (s *Service) GoogleRegister(ctx context.Context, ip string, req *GoogleRegisterRequest) (*Session, error) {
	if s.OIDC == nil {
		return nil, googleDisabled()
	}
	if f := validateGoogleRegister(req); len(f) > 0 {
		return nil, apperrors.Validation(f)
	}
	if err := s.take(ctx, s.Limiter.Key("register", ip), registerRule); err != nil {
		return nil, err
	}
	authHash, err := s.Hasher.Hash(req.AuthKey)
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	recHash, err := s.Hasher.Hash(req.RecoveryAuth)
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	kdf, _ := json.Marshal(req.Keys.Kdf)
	keysJSON, _ := json.Marshal(map[string]string{
		"wrappedMasterKey": req.Keys.WrappedMasterKey, "recoveryWrappedMasterKey": req.Keys.RecoveryWrappedMasterKey})

	var (
		sess    *Session
		failure error
	)
	err = database.WithoutUser(ctx, s.Pool, func(tx pgx.Tx) error {
		tk, err := s.takeTicket(ctx, tx, ticketGoogleSignup, req.SignupToken)
		if err != nil {
			return err
		}
		if tk == nil {
			failure = googleInvalidSignup()
			return nil
		}
		var payload googleSignupPayload
		if err := json.Unmarshal(tk.Payload, &payload); err != nil {
			return err
		}
		email := security.NormalizeEmail(payload.Email)
		if !validEmail(email) {
			failure = apperrors.Validation(map[string]string{"email": "invalid-email"})
			return nil
		}
		now := s.Now()
		if _, err := tx.Exec(ctx, `SELECT discard_unverified_user($1)`, email); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO users (id, email, full_name, accepted_terms_at, email_verified_at, kdf, auth_key_hash, recovery_auth_hash, keys, created_at)
			VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $4) ON CONFLICT (id) DO NOTHING`,
			req.UserID, email, trimName(req.FullName), now, kdf, authHash, recHash, keysJSON)
		if err != nil {
			if isUniqueViolation(err) {
				failure = googleInvalidSignup()
				return nil
			}
			return err
		}
		if tag.RowsAffected() == 0 {
			failure = googleInvalidSignup()
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_identities (provider, subject, user_id, email) VALUES ('google', $1, $2, $3)`,
			payload.Sub, req.UserID, payload.Email); err != nil {
			if isUniqueViolation(err) {
				failure = googleInvalidSignup()
				return nil
			}
			return err
		}
		if err := s.consumeTicket(ctx, tx, tk.ID); err != nil {
			return err
		}
		if err := database.SetUser(ctx, tx, req.UserID); err != nil {
			return err
		}
		u, err := userByID(ctx, tx, req.UserID)
		if err != nil {
			return err
		}
		// Cuenta nueva: no puede tener MFA (igual que VerifyEmail), así que se emite sesión directa.
		sess, err = s.newSession(ctx, tx, u, cleanDevice(req.Device), true)
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, req.UserID, "google-register")
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if failure != nil {
		return nil, failure
	}
	return sess, nil
}

// UnlinkGoogle desvincula Google de la cuenta. Exige la prueba de la contraseña (mismo error y
// límite que las demás operaciones sensibles).
func (s *Service) UnlinkGoogle(ctx context.Context, p Principal, authKey string) error {
	if s.OIDC == nil {
		return googleDisabled()
	}
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
	err = database.WithUser(ctx, s.Pool, p.UserID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_identities WHERE user_id = $1 AND provider = 'google'`, p.UserID); err != nil {
			return err
		}
		// Sin Google ya no puede existir confianza basada en Google (T1).
		if err := s.revokeTrustedDevices(ctx, tx, p.UserID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p.UserID, "google-unlink")
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	s.send(googleUnlinkedMail(u.Email))
	return nil
}

// ── Auxiliares ──────────────────────────────────────────────────

func identityUser(ctx context.Context, tx pgx.Tx, subject string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT user_id::text FROM user_identities WHERE provider = 'google' AND subject = $1`, subject).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func googleOutcomeFromLogin(o *loginOutcome) *GoogleOutcome {
	if o.Session != nil {
		return &GoogleOutcome{Status: "authenticated", Session: o.Session}
	}
	exp := o.MFAExp
	return &GoogleOutcome{Status: "mfa-required", MFAToken: o.MFAToken, ExpiresAt: &exp}
}

func googleInvalidResult() error {
	return apperrors.Validation(map[string]string{"code": "invalid-token"})
}
func googleInvalidLink() error {
	return apperrors.Validation(map[string]string{"linkToken": "invalid-token"})
}
func googleInvalidSignup() error {
	return apperrors.Validation(map[string]string{"signupToken": "invalid-token"})
}

// validateGoogleRegister valida el cuerpo del registro con Google (sin `email`, que sale del ticket).
func validateGoogleRegister(r *GoogleRegisterRequest) map[string]string {
	f := map[string]string{}
	if !validUUID(r.UserID) {
		f["userId"] = "required"
	}
	name := strings.TrimSpace(r.FullName)
	switch {
	case utf8.RuneCountInString(name) < 2:
		f["fullName"] = "name-too-short"
	case utf8.RuneCountInString(name) > maxNameLen:
		f["fullName"] = "name-too-long"
	}
	if !r.AcceptedTerms {
		f["acceptedTerms"] = "terms-required"
	}
	if !security.ValidAuthKey(r.AuthKey) {
		f["authKey"] = "required"
	}
	if !security.ValidAuthKey(r.RecoveryAuth) {
		f["recoveryAuth"] = "required"
	}
	if r.AuthKey != "" && r.AuthKey == r.RecoveryAuth {
		f["recoveryAuth"] = "invalid-payload"
	}
	if code := validateKeys(&r.Keys); code != "" {
		f["keys"] = code
	}
	return f
}
