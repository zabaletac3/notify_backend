package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

// Handler expone el módulo por HTTP.
type Handler struct {
	svc        *Service
	log        *slog.Logger
	trustProxy bool
	cookies    CookieOptions
}

// CookieOptions describe cómo se emite la cookie de sesión del modo cookie (web). Solo afecta a las
// peticiones que traen `X-AxoNote-Session: cookie`; sin esa cabecera nada cambia.
type CookieOptions struct {
	Secure         bool     // atributo Secure de la cookie
	Domain         string   // dominio de la cookie; vacío = host-only
	AllowedOrigins []string // orígenes permitidos (anti-CSRF: un Origin presente debe estar aquí)
}

const (
	// sessionHeader activa el modo cookie. Cualquier otro valor que no sea `cookie` es un 422.
	sessionHeader     = "X-AxoNote-Session"
	sessionCookieMode = "cookie"
	// refreshCookie es el nombre y la ruta de la cookie con el token de renovación.
	refreshCookieName = "axonote_rt"
	refreshCookiePath = "/v1/auth"
)

func NewHandler(svc *Service, log *slog.Logger, trustProxy bool, cookies CookieOptions) *Handler {
	return &Handler{svc: svc, log: log, trustProxy: trustProxy, cookies: cookies}
}

type ctxKey struct{}

// PrincipalFrom devuelve quien hace la petición (solo en rutas protegidas por Require).
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// bearerPrincipal valida el token de acceso de la cabecera Authorization y el dispositivo.
func (h *Handler) bearerPrincipal(r *http.Request) (Principal, error) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return Principal{}, apperrors.SessionExpired()
	}
	return h.svc.Authenticate(r.Context(), strings.TrimSpace(auth[len(prefix):]))
}

// Require exige un token de acceso válido y un dispositivo vigente.
func (h *Handler) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := h.bearerPrincipal(r)
		if err != nil {
			response.Error(w, r, h.log, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// Routes monta las rutas públicas y las protegidas.
func (h *Handler) Routes(r chi.Router) {
	r.Post("/auth/prelogin", h.preLogin)
	r.Post("/auth/register", h.register)
	r.Post("/auth/verify-email", h.verifyEmail)
	r.Post("/auth/resend-code", h.resendCode)
	r.Post("/auth/login", h.login)
	r.Post("/auth/refresh", h.refresh)
	// Logout queda fuera del grupo protegido: en modo cookie debe funcionar aunque el token de acceso
	// haya vencido. El propio handler exige el Bearer en modo cuerpo (igual que hoy).
	r.Post("/auth/logout", h.logout)
	r.Post("/auth/password/forgot", h.forgot)
	r.Post("/auth/password/reset/bundle", h.resetBundle)
	r.Post("/auth/password/reset", h.resetPassword)

	r.Group(func(r chi.Router) {
		r.Use(h.Require)
		r.Get("/auth/session", h.session)
		r.Get("/devices", h.devices)
		r.Delete("/devices/{deviceId}", h.removeDevice)
		r.Get("/keys", h.keys)
		r.Put("/keys/recovery", h.rotateRecovery)
		r.Post("/me/password", h.changePassword)
		r.Post("/me/delete", h.deleteMeConfirmed)
		r.Delete("/me", h.deleteMe)
		r.Get("/me", h.me)
		r.Patch("/me", h.updateMe)
		r.Post("/me/email-change", h.requestEmailChange)
		r.Post("/me/email-change/confirm", h.confirmEmailChange)
	})
}

// sessionMode decide si la petición usa el modo cookie. La cabecera ausente deja el
// comportamiento de siempre (refreshToken en el cuerpo). Un valor distinto de `cookie` es 422 y, en
// modo cookie, un `Origin` presente que no esté permitido es un 403 anti-CSRF.
func (h *Handler) sessionMode(w http.ResponseWriter, r *http.Request) (cookieMode, ok bool) {
	switch v := r.Header.Get(sessionHeader); v {
	case "":
		return false, true
	case sessionCookieMode:
		if !h.originAllowed(r) {
			h.fail(w, r, apperrors.Forbidden("csrf"))
			return false, false
		}
		return true, true
	default:
		h.fail(w, r, apperrors.Validation(map[string]string{"session": "invalid-payload"}))
		return false, false
	}
}

// originAllowed: sin `Origin` (clientes no navegador) se permite; con `Origin`, debe coincidir
// exactamente con uno de los orígenes permitidos. La cabecera personalizada fuerza el preflight CORS.
func (h *Handler) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, o := range h.cookies.AllowedOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

// setRefreshCookie entrega el token de renovación como cookie HttpOnly. El token de acceso sigue
// viajando en el cuerpo.
func (h *Handler) setRefreshCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure/HttpOnly/SameSite se fijan en el literal
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		MaxAge:   int(h.svc.Config.RefreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cookies.Secure,
		SameSite: http.SameSiteStrictMode,
		Domain:   h.cookies.Domain,
	})
}

// clearRefreshCookie borra la cookie de sesión (logout).
func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure/HttpOnly/SameSite se fijan en el literal
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookies.Secure,
		SameSite: http.SameSiteStrictMode,
		Domain:   h.cookies.Domain,
	})
}

// writeSession responde con la sesión: en modo cookie entrega el refresh token solo en la cookie
// (el cuerpo queda sin `refreshToken`).
func (h *Handler) writeSession(w http.ResponseWriter, sess *Session, cookieMode bool) {
	if cookieMode {
		h.setRefreshCookie(w, sess.RefreshToken)
		sess.RefreshToken = "" // viaja solo en la cookie (Session.RefreshToken es omitempty)
	}
	response.JSON(w, http.StatusOK, sess)
}

func (h *Handler) ip(r *http.Request) string { return httpserver.ClientIP(r, h.trustProxy) }

// decode lee un cuerpo JSON estricto (ver httpserver.DecodeJSON).
func decode(_ http.ResponseWriter, r *http.Request, v any) error { return httpserver.DecodeJSON(r, v) }

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	response.Error(w, r, h.log, err)
}

type emailBody struct {
	Email string `json:"email"`
}

func (h *Handler) preLogin(w http.ResponseWriter, r *http.Request) {
	var b emailBody
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	kdf, err := h.svc.PreLogin(r.Context(), h.ip(r), b.Email)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"kdf": kdf})
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var b RegisterRequest
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.Register(r.Context(), h.ip(r), &b); err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusCreated, emailBody{Email: strings.ToLower(strings.TrimSpace(b.Email))})
}

func (h *Handler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	cookieMode, ok := h.sessionMode(w, r)
	if !ok {
		return
	}
	var b struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	sess, err := h.svc.VerifyEmail(r.Context(), h.ip(r), b.Email, b.Code)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeSession(w, sess, cookieMode)
}

func (h *Handler) resendCode(w http.ResponseWriter, r *http.Request) {
	var b emailBody
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.ResendCode(r.Context(), h.ip(r), b.Email); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	cookieMode, ok := h.sessionMode(w, r)
	if !ok {
		return
	}
	var b LoginRequest
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	sess, err := h.svc.Login(r.Context(), h.ip(r), &b)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeSession(w, sess, cookieMode)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	cookieMode, ok := h.sessionMode(w, r)
	if !ok {
		return
	}
	var token string
	if cookieMode {
		// En modo cookie la petición no lleva cuerpo: manda la cookie (un cuerpo con refreshToken
		// se ignora). Sin cookie es el mismo 401 que un token inválido.
		c, err := r.Cookie(refreshCookieName)
		if err != nil || c.Value == "" {
			h.fail(w, r, apperrors.SessionExpired())
			return
		}
		token = c.Value
	} else {
		var b struct {
			RefreshToken string `json:"refreshToken"`
		}
		if err := decode(w, r, &b); err != nil {
			h.fail(w, r, err)
			return
		}
		token = b.RefreshToken
	}
	sess, err := h.svc.Refresh(r.Context(), h.ip(r), token)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeSession(w, sess, cookieMode)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	cookieMode, ok := h.sessionMode(w, r)
	if !ok {
		return
	}
	if !cookieMode {
		// Modo cuerpo: como hasta hoy, exige un token de acceso válido.
		p, err := h.bearerPrincipal(r)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if err := h.svc.Logout(r.Context(), p); err != nil {
			h.fail(w, r, err)
			return
		}
		response.NoContent(w)
		return
	}
	// Modo cookie: idempotente y sin revelar nada. Se revoca con el Bearer si es válido; si venció
	// o falta, con la cookie de renovación. Siempre 204 y siempre se borra la cookie.
	if p, err := h.bearerPrincipal(r); err == nil {
		h.logoutQuiet(r, func() error { return h.svc.Logout(r.Context(), p) })
	} else if c, err := r.Cookie(refreshCookieName); err == nil && c.Value != "" {
		h.logoutQuiet(r, func() error { return h.svc.LogoutByRefreshToken(r.Context(), c.Value) })
	}
	h.clearRefreshCookie(w)
	response.NoContent(w)
}

// logoutQuiet registra (sin datos sensibles) un fallo al revocar: el logout en modo cookie siempre
// responde 204.
func (h *Handler) logoutQuiet(r *http.Request, revoke func() error) {
	if err := revoke(); err != nil {
		h.log.Warn("logout en modo cookie: no se pudo revocar la sesión", "err", err)
	}
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	sess, err := h.svc.CurrentSession(r.Context(), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, sess)
}

func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	list, err := h.svc.ListDevices(r.Context(), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, list)
}

func (h *Handler) removeDevice(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	if err := h.svc.RemoveDevice(r.Context(), p, chi.URLParam(r, "deviceId")); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

func (h *Handler) forgot(w http.ResponseWriter, r *http.Request) {
	var b emailBody
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.ForgotPassword(r.Context(), h.ip(r), b.Email); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) resetBundle(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	out, err := h.svc.ResetBundle(r.Context(), h.ip(r), b.Token)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, out)
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var b PasswordResetRequest
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.ResetPassword(r.Context(), h.ip(r), &b); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

func (h *Handler) keys(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	k, err := h.svc.Keys(r.Context(), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, k)
}

func (h *Handler) rotateRecovery(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var b RecoveryKeyRotation
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.RotateRecoveryKey(r.Context(), p, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var b PasswordChangeRequest
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.ChangePassword(r.Context(), p, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

// legacyDeleteSunset es la fecha de retirada de DELETE /me: ajustar a despliegue + 14 días antes del
// primer despliegue.
const legacyDeleteSunset = "Mon, 30 Nov 2026 00:00:00 GMT"

func (h *Handler) deleteMeConfirmed(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var b DeleteAccountRequest
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.DeleteAccount(r.Context(), p, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) deleteMe(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	if err := h.svc.DeleteAccountLegacy(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Sunset", legacyDeleteSunset)
	w.Header().Set("Link", `</v1/me/delete>; rel="successor-version"`)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	u, err := h.svc.Me(r.Context(), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, u)
}

func (h *Handler) updateMe(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var b ProfileUpdate
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	u, err := h.svc.UpdateProfile(r.Context(), p, &b)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, u)
}

func (h *Handler) requestEmailChange(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var b EmailChangeRequest
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	email, err := h.svc.RequestEmailChange(r.Context(), p, &b)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusAccepted, emailBody{Email: email})
}

func (h *Handler) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var b EmailChangeConfirm
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	u, err := h.svc.ConfirmEmailChange(r.Context(), p, &b)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, u)
}
