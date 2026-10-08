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
}

func NewHandler(svc *Service, log *slog.Logger, trustProxy bool) *Handler {
	return &Handler{svc: svc, log: log, trustProxy: trustProxy}
}

type ctxKey struct{}

// PrincipalFrom devuelve quien hace la petición (solo en rutas protegidas por Require).
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Require exige un token de acceso válido y un dispositivo vigente.
func (h *Handler) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			response.Error(w, r, h.log, apperrors.SessionExpired())
			return
		}
		p, err := h.svc.Authenticate(r.Context(), strings.TrimSpace(auth[len(prefix):]))
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
	r.Post("/auth/password/forgot", h.forgot)
	r.Post("/auth/password/reset/bundle", h.resetBundle)
	r.Post("/auth/password/reset", h.resetPassword)

	r.Group(func(r chi.Router) {
		r.Use(h.Require)
		r.Post("/auth/logout", h.logout)
		r.Get("/auth/session", h.session)
		r.Get("/devices", h.devices)
		r.Delete("/devices/{deviceId}", h.removeDevice)
		r.Get("/keys", h.keys)
		r.Put("/keys/recovery", h.rotateRecovery)
		r.Post("/me/password", h.changePassword)
		r.Delete("/me", h.deleteMe)
		r.Get("/me", h.me)
		r.Patch("/me", h.updateMe)
		r.Post("/me/email-change", h.requestEmailChange)
		r.Post("/me/email-change/confirm", h.confirmEmailChange)
	})
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
	response.JSON(w, http.StatusOK, sess)
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
	response.JSON(w, http.StatusOK, sess)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var b struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := decode(w, r, &b); err != nil {
		h.fail(w, r, err)
		return
	}
	sess, err := h.svc.Refresh(r.Context(), h.ip(r), b.RefreshToken)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, sess)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	if err := h.svc.Logout(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
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

func (h *Handler) deleteMe(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	if err := h.svc.DeleteAccount(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
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
