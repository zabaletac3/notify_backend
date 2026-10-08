package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
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

	r.Group(func(r chi.Router) {
		r.Use(h.Require)
		r.Post("/auth/logout", h.logout)
		r.Get("/auth/session", h.session)
		r.Get("/devices", h.devices)
		r.Delete("/devices/{deviceId}", h.removeDevice)
	})
}

func (h *Handler) ip(r *http.Request) string { return httpserver.ClientIP(r, h.trustProxy) }

// decode lee un cuerpo JSON estricto: tipo correcto, sin campos desconocidos ni datos de más.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return apperrors.Validation(map[string]string{"body": "invalid-payload"})
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return apperrors.PayloadTooLarge()
		}
		return apperrors.Validation(map[string]string{"body": "invalid-payload"})
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return apperrors.Validation(map[string]string{"body": "invalid-payload"})
	}
	return nil
}

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
