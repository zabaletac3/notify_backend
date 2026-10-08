package notesync

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

// PrincipalFunc extrae la cuenta y el dispositivo autenticados del contexto de la petición.
// Lo aporta el módulo auth, que también protege las rutas con su middleware.
type PrincipalFunc func(ctx context.Context) (userID, deviceID string, ok bool)

type Handler struct {
	svc       *Service
	log       *slog.Logger
	principal PrincipalFunc
}

func NewHandler(svc *Service, log *slog.Logger, principal PrincipalFunc) *Handler {
	return &Handler{svc: svc, log: log, principal: principal}
}

// Routes monta las rutas; deben colgar de un grupo que ya exija autenticación.
func (h *Handler) Routes(r chi.Router) {
	r.Post("/sync", h.sync)
	r.Get("/notes", h.listNotes)
	r.Get("/notes/{noteId}", h.getNote)
	r.Get("/folders", h.listFolders)
}

func (h *Handler) who(r *http.Request) (Principal, error) {
	u, d, ok := h.principal(r.Context())
	if !ok {
		return Principal{}, apperrors.SessionExpired()
	}
	return Principal{UserID: u, DeviceID: d}, nil
}

func (h *Handler) sync(w http.ResponseWriter, r *http.Request) {
	p, err := h.who(r)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	var req Request
	if err := httpserver.DecodeJSON(r, &req); err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	res, err := h.svc.Sync(r.Context(), p, &req)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, res)
}

func (h *Handler) listNotes(w http.ResponseWriter, r *http.Request) {
	p, err := h.who(r)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	q := NotesQuery{Cursor: r.URL.Query().Get("cursor")}
	bad := map[string]string{}
	if v := r.URL.Query().Get("trashed"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			bad["trashed"] = "invalid-payload"
		}
		q.Trashed = &b
	}
	if v := r.URL.Query().Get("updatedSince"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			bad["updatedSince"] = "invalid-payload"
		}
		q.UpdatedSince = &t
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			bad["limit"] = "invalid-payload"
		}
		q.Limit = n
	}
	if len(bad) > 0 {
		response.Error(w, r, h.log, apperrors.Validation(bad))
		return
	}
	page, err := h.svc.ListNotes(r.Context(), p, q)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, page)
}

func (h *Handler) getNote(w http.ResponseWriter, r *http.Request) {
	p, err := h.who(r)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	n, err := h.svc.GetNote(r.Context(), p, chi.URLParam(r, "noteId"))
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, n)
}

func (h *Handler) listFolders(w http.ResponseWriter, r *http.Request) {
	p, err := h.who(r)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	list, err := h.svc.ListFolders(r.Context(), p)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, list)
}
