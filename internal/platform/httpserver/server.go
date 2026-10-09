// Package httpserver monta el router, los middlewares y el servidor HTTP.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/config"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

// Pinger comprueba una dependencia (la base de datos) para /ready.
type Pinger interface {
	Ping(ctx context.Context) error
}

// NewRouter arma el router base. Los módulos montan sus rutas sobre él (fases siguientes).
func NewRouter(cfg *config.Config, log *slog.Logger, db Pinger, modules ...func(chi.Router)) *chi.Mux {
	r := chi.NewRouter()
	r.Use(TraceID, Recover(log), Logging(log), SecurityHeaders, MaxBody(cfg.MaxBodyBytes, map[string]int64{"/v1/sync": cfg.MaxSyncBodyBytes}))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "x-trace-id", "X-AxoNote-Session"},
		ExposedHeaders:   []string{"x-trace-id"},
		AllowCredentials: true, // modo cookie: la web envía la cookie de refresco (nunca con origen comodín)
		MaxAge:           600,
	}))

	r.Get("/health", Live)
	r.Get("/ready", Ready(db))

	r.Route("/v1", func(v1 chi.Router) {
		for _, mount := range modules {
			mount(v1)
		}
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		response.Error(w, r, nil, apperrors.NotFound(""))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		response.Error(w, r, nil, &apperrors.Error{Kind: apperrors.KindValidation, Status: http.StatusMethodNotAllowed, Fields: map[string]string{"method": "invalid-payload"}})
	})
	return r
}

// New devuelve un servidor con tiempos límite (evita conexiones lentas que agotan recursos).
func New(cfg *config.Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// Serve arranca y se detiene con gracia al cancelarse ctx.
func Serve(ctx context.Context, srv *http.Server, shutdown time.Duration) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), shutdown)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}
