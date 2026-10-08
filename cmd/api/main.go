// Command api arranca el servidor HTTP de Apunte.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"

	"github.com/zabaletac3/notify_backend/internal/modules/auth"
	"github.com/zabaletac3/notify_backend/internal/modules/notesync"
	"github.com/zabaletac3/notify_backend/internal/platform/config"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
	"github.com/zabaletac3/notify_backend/internal/platform/observability"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := observability.NewLogger(os.Stdout, cfg.LogLevel, cfg.ServiceName, cfg.Env)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// El correo se inyecta como interfaz: los módulos no saben qué proveedor hay detrás.
	mail, err := mailer.New(mailer.Options{
		Provider: cfg.Mail.Provider, From: cfg.Mail.From, ResendAPIKey: cfg.Mail.ResendAPIKey,
	}, log)
	if err != nil {
		return err
	}

	// Piezas de seguridad: se construyen aquí para fallar al arrancar si la configuración es mala.
	hasher, err := security.NewAuthKeyHasher([]byte(cfg.Pepper))
	if err != nil {
		return err
	}
	signer, err := security.NewSigner(security.SignerOptions{
		Secret: []byte(cfg.JWTSecret), PreviousSecret: []byte(cfg.JWTSecretPrevious),
		Issuer: cfg.JWTIssuer, TTL: cfg.AccessTTL,
	})
	if err != nil {
		return err
	}
	limiter := ratelimit.New(pool, []byte(cfg.Pepper))

	authSvc := auth.NewService(auth.Deps{
		Pool: pool, Hasher: hasher, Signer: signer, Limiter: limiter, Mailer: mail, Log: log,
		Config: auth.Config{Pepper: []byte(cfg.Pepper), AccessTTL: cfg.AccessTTL, RefreshTTL: cfg.RefreshTTL, WebBaseURL: cfg.WebBaseURL},
	})
	defer authSvc.Close() // espera a los correos en vuelo
	authHandler := auth.NewHandler(authSvc, log, cfg.TrustProxy)

	syncSvc := notesync.NewService(pool, notesync.Limits{MaxChanges: cfg.MaxSyncChanges, MaxNotes: cfg.MaxNotes, MaxFolders: cfg.MaxFolders})
	syncHandler := notesync.NewHandler(syncSvc, log, func(ctx context.Context) (string, string, bool) {
		p, ok := auth.PrincipalFrom(ctx)
		return p.UserID, p.DeviceID, ok
	})
	protected := func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(authHandler.Require)
			syncHandler.Routes(r)
		})
	}

	srv := httpserver.New(cfg, httpserver.NewRouter(cfg, log, pool, authHandler.Routes, protected))
	log.Info("api escuchando", "port", cfg.Port, "mail", cfg.Mail.Provider)
	return httpserver.Serve(ctx, srv, cfg.ShutdownTimeout)
}
