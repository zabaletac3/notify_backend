// Command purge ejecuta la limpieza diaria (cron). Usa PURGE_DATABASE_URL: un rol de mantenimiento
// distinto del de la API (miembro de apunte_maint). Código de salida distinto de 0 si algo falla.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/zabaletac3/notify_backend/internal/jobs/purge"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envDays(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 3650 {
		return 0, fmt.Errorf("%s debe ser un número de días entre 1 y 3650", name)
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

func run() error {
	url := os.Getenv("PURGE_DATABASE_URL")
	if url == "" {
		return fmt.Errorf("falta PURGE_DATABASE_URL")
	}
	cfg := purge.Defaults()
	var err error
	if cfg.TrashRetention, err = envDays("TRASH_RETENTION_DAYS", cfg.TrashRetention); err != nil {
		return err
	}
	if cfg.AccountGrace, err = envDays("ACCOUNT_GRACE_DAYS", cfg.AccountGrace); err != nil {
		return err
	}
	if cfg.AuditRetention, err = envDays("AUDIT_RETENTION_DAYS", cfg.AuditRetention); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("job", "purge")
	pool, err := database.Connect(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	rep, err := purge.Run(ctx, pool, cfg, log)
	log.Info("purga terminada", "resumen", rep.String())
	ping(log, os.Getenv("PURGE_PING_URL"), err == nil)
	return err
}

// ping avisa a un servicio de «latido» (healthchecks.io, Better Stack…): si la purga no avisa a tiempo o
// avisa un fallo, el servicio manda el correo de alerta. Sin URL no hace nada. Un fallo al avisar no
// cambia el resultado de la purga.
func ping(log *slog.Logger, base string, ok bool) {
	if base == "" {
		return
	}
	url := base
	if !ok {
		url = strings.TrimRight(base, "/") + "/fail"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		log.Warn("URL de latido no válida")
		return
	}
	//nolint:gosec // la URL la fija quien opera el servidor (variable de entorno), no una persona usuaria
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Warn("URL de latido no válida")
		return
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // idem
	if err != nil {
		log.Warn("no se pudo avisar al servicio de latido")
		return
	}
	_ = resp.Body.Close()
}
