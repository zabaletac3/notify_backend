// Package config carga y valida la configuración desde variables de entorno.
// Falla cerrado: sin secretos válidos la API no arranca.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

const minSecretLen = 32

type Config struct {
	Env         string `env:"APP_ENV" envDefault:"dev"` // dev | qa | prod
	ServiceName string `env:"APP_NAME" envDefault:"apunte-api"`
	Port        int    `env:"PORT" envDefault:"8080"`
	LogLevel    string `env:"LOG_LEVEL" envDefault:"info"`

	DatabaseURL string `env:"DATABASE_URL,required,notEmpty"`

	// Secretos (≥ 32 caracteres). El pepper endurece el hash de authKey (fase 2).
	JWTSecret string `env:"JWT_SECRET,required,notEmpty"`
	// Secreto anterior: solo durante una rotación (los tokens firmados con él valen hasta caducar).
	JWTSecretPrevious string        `env:"JWT_SECRET_PREVIOUS"`
	JWTIssuer         string        `env:"JWT_ISSUER" envDefault:"apunte-api"`
	AccessTTL         time.Duration `env:"ACCESS_TTL" envDefault:"15m"`
	RefreshTTL        time.Duration `env:"REFRESH_TTL" envDefault:"720h"`
	Pepper            string        `env:"PEPPER,required,notEmpty"`

	// Dirección pública de la web: los enlaces de los correos (restablecer contraseña) apuntan aquí.
	WebBaseURL string `env:"WEB_BASE_URL" envDefault:"http://localhost:5173"`

	// Orígenes permitidos por CORS (lista separada por comas, sin comodines).
	AllowedOrigins []string `env:"ALLOWED_ORIGINS" envSeparator:","`

	// TrustProxy: la API va detrás de Caddy, que añade la IP real al final de X-Forwarded-For.
	// Con false (dev) se usa la dirección de la conexión y se ignora la cabecera.
	TrustProxy bool `env:"TRUST_PROXY" envDefault:"false"`

	MaxBodyBytes    int64         `env:"MAX_BODY_BYTES" envDefault:"1048576"`
	ReadTimeout     time.Duration `env:"READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout    time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`

	Mail MailConfig
}

// MailConfig elige el adaptador de correo. Cambiar de proveedor es cambiar
// MAIL_PROVIDER (y su clave): el resto de la app solo conoce la interfaz.
type MailConfig struct {
	Provider     string `env:"MAIL_PROVIDER" envDefault:"log"` // log | resend
	From         string `env:"MAIL_FROM" envDefault:"Apunte <no-reply@localhost>"`
	ResendAPIKey string `env:"RESEND_API_KEY"`
}

// Load lee el entorno y valida.
func Load() (*Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.Env = strings.ToLower(c.Env)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) IsProd() bool { return c.Env == "prod" }

// Validate aplica las reglas de seguridad de la configuración.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }

	switch c.Env {
	case "dev", "qa", "prod":
	default:
		add("APP_ENV debe ser dev, qa o prod")
	}
	if len(c.JWTSecret) < minSecretLen {
		add("JWT_SECRET debe tener al menos %d caracteres", minSecretLen)
	}
	if len(c.Pepper) < minSecretLen {
		add("PEPPER debe tener al menos %d caracteres", minSecretLen)
	}
	if c.JWTSecret != "" && c.JWTSecret == c.Pepper {
		add("JWT_SECRET y PEPPER deben ser distintos")
	}
	if c.JWTSecretPrevious != "" {
		if len(c.JWTSecretPrevious) < minSecretLen {
			add("JWT_SECRET_PREVIOUS debe tener al menos %d caracteres", minSecretLen)
		}
		if c.JWTSecretPrevious == c.JWTSecret || c.JWTSecretPrevious == c.Pepper {
			add("JWT_SECRET_PREVIOUS debe ser distinto de JWT_SECRET y PEPPER")
		}
	}
	if c.AccessTTL <= 0 || c.AccessTTL > time.Hour {
		add("ACCESS_TTL debe estar entre 1 ns y 1 h")
	}
	if c.RefreshTTL < c.AccessTTL || c.RefreshTTL > 90*24*time.Hour {
		add("REFRESH_TTL debe ser mayor que ACCESS_TTL y como máximo 90 días")
	}
	if c.Port < 1 || c.Port > 65535 {
		add("PORT fuera de rango")
	}
	if c.MaxBodyBytes < 1 {
		add("MAX_BODY_BYTES debe ser positivo")
	}
	for _, o := range c.AllowedOrigins {
		if o == "*" {
			add("ALLOWED_ORIGINS no admite comodines")
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
			add("ALLOWED_ORIGINS contiene un origen no válido: %q", o)
		}
	}

	switch c.Mail.Provider {
	case "log":
		if c.IsProd() {
			add("MAIL_PROVIDER=log no está permitido en prod")
		}
	case "resend":
		if c.Mail.ResendAPIKey == "" {
			add("RESEND_API_KEY es obligatoria con MAIL_PROVIDER=resend")
		}
	default:
		add("MAIL_PROVIDER desconocido: %q", c.Mail.Provider)
	}
	if !validWebBase(c.WebBaseURL, c.IsProd()) {
		add("WEB_BASE_URL no es válida (en prod debe ser https y sin ruta)")
	}
	if c.IsProd() {
		if len(c.AllowedOrigins) == 0 {
			add("ALLOWED_ORIGINS es obligatoria en prod")
		}
		for _, o := range c.AllowedOrigins {
			if !strings.HasPrefix(o, "https://") {
				add("en prod los orígenes deben ser https: %q", o)
			}
		}
	}
	return errors.Join(errs...)
}

// validWebBase: URL base de la web, sin ruta ni consulta; https obligatorio en prod.
func validWebBase(raw string, prod bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && !prod)
}
