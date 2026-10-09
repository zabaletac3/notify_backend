// Package config carga y valida la configuración desde variables de entorno.
// Falla cerrado: sin secretos válidos la API no arranca.
package config

import (
	"errors"
	"fmt"
	"net/mail"
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

	// CookieSecure: la cookie de sesión web (modo cookie) lleva `Secure`. Por defecto `true`; solo
	// en dev vale `false` si no se indica. En qa/prod no puede ser `false`.
	CookieSecure *bool `env:"COOKIE_SECURE"`
	// CookieDomain: dominio de la cookie de sesión; vacío = solo el host de la API (host-only).
	CookieDomain string `env:"COOKIE_DOMAIN"`

	// TrustProxy: la API va detrás de Caddy, que añade la IP real al final de X-Forwarded-For.
	// Con false (dev) se usa la dirección de la conexión y se ignora la cabecera.
	TrustProxy bool `env:"TRUST_PROXY" envDefault:"false"`

	MaxBodyBytes int64 `env:"MAX_BODY_BYTES" envDefault:"1048576"`
	// Límites de /sync: tamaño del cuerpo y cantidad de elementos por cuenta.
	MaxSyncBodyBytes int64 `env:"MAX_SYNC_BODY_BYTES" envDefault:"8388608"`
	MaxSyncChanges   int   `env:"MAX_SYNC_CHANGES" envDefault:"500"`
	MaxRemote        int   `env:"MAX_SYNC_REMOTE_CHANGES" envDefault:"500"`   // elementos por página al bajar cambios
	RemoteBytes      int64 `env:"MAX_SYNC_REMOTE_BYTES" envDefault:"8388608"` // bytes cifrados por página
	MaxNotes         int   `env:"MAX_NOTES_PER_ACCOUNT" envDefault:"10000"`
	QuotaBytes       int64 `env:"QUOTA_BYTES" envDefault:"1073741824"` // 1 GiB de textos cifrados por cuenta
	MaxFolders       int   `env:"MAX_FOLDERS_PER_ACCOUNT" envDefault:"500"`

	ReadTimeout     time.Duration `env:"READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout    time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`

	Mail   MailConfig
	Google GoogleConfig
}

// MailConfig elige el adaptador de correo. Cambiar de proveedor es cambiar
// MAIL_PROVIDER (y su clave): el resto de la app solo conoce la interfaz.
type MailConfig struct {
	Provider     string `env:"MAIL_PROVIDER" envDefault:"log"` // log | resend | smtp
	From         string `env:"MAIL_FROM" envDefault:"AxoNote <no-reply@localhost>"`
	ResendAPIKey string `env:"RESEND_API_KEY"`
	// SMTP (MAIL_PROVIDER=smtp). Puerto 465 = TLS implícito; otro (587) = STARTTLS obligatorio.
	SMTPHost     string `env:"SMTP_HOST"`
	SMTPPort     int    `env:"SMTP_PORT" envDefault:"587"`
	SMTPUser     string `env:"SMTP_USER"`
	SMTPPassword string `env:"SMTP_PASSWORD"`
}

// GoogleConfig elige el proveedor de identidad de Google. `off` deja las rutas activas pero
// deshabilitadas (responden 403); `google` usa el OAuth real; `fake` solo vale en dev para pruebas.
type GoogleConfig struct {
	Provider     string `env:"GOOGLE_PROVIDER" envDefault:"off"` // off | google | fake
	ClientID     string `env:"GOOGLE_CLIENT_ID"`
	ClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	RedirectURL  string `env:"GOOGLE_REDIRECT_URL"`
}

// Load lee el entorno y valida.
func Load() (*Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.Env = strings.ToLower(c.Env)
	if c.CookieSecure == nil {
		secure := c.Env != "dev" // dev permite http://localhost; qa/prod siempre Secure
		c.CookieSecure = &secure
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) IsProd() bool { return c.Env == "prod" }

// SecureCookie indica si la cookie de sesión web debe llevar el atributo `Secure`.
func (c *Config) SecureCookie() bool { return c.CookieSecure != nil && *c.CookieSecure }

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
	if c.MaxSyncBodyBytes < c.MaxBodyBytes || c.MaxSyncChanges < 1 || c.MaxNotes < 1 || c.MaxFolders < 1 || c.MaxRemote < 1 || c.RemoteBytes < 1<<16 || c.QuotaBytes < 1<<20 {
		add("los límites de sincronización no son válidos")
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
	if c.CookieDomain != "" && !validCookieDomain(c.CookieDomain) {
		add("COOKIE_DOMAIN no es un dominio válido: %q", c.CookieDomain)
	}
	if c.Env == "qa" || c.Env == "prod" {
		if !c.SecureCookie() {
			add("COOKIE_SECURE no puede ser false en %s", c.Env)
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
	case "smtp":
		if c.Mail.SMTPHost == "" || c.Mail.SMTPUser == "" || c.Mail.SMTPPassword == "" {
			add("SMTP_HOST, SMTP_USER y SMTP_PASSWORD son obligatorias con MAIL_PROVIDER=smtp")
		}
		if c.Mail.SMTPPort < 1 || c.Mail.SMTPPort > 65535 {
			add("SMTP_PORT no es válido")
		}
		if _, err := mail.ParseAddress(c.Mail.From); err != nil {
			add("MAIL_FROM no es una dirección válida")
		}
	default:
		add("MAIL_PROVIDER desconocido: %q", c.Mail.Provider)
	}
	if !validWebBase(c.WebBaseURL, c.IsProd()) {
		add("WEB_BASE_URL no es válida (en prod debe ser https y sin ruta)")
	}
	switch c.Google.Provider {
	case "off": // sin proveedor: rutas deshabilitadas, la API arranca igual
	case "google":
		if c.Google.ClientID == "" || c.Google.ClientSecret == "" || c.Google.RedirectURL == "" {
			add("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET y GOOGLE_REDIRECT_URL son obligatorias con GOOGLE_PROVIDER=google")
		}
		if c.Google.RedirectURL != "" && !validRedirectURL(c.Google.RedirectURL, c.Env == "dev") {
			add("GOOGLE_REDIRECT_URL no es válida (en qa/prod debe ser https con host)")
		}
	case "fake":
		if c.Env != "dev" {
			add("GOOGLE_PROVIDER=fake solo se admite con APP_ENV=dev")
		}
	default:
		add("GOOGLE_PROVIDER desconocido: %q", c.Google.Provider)
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

// validRedirectURL: la URI de redirección de Google; https obligatorio fuera de dev.
func validRedirectURL(raw string, dev bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && dev)
}

// validCookieDomain acepta un dominio de cookie (con o sin punto inicial) sin esquema, puerto ni ruta.
func validCookieDomain(raw string) bool {
	s := strings.TrimPrefix(raw, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			ok := ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
			if !ok || (ch == '-' && (i == 0 || i == len(label)-1)) {
				return false
			}
		}
	}
	return true
}
