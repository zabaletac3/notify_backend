package config

import (
	"strings"
	"testing"
)

const (
	secretA = "a-very-long-secret-with-more-than-32-chars"
	secretB = "another-very-long-secret-more-than-32-chars"
)

func setValid(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("JWT_SECRET", secretA)
	t.Setenv("PEPPER", secretB)
}

func setSMTP(t *testing.T) {
	t.Helper()
	t.Setenv("MAIL_PROVIDER", "smtp")
	t.Setenv("SMTP_HOST", "smtp.gmail.com")
	t.Setenv("SMTP_USER", "ana@gmail.com")
	t.Setenv("SMTP_PASSWORD", "app-password")
	t.Setenv("MAIL_FROM", "Apunte <ana@gmail.com>")
}

func TestSMTPValid(t *testing.T) {
	setValid(t)
	setSMTP(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mail.SMTPPort != 587 {
		t.Fatalf("el puerto por defecto debe ser 587: %d", c.Mail.SMTPPort)
	}
	t.Setenv("APP_ENV", "prod")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("WEB_BASE_URL", "https://app.example.com")
	if _, err := Load(); err != nil {
		t.Fatalf("prod debe admitir smtp: %v", err)
	}
}

func TestLoadValid(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 8080 || c.Mail.Provider != "log" {
		t.Fatalf("valores por defecto inesperados: %+v", c)
	}
}

func TestLoadFailsClosed(t *testing.T) {
	cases := map[string]func(*testing.T){
		"sin DATABASE_URL": func(t *testing.T) { t.Setenv("DATABASE_URL", "") },
		"secreto corto":    func(t *testing.T) { t.Setenv("JWT_SECRET", "corto") },
		"pepper corto":     func(t *testing.T) { t.Setenv("PEPPER", "corto") },
		"secretos iguales": func(t *testing.T) { t.Setenv("PEPPER", secretA) },
		"env inválido":     func(t *testing.T) { t.Setenv("APP_ENV", "staging") },
		"origen comodín":   func(t *testing.T) { t.Setenv("ALLOWED_ORIGINS", "*") },
		"origen con ruta":  func(t *testing.T) { t.Setenv("ALLOWED_ORIGINS", "https://a.com/x") },
		"previo corto":     func(t *testing.T) { t.Setenv("JWT_SECRET_PREVIOUS", "corto") },
		"previo igual":     func(t *testing.T) { t.Setenv("JWT_SECRET_PREVIOUS", secretA) },
		"access largo":     func(t *testing.T) { t.Setenv("ACCESS_TTL", "3h") },
		"refresh corto":    func(t *testing.T) { t.Setenv("REFRESH_TTL", "1m") },
		"web sin esquema":  func(t *testing.T) { t.Setenv("WEB_BASE_URL", "app.example.com") },
		"web con consulta": func(t *testing.T) { t.Setenv("WEB_BASE_URL", "https://app.example.com/?x=1") },
		"mail desconocido": func(t *testing.T) { t.Setenv("MAIL_PROVIDER", "sendgrid") },
		"resend sin clave": func(t *testing.T) { t.Setenv("MAIL_PROVIDER", "resend") },
		"smtp sin datos":   func(t *testing.T) { t.Setenv("MAIL_PROVIDER", "smtp") },
		"smtp puerto malo": func(t *testing.T) { setSMTP(t); t.Setenv("SMTP_PORT", "70000") },
		"smtp from malo":   func(t *testing.T) { setSMTP(t); t.Setenv("MAIL_FROM", "no es una dirección") },
		"dominio cookie":   func(t *testing.T) { t.Setenv("COOKIE_DOMAIN", "http://x") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			setValid(t)
			mutate(t)
			if _, err := Load(); err == nil {
				t.Fatal("debía fallar")
			}
		})
	}
}

func TestProdRules(t *testing.T) {
	setValid(t)
	t.Setenv("APP_ENV", "prod")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MAIL_PROVIDER=log") {
		t.Fatalf("prod no debe admitir el correo en log: %v", err)
	}
	t.Setenv("MAIL_PROVIDER", "resend")
	t.Setenv("RESEND_API_KEY", "re_test")
	t.Setenv("ALLOWED_ORIGINS", "http://app.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("prod exige orígenes https")
	}
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("WEB_BASE_URL", "http://app.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("prod exige que la web sea https")
	}
	t.Setenv("WEB_BASE_URL", "https://app.example.com")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}

func TestCookieSecureDefaultsByEnv(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.SecureCookie() {
		t.Fatal("en dev, sin COOKIE_SECURE, la cookie no debe ser Secure")
	}

	setValid(t)
	t.Setenv("APP_ENV", "prod")
	t.Setenv("MAIL_PROVIDER", "resend")
	t.Setenv("RESEND_API_KEY", "re_test")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("WEB_BASE_URL", "https://app.example.com")
	if c, err := Load(); err != nil || !c.SecureCookie() {
		t.Fatalf("en prod la cookie debe ser Secure por defecto: %v %v", err, c)
	}
}

func TestCookieSecureValidation(t *testing.T) {
	cfg := func(env string, secure bool) *Config {
		s := secure
		return &Config{Env: env, CookieSecure: &s}
	}
	for _, env := range []string{"prod", "qa"} {
		if err := cfg(env, false).Validate(); err == nil || !strings.Contains(err.Error(), "COOKIE_SECURE") {
			t.Fatalf("%s debe rechazar COOKIE_SECURE=false: %v", env, err)
		}
	}
	if err := cfg("dev", false).Validate(); err != nil && strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Fatalf("dev no debe exigir COOKIE_SECURE: %v", err)
	}
	if err := cfg("prod", true).Validate(); err != nil && strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Fatalf("prod con COOKIE_SECURE=true no debe fallar por cookie: %v", err)
	}
}
