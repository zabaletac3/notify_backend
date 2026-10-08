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
		"mail desconocido": func(t *testing.T) { t.Setenv("MAIL_PROVIDER", "smtp") },
		"resend sin clave": func(t *testing.T) { t.Setenv("MAIL_PROVIDER", "resend") },
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
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
