package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	const secret = `QKTLrH|g[^E4cV-?}E3}$Ac>+MP!n$G/pR:*J&x;y"z'`
	path := filepath.Join(t.TempDir(), ".env")
	body := "# comentario\n\nAPP_ENV=dev                 # dev | qa | prod\nDOTENV_SECRET=" + secret + "\nexport DOTENV_EXPORTED=si\nDOTENV_KEEP=archivo\nDOTENV_EMPTY=\nDOTENV_HASH=a#b\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOTENV_KEEP", "entorno")
	t.Setenv("APP_ENV", "") // se restaura al terminar; la prueba la quita para que el archivo la fije
	_ = os.Unsetenv("APP_ENV")
	for _, k := range []string{"DOTENV_SECRET", "DOTENV_EXPORTED", "DOTENV_EMPTY", "DOTENV_HASH"} {
		t.Cleanup(func() { _ = os.Unsetenv(k) })
	}

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"APP_ENV": "dev", "DOTENV_SECRET": secret, "DOTENV_EXPORTED": "si",
		"DOTENV_KEEP": "entorno", "DOTENV_EMPTY": "", "DOTENV_HASH": "a#b",
	} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestLoadDotEnvMissingAndMalformed(t *testing.T) {
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "no-existe")); err != nil {
		t.Fatalf("archivo inexistente no es error: %v", err)
	}
	bad := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(bad, []byte("esto no es una asignación\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadDotEnv(bad); err == nil {
		t.Fatal("una línea sin = debe fallar")
	}
}
