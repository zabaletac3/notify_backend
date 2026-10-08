package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnv carga un archivo `.env` (si existe) en el entorno del proceso, para el desarrollo local.
//
// Reglas, a propósito mínimas y sin sorpresas:
//   - `CLAVE=valor` por línea; las líneas vacías y las que empiezan por `#` se ignoran.
//   - Un comentario al final solo cuenta si va precedido de un espacio (`valor  # nota`), así que los
//     secretos pueden contener `#`, `$`, `&`, `;`, `|` o comillas sin que se interpreten.
//   - Sin expansión de variables (`$x` se queda tal cual) y sin comillas: el valor es literal.
//   - Lo que ya está en el entorno manda: el archivo nunca lo pisa (así los contenedores y la CI no cambian).
//
// Un archivo inexistente no es un error. Nunca se registra su contenido.
func LoadDotEnv(path string) error {
	f, err := os.Open(path) //nolint:gosec // ruta fija elegida por quien arranca el proceso
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("config: no se pudo abrir %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return fmt.Errorf("config: %s línea %d: se esperaba CLAVE=valor", path, n)
		}
		value = stripComment(strings.TrimSpace(value))
		if _, set := os.LookupEnv(key); set {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("config: %s línea %d: %w", path, n, err)
		}
	}
	return sc.Err()
}

// stripComment quita un comentario final (`  # nota`) que empiece tras un espacio o tabulación.
func stripComment(v string) string {
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}
