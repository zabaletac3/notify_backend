package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

// KDFParams son los parámetros de derivación de contraseña que `prelogin` entrega al cliente.
type KDFParams struct {
	Alg         string `json:"alg"`
	MemoryKiB   int    `json:"memoryKiB"`
	Iterations  int    `json:"iterations"`
	Parallelism int    `json:"parallelism"`
	Salt        string `json:"salt"`
}

// DefaultKDF coincide con los parámetros de producción del cliente (64 MiB, 3 iteraciones).
var DefaultKDF = KDFParams{Alg: "argon2id", MemoryKiB: 65536, Iterations: 3, Parallelism: 1}

// FakeKDF devuelve parámetros falsos pero estables para un correo que no existe: misma forma que los
// reales y la misma sal en cada petición, derivada de un secreto del servidor. Así `prelogin` no
// revela qué cuentas existen.
func FakeKDF(pepper []byte, email string) KDFParams {
	m := hmac.New(sha256.New, DeriveKey(pepper, "prelogin"))
	m.Write([]byte(NormalizeEmail(email)))
	p := DefaultKDF
	p.Salt = base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
	return p
}

// NormalizeEmail deja el correo en minúsculas y sin espacios en los extremos.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// HashIP devuelve un HMAC de la IP con una clave que cambia cada día: sirve para correlacionar
// eventos del mismo día sin guardar la dirección.
func HashIP(pepper []byte, ip string, day time.Time) []byte {
	key := hmac.New(sha256.New, DeriveKey(pepper, "ip"))
	key.Write([]byte(day.UTC().Format("2006-01-02")))
	m := hmac.New(sha256.New, key.Sum(nil))
	m.Write([]byte(ip))
	return m.Sum(nil)
}
