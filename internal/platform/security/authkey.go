// Package security reúne las primitivas de seguridad del servidor: hash de la prueba de contraseña,
// tokens, códigos, JWT y derivaciones con dominio separado. No conoce HTTP ni la base de datos.
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parámetros de Argon2id del lado servidor (mínimo recomendado por OWASP). La authKey ya llega
// derivada con Argon2id en el cliente; esta capa protege ante el robo de la base de datos.
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16

	maxAcceptedMemoryKiB = 256 * 1024 // tope al leer parámetros guardados (evita DoS por datos alterados)
	maxAcceptedTime      = 10
	minPepperLen         = 32
)

// ErrInvalidAuthKey: la authKey no tiene la forma esperada (32 bytes en base64url).
var ErrInvalidAuthKey = errors.New("security: invalid authKey")

var authKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ValidAuthKey indica si la cadena tiene la forma de una authKey.
func ValidAuthKey(s string) bool { return authKeyRe.MatchString(s) }

// AuthKeyHasher guarda y verifica la prueba de contraseña (authKey): HMAC con el pepper y después
// Argon2id con sal aleatoria. El hash se guarda codificado, con sus parámetros.
type AuthKeyHasher struct {
	pepper []byte
	dummy  []byte
}

// NewAuthKeyHasher exige un pepper de al menos 32 bytes.
func NewAuthKeyHasher(pepper []byte) (*AuthKeyHasher, error) {
	if len(pepper) < minPepperLen {
		return nil, fmt.Errorf("security: el pepper debe tener al menos %d bytes", minPepperLen)
	}
	h := &AuthKeyHasher{pepper: append([]byte(nil), pepper...)}
	// Hash de relleno para igualar el tiempo cuando la cuenta no existe.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	d, err := h.Hash(base64.RawURLEncoding.EncodeToString(b))
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

func (h *AuthKeyHasher) prehash(authKey string) []byte {
	m := hmac.New(sha256.New, h.pepper)
	m.Write([]byte(authKey))
	return m.Sum(nil)
}

// Hash devuelve el hash codificado para guardar en `users.auth_key_hash`.
func (h *AuthKeyHasher) Hash(authKey string) ([]byte, error) {
	if !ValidAuthKey(authKey) {
		return nil, ErrInvalidAuthKey
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sum := argon2.IDKey(h.prehash(authKey), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return []byte(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(sum))), nil
}

// Verify compara en tiempo constante. needsRehash indica que los parámetros guardados son más
// débiles que los actuales (conviene volver a guardar el hash tras un login correcto).
func (h *AuthKeyHasher) Verify(stored []byte, authKey string) (ok, needsRehash bool) {
	if !ValidAuthKey(authKey) {
		h.VerifyDummy(authKey)
		return false, false
	}
	mem, t, p, salt, want, err := parseHash(stored)
	if err != nil {
		h.VerifyDummy(authKey)
		return false, false
	}
	got := argon2.IDKey(h.prehash(authKey), salt, t, mem, p, uint32(len(want))) //nolint:gosec // len(want) está acotado a 16..64 en parseHash
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, mem != argonMemoryKiB || t != argonTime || p != argonThreads
}

// VerifyDummy gasta el mismo tiempo que una verificación real: se usa cuando la cuenta no existe.
func (h *AuthKeyHasher) VerifyDummy(authKey string) {
	mem, t, p, salt, want, err := parseHash(h.dummy)
	if err != nil {
		return
	}
	got := argon2.IDKey(h.prehash(authKey), salt, t, mem, p, uint32(len(want))) //nolint:gosec // len(want) está acotado a 16..64 en parseHash
	_ = subtle.ConstantTimeCompare(got, want)
}

func parseHash(encoded []byte) (mem uint32, t uint32, p uint8, salt, sum []byte, err error) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("formato")
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return 0, 0, 0, nil, nil, errors.New("versión")
	}
	var threads uint
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &threads); err != nil {
		return 0, 0, 0, nil, nil, errors.New("parámetros")
	}
	if mem < 1024 || mem > maxAcceptedMemoryKiB || t < 1 || t > maxAcceptedTime || threads < 1 || threads > 16 {
		return 0, 0, 0, nil, nil, errors.New("parámetros fuera de rango")
	}
	p = uint8(threads)
	enc := base64.RawStdEncoding
	if salt, err = enc.DecodeString(parts[4]); err != nil || len(salt) < 8 {
		return 0, 0, 0, nil, nil, errors.New("sal")
	}
	if sum, err = enc.DecodeString(parts[5]); err != nil || len(sum) < 16 || len(sum) > 64 {
		return 0, 0, 0, nil, nil, errors.New("hash")
	}
	return mem, t, p, salt, sum, nil
}
