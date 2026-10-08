package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// RandomToken devuelve n bytes aleatorios en base64url (sin relleno).
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken es el SHA-256 de un token de alta entropía (p. ej. el de renovación). Solo se guarda
// el hash: un volcado de la base de datos no permite usar los tokens.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NumericCode genera un código decimal de `digits` cifras, uniforme y con ceros a la izquierda.
func NumericCode(digits int) (string, error) {
	if digits < 4 || digits > 12 {
		return "", fmt.Errorf("security: dígitos fuera de rango")
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n), nil
}

// HashCode liga un código corto a su finalidad y a la cuenta con HMAC (con el pepper): un código
// de verificación de correo no sirve para restablecer la contraseña ni para otra cuenta.
func HashCode(pepper []byte, purpose, subject, code string) []byte {
	m := hmac.New(sha256.New, DeriveKey(pepper, "code"))
	m.Write([]byte(strings.Join([]string{purpose, subject, code}, "\x00")))
	return m.Sum(nil)
}

// Equal compara en tiempo constante.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// DeriveKey deriva una subclave del pepper con separación de dominio (etiqueta): lo derivado para
// una finalidad nunca coincide con lo de otra.
func DeriveKey(pepper []byte, label string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte("apunte/v1/" + label))
	return m.Sum(nil)
}
