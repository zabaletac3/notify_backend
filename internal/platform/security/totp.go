package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 exige HMAC-SHA-1; no es un uso de resistencia a colisiones
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ── TOTP (RFC 6238) ─────────────────────────────────────────────

const (
	totpDigits = 6
	totpPeriod = 30 // segundos
)

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret genera un secreto TOTP nuevo: 20 bytes aleatorios, devueltos en crudo y en base32 sin
// relleno (el formato que espera la URI otpauth).
func NewTOTPSecret() (raw []byte, base32secret string, err error) {
	raw = make([]byte, 20)
	if _, err = rand.Read(raw); err != nil {
		return nil, "", err
	}
	return raw, totpB32.EncodeToString(raw), nil
}

// TOTPCode calcula el código TOTP de 6 dígitos para un paso concreto (RFC 6238 sobre HOTP, RFC 4226).
func TOTPCode(secret []byte, step int64) string {
	if step < 0 {
		step = 0 // los pasos no negativos son los únicos válidos (el reloj Unix nunca da menos)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret) //nolint:gosec // RFC 6238 exige HMAC-SHA-1
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000)
}

// VerifyTOTP comprueba un código de 6 dígitos contra la ventana ±1 paso. Devuelve el paso aceptado para
// que el llamante lo fije como `last_step` (anti-reutilización: se rechaza cualquier paso <= lastStep).
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (step int64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, d := range code {
		if d < '0' || d > '9' {
			return 0, false
		}
	}
	t := now.Unix() / totpPeriod
	for _, delta := range []int64{-1, 0, 1} {
		candidate := t + delta
		if candidate <= lastStep || candidate < 0 {
			continue
		}
		expected := TOTPCode(secret, candidate)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

// OTPAuthURI arma la URI otpauth:// que el cliente convierte en QR (en el propio navegador, nunca en un
// servicio externo).
func OTPAuthURI(issuer, account, base32secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", base32secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ── Cifrado del secreto TOTP ────────────────────────────────────

const totpAADPrefix = "apunte/v1/totp/"

// SealTOTP cifra el secreto con AES-256-GCM y una clave derivada del pepper (S4). Los datos asociados
// ligan el texto a la cuenta. Formato: `t1.<nonce b64url>.<ct b64url>`.
func SealTOTP(pepper []byte, userID string, secret []byte) (string, error) {
	block, err := aes.NewCipher(DeriveKey(pepper, "totp-enc"))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, secret, []byte(totpAADPrefix+userID))
	return "t1." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

// OpenTOTP descifra un secreto sellado con SealTOTP. Falla si el texto o los datos asociados no cuadran.
func OpenTOTP(pepper []byte, userID, sealed string) ([]byte, error) {
	parts := strings.Split(sealed, ".")
	if len(parts) != 3 || parts[0] != "t1" {
		return nil, fmt.Errorf("security: secreto TOTP mal formado")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(DeriveKey(pepper, "totp-enc"))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, []byte(totpAADPrefix+userID))
}

// ── Códigos de respaldo ─────────────────────────────────────────

// recoveryAlphabet excluye caracteres ambiguos (0/O, 1/I/L, U/V).
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

// NewRecoveryCodes genera n códigos de 10 caracteres mostrados como `XXXXX-XXXXX`, uniformes (sin sesgo
// de módulo) y con crypto/rand.
func NewRecoveryCodes(n int) ([]string, error) {
	if n < 1 {
		return nil, fmt.Errorf("security: número de códigos inválido")
	}
	out := make([]string, 0, n)
	code := make([]byte, 10)
	for len(out) < n {
		i := 0
		for i < len(code) {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, err
			}
			// 240 = 8 * 30: rechaza el resto para no sesgar el módulo.
			if int(b[0]) >= 240 {
				continue
			}
			code[i] = recoveryAlphabet[int(b[0])%len(recoveryAlphabet)]
			i++
		}
		out = append(out, string(code[:5])+"-"+string(code[5:]))
	}
	return out, nil
}

// NormalizeRecoveryCode valida y normaliza un código de respaldo: mayúsculas, sin espacios ni guiones,
// alfabeto permitido y longitud exacta. Devuelve el código normalizado y si es válido.
func NormalizeRecoveryCode(s string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r == ' ' || r == '-' || r == '\t' {
			continue
		}
		if !strings.ContainsRune(recoveryAlphabet, r) {
			return "", false
		}
		b.WriteRune(r)
	}
	if b.Len() != 10 {
		return "", false
	}
	return b.String(), true
}
