package auth

import (
	"encoding/base64"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

var (
	sealedRe = regexp.MustCompile(`^a1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$`)
	codeRe   = regexp.MustCompile(`^\d{6}$`)
)

const (
	maxSealedLen = 512
	maxEmailLen  = 254
	maxNameLen   = 80
)

var platforms = map[string]bool{"linux": true, "windows": true, "android": true, "web": true}

// validEmail acepta solo direcciones simples (sin nombre ni comentarios).
func validEmail(s string) bool {
	if len(s) < 3 || len(s) > maxEmailLen || strings.ContainsAny(s, " \r\n\t<>") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && strings.Contains(s[strings.LastIndex(s, "@"):], ".")
}

func validUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == strings.ToLower(s)
}

// validateRegister devuelve campo → código de validación (vacío si todo está bien).
func validateRegister(r *RegisterRequest) map[string]string {
	f := map[string]string{}
	if !validUUID(r.UserID) {
		f["userId"] = "required"
	}
	name := strings.TrimSpace(r.FullName)
	switch {
	case utf8.RuneCountInString(name) < 2:
		f["fullName"] = "name-too-short"
	case utf8.RuneCountInString(name) > maxNameLen:
		f["fullName"] = "name-too-long"
	}
	if !validEmail(security.NormalizeEmail(r.Email)) {
		f["email"] = "invalid-email"
	}
	if !r.AcceptedTerms {
		f["acceptedTerms"] = "terms-required"
	}
	if !security.ValidAuthKey(r.AuthKey) {
		f["authKey"] = "required"
	}
	if !security.ValidAuthKey(r.RecoveryAuth) {
		f["recoveryAuth"] = "required"
	}
	if r.AuthKey != "" && r.AuthKey == r.RecoveryAuth {
		f["recoveryAuth"] = "invalid-payload"
	}
	if code := validateKeys(&r.Keys); code != "" {
		f["keys"] = code
	}
	return f
}

// validateKeys comprueba la forma del paquete de claves (el servidor no puede comprobar nada más).
func validateKeys(k *KeyBundle) string {
	d := k.Kdf
	if d.Alg != "argon2id" || d.MemoryKiB < 1024 || d.MemoryKiB > 256*1024 ||
		d.Iterations < 1 || d.Iterations > 10 || d.Parallelism < 1 || d.Parallelism > 16 {
		return "invalid-payload"
	}
	salt, err := base64.RawURLEncoding.DecodeString(d.Salt)
	if err != nil || len(salt) != 16 {
		return "invalid-payload"
	}
	for _, s := range []string{k.WrappedMasterKey, k.RecoveryWrappedMasterKey} {
		if len(s) > maxSealedLen || !sealedRe.MatchString(s) {
			return "invalid-payload"
		}
	}
	return ""
}

func cleanDevice(d *DeviceInfo) DeviceInfo {
	out := DeviceInfo{Name: "Navegador", Platform: "web"}
	if d == nil {
		return out
	}
	if n := strings.TrimSpace(d.Name); n != "" {
		if utf8.RuneCountInString(n) > 100 {
			n = string([]rune(n)[:100])
		}
		out.Name = n
	}
	if platforms[d.Platform] {
		out.Platform = d.Platform
	}
	return out
}

func trimSpace(s string) string { return strings.TrimSpace(s) }
