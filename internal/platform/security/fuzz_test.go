package security

import (
	"testing"
	"time"
)

// FuzzVerifyStoredHash: un hash guardado corrupto o malicioso nunca provoca pánico ni agota memoria.
func FuzzVerifyStoredHash(f *testing.F) {
	h, _ := NewAuthKeyHasher([]byte("0123456789abcdef0123456789abcdef-pepper"))
	good, _ := h.Hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add(good)
	f.Add([]byte("$argon2id$v=19$m=999999999,t=999,p=255$AAAA$BBBB"))
	f.Add([]byte("$argon2id$v=19$m=19456,t=2,p=1$"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, stored []byte) {
		ok, _ := h.Verify(stored, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if ok && string(stored) != string(good) {
			// Otro hash válido de la misma clave también puede verificar; solo se exige no entrar en pánico.
			return
		}
	})
}

func FuzzJWTParse(f *testing.F) {
	const uid, did = "01a119d2-bc8e-7d83-b461-8de8e246853f", "01a119d2-bc8e-7d83-b461-8de8e246853e"
	secret := []byte("0123456789abcdef0123456789abcdef-pepper")
	s, _ := NewSigner(SignerOptions{Secret: secret, Issuer: "t", TTL: time.Hour})
	tok, _, _ := s.Issue(uid, did)
	f.Add(tok)
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, token string) {
		// Sin pánico, y lo que se acepta solo puede ser un token firmado por nosotros (con nuestras
		// reclamaciones). Variaciones inocuas de la codificación de la firma pueden seguir validando.
		if c, err := s.Parse(token); err == nil && (c.UserID != uid || c.DeviceID != did) {
			t.Fatalf("aceptó un token con reclamaciones ajenas: %q → %+v", token, c)
		}
	})
}
