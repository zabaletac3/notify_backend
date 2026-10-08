package auth

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzValidEmail(f *testing.F) {
	for _, s := range []string{"ana@example.com", "a@b.c", "Ana <ana@example.com>", "a b@c.com", "\"a@b\"@c.com", "a@b", "", "@", "a@@b.com", "x\x00@y.com", strings.Repeat("a", 300) + "@b.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !validEmail(s) {
			return
		}
		if len(s) > maxEmailLen || strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
			t.Fatalf("aceptó un correo con espacios, control o demasiado largo: %q", s)
		}
	})
}

func FuzzValidateRegister(f *testing.F) {
	f.Add("01a119d2-bc8e-7d83-b461-8de8e246853f", "Ana Pérez", "ana@example.com", strings.Repeat("A", 43), "a1.AAAAAAAAAAAAAAAA.QUJDRA")
	f.Fuzz(func(t *testing.T, id, name, email, key, sealedKey string) {
		r := &RegisterRequest{UserID: id, FullName: name, Email: email, AcceptedTerms: true, AuthKey: key, RecoveryAuth: strings.Repeat("B", 43),
			Keys: KeyBundle{Kdf: KdfParams{Alg: "argon2id", MemoryKiB: 1024, Iterations: 1, Parallelism: 1, Salt: "AAAAAAAAAAAAAAAAAAAAAA"}, WrappedMasterKey: sealedKey, RecoveryWrappedMasterKey: sealedKey}}
		if len(validateRegister(r)) == 0 && (!validUUID(id) || !sealedRe.MatchString(sealedKey)) {
			t.Fatalf("aceptó un registro mal formado: id=%q sealed=%q", id, sealedKey)
		}
	})
}
