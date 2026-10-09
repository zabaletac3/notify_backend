package security

import (
	"strings"
	"testing"
	"time"
)

// Vectores de RFC 4226 (Apéndice D) con el secreto ASCII "12345678901234567890".
func TestTOTPRFC4226Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for step, exp := range want {
		if got := TOTPCode(secret, int64(step)); got != exp {
			t.Errorf("paso %d: got %s, want %s", step, got, exp)
		}
	}
}

func TestNewTOTPSecretShape(t *testing.T) {
	raw, b32, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 20 {
		t.Fatalf("secreto de %d bytes, se esperaban 20", len(raw))
	}
	if strings.Contains(b32, "=") || b32 == "" {
		t.Fatalf("base32 sin relleno esperado, got %q", b32)
	}
	raw2, _, _ := NewTOTPSecret()
	if string(raw) == string(raw2) {
		t.Fatal("dos secretos no deberían coincidir")
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	base := time.Unix(1_700_000_000, 0)
	t.Logf("paso base: %d", base.Unix()/30)
	step := base.Unix() / 30

	// El código del paso anterior, el actual y el siguiente deben aceptarse.
	for _, d := range []int64{-1, 0, 1} {
		code := TOTPCode(secret, step+d)
		got, ok := VerifyTOTP(secret, code, base, 0)
		if !ok || got != step+d {
			t.Errorf("desfase %d: got (%d,%v)", d, got, ok)
		}
	}
	// El de dos pasos atrás queda fuera de la ventana.
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, step-2), base, 0); ok {
		t.Error("no debería aceptar un código fuera de la ventana")
	}
	// Código mal formado.
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, base, 0); ok {
			t.Errorf("código mal formado aceptado: %q", bad)
		}
	}
}

func TestVerifyTOTPRejectsReusedStep(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1_700_000_000, 0)
	step := now.Unix() / 30
	code := TOTPCode(secret, step)

	accepted, ok := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("el código actual debía aceptarse")
	}
	if _, ok := VerifyTOTP(secret, code, now, accepted); ok {
		t.Fatal("un paso ya usado no debe volver a aceptarse")
	}
	// Un paso posterior tampoco vale si va hacia atrás.
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, accepted-1), now, accepted); ok {
		t.Fatal("no debe aceptar pasos <= last_step")
	}
}

func TestSealOpenTOTP(t *testing.T) {
	pepper := []byte("0123456789abcdef0123456789abcdef-pepper")
	uid := "01a119d2-bc8e-7d83-b461-8de8e246853f"
	secret := []byte("12345678901234567890")

	sealed, err := SealTOTP(pepper, uid, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "t1.") {
		t.Fatalf("formato inesperado: %q", sealed)
	}
	got, err := OpenTOTP(pepper, uid, sealed)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("abrir: %v %q", err, got)
	}
	// Otra cuenta no puede abrirlo (los datos asociados cambian).
	if _, err := OpenTOTP(pepper, "01a119d2-bc8e-7d83-b461-8de8e2468540", sealed); err == nil {
		t.Fatal("otra cuenta no debería poder abrir el secreto")
	}
	// Texto cifrado manipulado.
	tampered := sealed[:len(sealed)-1] + "A"
	if tampered == sealed {
		tampered = sealed[:len(sealed)-1] + "B"
	}
	if _, err := OpenTOTP(pepper, uid, tampered); err == nil {
		t.Fatal("un texto cifrado manipulado debe fallar")
	}
	// Sin el pepper correcto.
	if _, err := OpenTOTP([]byte("otro-pepper-distinto-0123456789abcdef"), uid, sealed); err == nil {
		t.Fatal("otro pepper no debería abrirlo")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("se esperaban 10 códigos, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("formato inesperado: %q", c)
		}
		norm, ok := NormalizeRecoveryCode(c)
		if !ok || len(norm) != 10 {
			t.Fatalf("no se pudo normalizar %q", c)
		}
		if seen[norm] {
			t.Fatalf("código repetido: %q", norm)
		}
		seen[norm] = true
	}
	// Entrada tolerante: minúsculas, espacios y guion.
	if norm, ok := NormalizeRecoveryCode("  abcd-efgh jk  "); !ok || norm != "ABCDEFGHJK" {
		t.Fatalf("normalización: %q %v", norm, ok)
	}
	// Alfabeto y longitud.
	for _, bad := range []string{"", "ABCDEFGHI", "ABCDEFGHIJ", "ABCDEFGHI0", "ABCDEFGHIO", "ABCDEFGHI!"} {
		if _, ok := NormalizeRecoveryCode(bad); ok {
			t.Errorf("código inválido aceptado: %q", bad)
		}
	}
}

func FuzzNormalizeRecoveryCode(f *testing.F) {
	f.Add("ABCDE-FGHJK")
	f.Add("abcd efghjk")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		norm, ok := NormalizeRecoveryCode(s)
		if ok && len(norm) != 10 {
			t.Fatalf("normalizado con longitud %d: %q", len(norm), norm)
		}
	})
}
