package security

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	pepper  = []byte("0123456789abcdef0123456789abcdef-pepper")
	authKey = strings.Repeat("A", 43)
)

func TestAuthKeyHashVerify(t *testing.T) {
	h, err := NewAuthKeyHasher(pepper)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.Hash(authKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(stored), "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("formato inesperado: %s", stored)
	}
	if strings.Contains(string(stored), authKey) {
		t.Fatal("el hash contiene la authKey")
	}
	if ok, re := h.Verify(stored, authKey); !ok || re {
		t.Fatalf("verificación correcta falló: ok=%v rehash=%v", ok, re)
	}
	if ok, _ := h.Verify(stored, strings.Repeat("B", 43)); ok {
		t.Fatal("aceptó una authKey distinta")
	}
	// Dos hashes de la misma clave difieren (sal aleatoria).
	other, _ := h.Hash(authKey)
	if string(other) == string(stored) {
		t.Fatal("la sal no es aleatoria")
	}
}

func TestAuthKeyDependsOnPepper(t *testing.T) {
	h1, _ := NewAuthKeyHasher(pepper)
	h2, _ := NewAuthKeyHasher([]byte(strings.Repeat("x", 40)))
	stored, _ := h1.Hash(authKey)
	if ok, _ := h2.Verify(stored, authKey); ok {
		t.Fatal("un pepper distinto no debe verificar")
	}
}

func TestAuthKeyRejectsBadInput(t *testing.T) {
	h, _ := NewAuthKeyHasher(pepper)
	for _, bad := range []string{"", "corta", strings.Repeat("A", 44), strings.Repeat("!", 43)} {
		if _, err := h.Hash(bad); err == nil {
			t.Errorf("aceptó %q", bad)
		}
	}
	// Datos guardados corruptos o con parámetros peligrosos: no verifican y no revientan.
	for _, stored := range []string{"", "x", "$argon2id$v=19$m=999999999,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=19456,t=999,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", "$bcrypt$x"} {
		if ok, _ := h.Verify([]byte(stored), authKey); ok {
			t.Errorf("verificó datos inválidos %q", stored)
		}
	}
	if _, err := NewAuthKeyHasher([]byte("corto")); err == nil {
		t.Fatal("aceptó un pepper corto")
	}
}

func TestVerifyDummyAndRehash(t *testing.T) {
	h, _ := NewAuthKeyHasher(pepper)
	h.VerifyDummy(authKey) // no debe fallar ni entrar en pánico
	stored, _ := h.Hash(authKey)
	mem, tt, p, salt, _, err := parseHash(stored)
	if err != nil || mem != argonMemoryKiB || tt != argonTime || p != argonThreads || len(salt) != argonSaltLen {
		t.Fatalf("parseHash: %v", err)
	}
}

func TestTokens(t *testing.T) {
	a, _ := RandomToken(32)
	b, _ := RandomToken(32)
	if a == b || len(a) != 43 {
		t.Fatalf("tokens: %q %q", a, b)
	}
	if string(HashToken(a)) == string(HashToken(b)) || len(HashToken(a)) != 32 {
		t.Fatal("HashToken")
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := NumericCode(6)
		if err != nil || len(c) != 6 || strings.Trim(c, "0123456789") != "" {
			t.Fatalf("código inválido %q %v", c, err)
		}
		seen[c] = true
	}
	if len(seen) < 150 {
		t.Fatalf("poca entropía: %d distintos de 200", len(seen))
	}
	if _, err := NumericCode(2); err == nil {
		t.Fatal("aceptó 2 dígitos")
	}
}

func TestCodeHashIsBoundToPurposeAndSubject(t *testing.T) {
	base := HashCode(pepper, "verify-email", "user-1", "123456")
	for name, other := range map[string][]byte{
		"otra finalidad": HashCode(pepper, "password-reset", "user-1", "123456"),
		"otra cuenta":    HashCode(pepper, "verify-email", "user-2", "123456"),
		"otro código":    HashCode(pepper, "verify-email", "user-1", "654321"),
		"otro pepper":    HashCode([]byte(strings.Repeat("y", 40)), "verify-email", "user-1", "123456"),
	} {
		if Equal(base, other) {
			t.Errorf("%s: el hash coincide", name)
		}
	}
	if !Equal(base, HashCode(pepper, "verify-email", "user-1", "123456")) {
		t.Fatal("el hash no es determinista")
	}
}

func TestDeriveKeyDomainSeparation(t *testing.T) {
	if Equal(DeriveKey(pepper, "a"), DeriveKey(pepper, "b")) || len(DeriveKey(pepper, "a")) != 32 {
		t.Fatal("derivación sin separación de dominio")
	}
}

// ── JWT ───────────────────────────────────────────────────────────

func newSigner(t *testing.T, now *time.Time, secret, prev []byte) *Signer {
	t.Helper()
	s, err := NewSigner(SignerOptions{Secret: secret, PreviousSecret: prev, Issuer: "apunte-test", TTL: 15 * time.Minute,
		Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJWTRoundTripAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := newSigner(t, &now, pepper, nil)
	uid, did := uuid.NewString(), uuid.NewString()
	tok, exp, err := s.Issue(uid, did)
	if err != nil || !exp.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("emitir: %v %v", err, exp)
	}
	c, err := s.Parse(tok)
	if err != nil || c.UserID != uid || c.DeviceID != did || c.ID == "" {
		t.Fatalf("parse: %+v %v", c, err)
	}
	now = now.Add(15*time.Minute + time.Minute) // pasado el margen de 30 s
	if _, err := s.Parse(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token caducado aceptado: %v", err)
	}
}

func TestJWTRejectsTampering(t *testing.T) {
	now := time.Now()
	s := newSigner(t, &now, pepper, nil)
	uid, did := uuid.NewString(), uuid.NewString()
	tok, _, _ := s.Issue(uid, did)

	// alg=none
	none := jwt.NewWithClaims(jwt.SigningMethodNone, wireClaims{DeviceID: did, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "apunte-test", Subject: uid, Audience: jwt.ClaimStrings{jwtAudience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}})
	none.Header["kid"] = s.current.kid
	noneTok, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)

	// Otro algoritmo (HS512) con el mismo secreto.
	hs512 := jwt.NewWithClaims(jwt.SigningMethodHS512, wireClaims{DeviceID: did, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "apunte-test", Subject: uid, Audience: jwt.ClaimStrings{jwtAudience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}})
	hs512.Header["kid"] = s.current.kid
	hs512Tok, _ := hs512.SignedString(pepper)

	// Otro secreto, otro emisor, sin caducidad, sub no UUID.
	other := newSigner(t, &now, []byte(strings.Repeat("z", 40)), nil)
	otherTok, _, _ := other.Issue(uid, did)
	mk := func(c wireClaims) string {
		tk := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
		tk.Header["kid"] = s.current.kid
		out, _ := tk.SignedString(pepper)
		return out
	}
	rc := func(mod func(*jwt.RegisteredClaims)) wireClaims {
		r := jwt.RegisteredClaims{Issuer: "apunte-test", Subject: uid, Audience: jwt.ClaimStrings{jwtAudience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}
		mod(&r)
		return wireClaims{DeviceID: did, RegisteredClaims: r}
	}

	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(payload, &m)
	m["sub"] = uuid.NewString()
	forged, _ := json.Marshal(m)

	cases := map[string]string{
		"alg none":         noneTok,
		"HS512":            hs512Tok,
		"otro secreto":     otherTok,
		"emisor ajeno":     mk(rc(func(r *jwt.RegisteredClaims) { r.Issuer = "otro" })),
		"audiencia ajena":  mk(rc(func(r *jwt.RegisteredClaims) { r.Audience = jwt.ClaimStrings{"otra"} })),
		"sin caducidad":    mk(rc(func(r *jwt.RegisteredClaims) { r.ExpiresAt = nil })),
		"sub no UUID":      mk(rc(func(r *jwt.RegisteredClaims) { r.Subject = "admin" })),
		"payload alterado": parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2],
		"basura":           "no.es.un.jwt",
		"vacío":            "",
	}
	for name, bad := range cases {
		if _, err := s.Parse(bad); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: aceptado (%v)", name, err)
		}
	}
}

func TestJWTSecretRotation(t *testing.T) {
	now := time.Now()
	old := newSigner(t, &now, []byte(strings.Repeat("o", 40)), nil)
	uid, did := uuid.NewString(), uuid.NewString()
	tok, _, _ := old.Issue(uid, did)

	rotated := newSigner(t, &now, []byte(strings.Repeat("n", 40)), []byte(strings.Repeat("o", 40)))
	if _, err := rotated.Parse(tok); err != nil {
		t.Fatalf("el secreto anterior debe seguir valiendo durante la rotación: %v", err)
	}
	if _, err := newSigner(t, &now, []byte(strings.Repeat("n", 40)), nil).Parse(tok); err == nil {
		t.Fatal("sin el secreto anterior el token viejo no debe valer")
	}
	newTok, _, _ := rotated.Issue(uid, did)
	if _, err := old.Parse(newTok); err == nil {
		t.Fatal("el firmador viejo no debe aceptar el token nuevo")
	}
}

func TestSignerValidatesOptions(t *testing.T) {
	ok := SignerOptions{Secret: pepper, Issuer: "i", TTL: time.Minute}
	bad := map[string]SignerOptions{
		"secreto corto": {Secret: []byte("x"), Issuer: "i", TTL: time.Minute},
		"previo corto":  {Secret: pepper, PreviousSecret: []byte("x"), Issuer: "i", TTL: time.Minute},
		"sin emisor":    {Secret: pepper, TTL: time.Minute},
		"ttl cero":      {Secret: pepper, Issuer: "i"},
		"ttl demasiado": {Secret: pepper, Issuer: "i", TTL: 24 * time.Hour},
	}
	if _, err := NewSigner(ok); err != nil {
		t.Fatal(err)
	}
	for name, o := range bad {
		if _, err := NewSigner(o); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
	s, _ := NewSigner(ok)
	if _, _, err := s.Issue("no-uuid", uuid.NewString()); err == nil {
		t.Fatal("emitió para un id inválido")
	}
}

// ── prelogin y hash de IP ─────────────────────────────────────────

func TestFakeKDFIsStableAndShaped(t *testing.T) {
	a := FakeKDF(pepper, "ana@example.com")
	if a != FakeKDF(pepper, "  ANA@example.com ") {
		t.Fatal("no normaliza el correo")
	}
	if a == FakeKDF(pepper, "luis@example.com") {
		t.Fatal("la sal no depende del correo")
	}
	if a == FakeKDF([]byte(strings.Repeat("q", 40)), "ana@example.com") {
		t.Fatal("la sal no depende del secreto")
	}
	salt, err := base64.RawURLEncoding.DecodeString(a.Salt)
	if err != nil || len(salt) != 16 || a.Alg != "argon2id" || a.MemoryKiB != 65536 || a.Iterations != 3 || a.Parallelism != 1 {
		t.Fatalf("forma incorrecta: %+v", a)
	}
	if strings.Contains(a.Salt, "ana") {
		t.Fatal("la sal revela el correo")
	}
}

func TestHashIPRotatesDaily(t *testing.T) {
	d1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d2 := d1.Add(24 * time.Hour)
	if !Equal(HashIP(pepper, "1.2.3.4", d1), HashIP(pepper, "1.2.3.4", d1.Add(time.Minute))) {
		t.Fatal("el mismo día debe dar el mismo hash")
	}
	if Equal(HashIP(pepper, "1.2.3.4", d1), HashIP(pepper, "1.2.3.4", d2)) {
		t.Fatal("otro día debe dar otro hash")
	}
	if Equal(HashIP(pepper, "1.2.3.4", d1), HashIP(pepper, "1.2.3.5", d1)) {
		t.Fatal("otra IP debe dar otro hash")
	}
}

// El camino de "cuenta inexistente" (VerifyDummy) debe costar lo mismo que verificar una cuenta real,
// para que el tiempo de respuesta no revele qué correos existen. Se compara la mediana con margen amplio.
func TestDummyVerifyCostsLikeRealVerify(t *testing.T) {
	h, _ := NewAuthKeyHasher(pepper)
	stored, _ := h.Hash(authKey)
	median := func(f func()) time.Duration {
		var ds []time.Duration
		for i := 0; i < 7; i++ {
			start := time.Now()
			f()
			ds = append(ds, time.Since(start))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	real := median(func() { h.Verify(stored, strings.Repeat("B", 43)) })
	dummy := median(func() { h.VerifyDummy(strings.Repeat("B", 43)) })
	ratio := float64(dummy) / float64(real)
	if ratio < 0.5 || ratio > 2 {
		t.Fatalf("los tiempos difieren demasiado: real=%v dummy=%v", real, dummy)
	}
}
