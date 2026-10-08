package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalidToken se devuelve para cualquier token de acceso inválido, sin distinguir el motivo.
var ErrInvalidToken = errors.New("security: invalid token")

const (
	jwtAudience = "apunte-api"
	jwtLeeway   = 30 * time.Second
)

// Claims son los datos del token de acceso.
type Claims struct {
	UserID    string // sub
	DeviceID  string // did
	ID        string // jti
	ExpiresAt time.Time
}

type wireClaims struct {
	DeviceID string `json:"did"`
	jwt.RegisteredClaims
}

// SignerOptions configura el firmador. PreviousSecret permite rotar el secreto sin cerrar las
// sesiones: los tokens firmados con él siguen siendo válidos hasta que caducan.
type SignerOptions struct {
	Secret         []byte
	PreviousSecret []byte
	Issuer         string
	TTL            time.Duration
	Now            func() time.Time
}

// Signer emite y valida tokens de acceso HS256.
type Signer struct {
	issuer  string
	ttl     time.Duration
	now     func() time.Time
	current keyEntry
	keys    map[string][]byte
	parser  *jwt.Parser
}

type keyEntry struct {
	kid    string
	secret []byte
}

func kidOf(secret []byte) string {
	sum := sha256.Sum256(append([]byte("apunte/v1/kid:"), secret...))
	return hex.EncodeToString(sum[:4])
}

// NewSigner valida las opciones: secretos de al menos 32 bytes y TTL razonable.
func NewSigner(o SignerOptions) (*Signer, error) {
	if len(o.Secret) < minPepperLen {
		return nil, fmt.Errorf("security: el secreto JWT debe tener al menos %d bytes", minPepperLen)
	}
	if len(o.PreviousSecret) > 0 && len(o.PreviousSecret) < minPepperLen {
		return nil, fmt.Errorf("security: el secreto JWT anterior debe tener al menos %d bytes", minPepperLen)
	}
	if o.Issuer == "" {
		return nil, errors.New("security: falta el emisor JWT")
	}
	if o.TTL <= 0 || o.TTL > time.Hour {
		return nil, errors.New("security: el TTL del token de acceso debe estar entre 1 ns y 1 h")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Signer{issuer: o.Issuer, ttl: o.TTL, now: o.Now, keys: map[string][]byte{}}
	s.current = keyEntry{kid: kidOf(o.Secret), secret: append([]byte(nil), o.Secret...)}
	s.keys[s.current.kid] = s.current.secret
	if len(o.PreviousSecret) > 0 {
		prev := append([]byte(nil), o.PreviousSecret...)
		s.keys[kidOf(prev)] = prev
	}
	s.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(o.Issuer),
		jwt.WithAudience(jwtAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(jwtLeeway),
		jwt.WithTimeFunc(o.Now),
	)
	return s, nil
}

// Issue firma un token de acceso para una cuenta y dispositivo.
func (s *Signer) Issue(userID, deviceID string) (token string, expiresAt time.Time, err error) {
	if _, err = uuid.Parse(userID); err != nil {
		return "", time.Time{}, errors.New("security: id de cuenta no válido")
	}
	if _, err = uuid.Parse(deviceID); err != nil {
		return "", time.Time{}, errors.New("security: id de dispositivo no válido")
	}
	jti := make([]byte, 16)
	if _, err = rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expiresAt = now.Add(s.ttl)
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, wireClaims{
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: s.issuer, Subject: userID, Audience: jwt.ClaimStrings{jwtAudience},
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt), ID: hex.EncodeToString(jti),
		},
	})
	t.Header["kid"] = s.current.kid
	token, err = t.SignedString(s.current.secret)
	return token, expiresAt, err
}

// Parse valida firma, algoritmo, emisor, audiencia y caducidad. Cualquier fallo es ErrInvalidToken.
func (s *Signer) Parse(token string) (*Claims, error) {
	var wc wireClaims
	t, err := s.parser.ParseWithClaims(token, &wc, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		secret, ok := s.keys[kid]
		if !ok {
			return nil, errors.New("kid desconocido")
		}
		return secret, nil
	})
	if err != nil || !t.Valid {
		return nil, ErrInvalidToken
	}
	if _, err := uuid.Parse(wc.Subject); err != nil {
		return nil, ErrInvalidToken
	}
	if _, err := uuid.Parse(wc.DeviceID); err != nil {
		return nil, ErrInvalidToken
	}
	return &Claims{UserID: wc.Subject, DeviceID: wc.DeviceID, ID: wc.ID, ExpiresAt: wc.ExpiresAt.Time}, nil
}
