// Package auth implementa cuentas y sesión: prelogin, registro, verificación de correo, login,
// renovación de tokens con rotación, cierre de sesión y dispositivos. El servidor nunca recibe la
// contraseña: solo pruebas derivadas en el cliente (authKey, recoveryAuth).
package auth

import (
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/security"
)

// ── Contrato HTTP (docs/api/openapi.yaml) ────────────────────────────────────

type KdfParams = security.KDFParams

type KeyBundle struct {
	Kdf                      KdfParams `json:"kdf"`
	WrappedMasterKey         string    `json:"wrappedMasterKey"`
	RecoveryWrappedMasterKey string    `json:"recoveryWrappedMasterKey"`
	KeysVersion              int       `json:"keysVersion"`
}

type RegisterRequest struct {
	UserID        string    `json:"userId"`
	FullName      string    `json:"fullName"`
	Email         string    `json:"email"`
	AcceptedTerms bool      `json:"acceptedTerms"`
	AuthKey       string    `json:"authKey"`
	RecoveryAuth  string    `json:"recoveryAuth"`
	Keys          KeyBundle `json:"keys"`
}

type DeviceInfo struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

type LoginRequest struct {
	Email   string      `json:"email"`
	AuthKey string      `json:"authKey"`
	Device  *DeviceInfo `json:"device,omitempty"`
}

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	FullName      string    `json:"fullName"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
}

type Session struct {
	User         User       `json:"user"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	AccessToken  string     `json:"accessToken,omitempty"`
	RefreshToken string     `json:"refreshToken,omitempty"`
	Keys         *KeyBundle `json:"keys,omitempty"`
}

type Device struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Platform     string    `json:"platform"`
	LastActiveAt time.Time `json:"lastActiveAt"`
	Current      bool      `json:"current"`
}

// Principal es quien hace la petición, ya autenticado.
type Principal struct {
	UserID   string
	DeviceID string
	Expires  time.Time
}

// ── Claves, contraseña y recuperación ────────────────────────────────────

type PasswordChangeRequest struct {
	CurrentAuthKey string    `json:"currentAuthKey"`
	NewAuthKey     string    `json:"newAuthKey"`
	Keys           KeyBundle `json:"keys"`
}

type RecoveryKeyRotation struct {
	AuthKey                  string `json:"authKey"`
	RecoveryAuth             string `json:"recoveryAuth"`
	RecoveryWrappedMasterKey string `json:"recoveryWrappedMasterKey"`
}

type PasswordResetBundle struct {
	UserID                   string    `json:"userId"`
	RecoveryWrappedMasterKey string    `json:"recoveryWrappedMasterKey"`
	Kdf                      KdfParams `json:"kdf"`
}

type PasswordResetRequest struct {
	Token        string    `json:"token"`
	Mode         string    `json:"mode"` // keep | wipe
	NewAuthKey   string    `json:"newAuthKey"`
	RecoveryAuth string    `json:"recoveryAuth"`
	Keys         KeyBundle `json:"keys"`
}
