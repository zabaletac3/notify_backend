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
	HasGoogle     bool      `json:"hasGoogle"`
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

// ── Dispositivos de confianza ────────────────────────────────────

// TrustedDevice es la vista de un dispositivo de confianza vigente (sin la clave maestra cifrada).
type TrustedDevice struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
}

// TrustedDeviceInput es el alta de un dispositivo de confianza (`POST /trusted-devices`).
type TrustedDeviceInput struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Platform         string `json:"platform"`
	WrappedMasterKey string `json:"wrappedMasterKey"`
}

// ── Verificación en dos pasos (MFA) ─────────────────────────────

// MfaChallenge es la respuesta del primer paso cuando la cuenta tiene MFA activo. No es una sesión.
type MfaChallenge struct {
	MFARequired bool      `json:"mfaRequired"`
	MFAToken    string    `json:"mfaToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type LoginMfaRequest struct {
	MFAToken string `json:"mfaToken"`
	Code     string `json:"code"`
}

type MFAStatus struct {
	Enabled           bool       `json:"enabled"`
	EnabledAt         *time.Time `json:"enabledAt"`
	RecoveryCodesLeft int        `json:"recoveryCodesLeft"`
}

type MfaSetupResult struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauthUri"`
}

type MfaRecoveryCodes struct {
	RecoveryCodes []string `json:"recoveryCodes"`
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
	MFAEnabled               bool      `json:"mfaEnabled"`
}

type PasswordResetRequest struct {
	Token        string    `json:"token"`
	Mode         string    `json:"mode"` // keep | wipe
	NewAuthKey   string    `json:"newAuthKey"`
	RecoveryAuth string    `json:"recoveryAuth"`
	Keys         KeyBundle `json:"keys"`
	MFACode      string    `json:"mfaCode,omitempty"`
	DisableMFA   bool      `json:"disableMfa,omitempty"`
}

// ── Acceso con Google ───────────────────────────────────────────────

type GoogleStartRequest struct {
	Challenge string `json:"challenge"`
}

type GoogleStartResult struct {
	URL string `json:"url"`
}

type GoogleExchangeRequest struct {
	Code     string      `json:"code"`
	Verifier string      `json:"verifier"`
	Device   *DeviceInfo `json:"device,omitempty"`
}

type GoogleLinkRequest struct {
	LinkToken string      `json:"linkToken"`
	AuthKey   string      `json:"authKey"`
	Device    *DeviceInfo `json:"device,omitempty"`
}

type GoogleRegisterRequest struct {
	SignupToken   string      `json:"signupToken"`
	UserID        string      `json:"userId"`
	FullName      string      `json:"fullName"`
	AcceptedTerms bool        `json:"acceptedTerms"`
	AuthKey       string      `json:"authKey"`
	RecoveryAuth  string      `json:"recoveryAuth"`
	Keys          KeyBundle   `json:"keys"`
	Device        *DeviceInfo `json:"device,omitempty"`
}

// GoogleOutcome es la respuesta de `POST /auth/google/exchange`, una unión discriminada por `status`.
// Solo se rellena el campo de la variante correspondiente (los demás van omitidos).
type GoogleOutcome struct {
	Status      string     `json:"status"` // authenticated | mfa-required | link-required | signup-required
	Session     *Session   `json:"session,omitempty"`
	MFAToken    string     `json:"mfaToken,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LinkToken   string     `json:"linkToken,omitempty"`
	SignupToken string     `json:"signupToken,omitempty"`
	Email       string     `json:"email,omitempty"`
	FullName    string     `json:"fullName,omitempty"`
	Kdf         *KdfParams `json:"kdf,omitempty"`
}

// ── Perfil y cambio de correo ────────────────────────────────────────

type ProfileUpdate struct {
	FullName string `json:"fullName"`
}

type EmailChangeRequest struct {
	NewEmail string `json:"newEmail"`
	AuthKey  string `json:"authKey"`
}

type EmailChangeConfirm struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type DeleteAccountRequest struct {
	AuthKey string `json:"authKey"`
}
