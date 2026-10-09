// Package account implementa las preferencias de la cuenta y el uso de espacio.
package account

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

// Settings son las preferencias (AppSettings del contrato). Se guardan en users.settings.
type Settings struct {
	Theme           string `json:"theme"`
	TextSize        string `json:"textSize"`
	NoteOrder       string `json:"noteOrder"`
	OpenWithNewNote bool   `json:"openWithNewNote"`
	ShowPreview     bool   `json:"showPreview"`
	Language        string `json:"language"`
	AutoSync        bool   `json:"autoSync"`
	WifiOnly        bool   `json:"wifiOnly"`
	BiometricLock   bool   `json:"biometricLock"`
	LockOnExit      bool   `json:"lockOnExit"`
	LockTimeout     string `json:"lockTimeout"`
	TwoFactor       bool   `json:"twoFactor"`
}

// Valores por defecto (los mismos que `DEFAULT_SETTINGS` de la web).
var defaults = Settings{
	Theme: "system", TextSize: "medium", NoteOrder: "updated", OpenWithNewNote: false, ShowPreview: true,
	Language: "es", AutoSync: true, WifiOnly: false, BiometricLock: true, LockOnExit: true, LockTimeout: "1m", TwoFactor: false,
}

// SettingsPatch es cualquier subconjunto de Settings.
type SettingsPatch struct {
	Theme           *string `json:"theme"`
	TextSize        *string `json:"textSize"`
	NoteOrder       *string `json:"noteOrder"`
	OpenWithNewNote *bool   `json:"openWithNewNote"`
	ShowPreview     *bool   `json:"showPreview"`
	Language        *string `json:"language"`
	AutoSync        *bool   `json:"autoSync"`
	WifiOnly        *bool   `json:"wifiOnly"`
	BiometricLock   *bool   `json:"biometricLock"`
	LockOnExit      *bool   `json:"lockOnExit"`
	LockTimeout     *string `json:"lockTimeout"`
	TwoFactor       *bool   `json:"twoFactor"`
}

var allowed = map[string][]string{
	"theme":       {"system", "light", "dark"},
	"textSize":    {"small", "medium", "large"},
	"noteOrder":   {"updated", "created", "title"},
	"language":    {"es"},
	"lockTimeout": {"immediately", "1m", "5m", "15m"},
}

func oneOf(field string, v *string, bad map[string]string) {
	if v == nil {
		return
	}
	for _, ok := range allowed[field] {
		if *v == ok {
			return
		}
	}
	bad[field] = "invalid-payload"
}

// validate comprueba el parche y devuelve campo → código. `twoFactor` es de solo lectura (se gestiona
// con `/mfa`): enviarlo, sea `true` o `false`, es un error para no dar una falsa sensación de control.
func (p *SettingsPatch) validate() map[string]string {
	bad := map[string]string{}
	oneOf("theme", p.Theme, bad)
	oneOf("textSize", p.TextSize, bad)
	oneOf("noteOrder", p.NoteOrder, bad)
	oneOf("language", p.Language, bad)
	oneOf("lockTimeout", p.LockTimeout, bad)
	if p.TwoFactor != nil {
		bad["twoFactor"] = "invalid-payload"
	}
	if *p == (SettingsPatch{}) {
		bad["body"] = "invalid-payload" // un parche vacío no cambia nada
	}
	return bad
}

func (p *SettingsPatch) apply(s *Settings) {
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	setb := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&s.Theme, p.Theme)
	set(&s.TextSize, p.TextSize)
	set(&s.NoteOrder, p.NoteOrder)
	setb(&s.OpenWithNewNote, p.OpenWithNewNote)
	setb(&s.ShowPreview, p.ShowPreview)
	set(&s.Language, p.Language)
	setb(&s.AutoSync, p.AutoSync)
	setb(&s.WifiOnly, p.WifiOnly)
	setb(&s.BiometricLock, p.BiometricLock)
	setb(&s.LockOnExit, p.LockOnExit)
	set(&s.LockTimeout, p.LockTimeout)
}

// Usage es el uso de espacio (StorageUsage del contrato).
type Usage struct {
	UsedBytes   int64 `json:"usedBytes"`
	QuotaBytes  int64 `json:"quotaBytes"`
	NotesBytes  int64 `json:"notesBytes"`
	ImagesBytes int64 `json:"imagesBytes"`
	TrashBytes  int64 `json:"trashBytes"`
}

type Service struct {
	pool       *pgxpool.Pool
	quotaBytes int64
}

func NewService(pool *pgxpool.Pool, quotaBytes int64) *Service {
	return &Service{pool: pool, quotaBytes: quotaBytes}
}

func readSettings(ctx context.Context, tx pgx.Tx, userID string, lock bool) (Settings, error) {
	q := `SELECT settings FROM users WHERE id = $1 AND deleted_at IS NULL`
	if lock {
		q += ` FOR UPDATE`
	}
	var raw []byte
	if err := tx.QueryRow(ctx, q, userID).Scan(&raw); err != nil {
		return Settings{}, err
	}
	s := defaults // los ajustes que falten (cuenta nueva) toman el valor por defecto
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return Settings{}, err
		}
	}
	// `twoFactor` no se guarda en settings: es el estado real de la verificación en dos pasos. Se lee
	// directamente de `user_totp` (account no importa auth; comparte la transacción con RLS ya fijada).
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_totp WHERE user_id = app_user_id() AND enabled_at IS NOT NULL)`).Scan(&enabled); err != nil {
		return Settings{}, err
	}
	s.TwoFactor = enabled
	return s, nil
}

func (s *Service) Get(ctx context.Context, userID string) (*Settings, error) {
	var out Settings
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) (err error) {
		out, err = readSettings(ctx, tx, userID, false)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.SessionExpired()
	}
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return &out, nil
}

func (s *Service) Update(ctx context.Context, userID string, patch *SettingsPatch) (*Settings, error) {
	if bad := patch.validate(); len(bad) > 0 {
		return nil, apperrors.Validation(bad)
	}
	var out Settings
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) error {
		cur, err := readSettings(ctx, tx, userID, true)
		if err != nil {
			return err
		}
		patch.apply(&cur)
		raw, _ := json.Marshal(cur)
		if _, err = tx.Exec(ctx, `UPDATE users SET settings = $2 WHERE id = $1`, userID, raw); err != nil {
			return err
		}
		out = cur
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.SessionExpired()
	}
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return &out, nil
}

// Usage suma el tamaño guardado de lo cifrado (clave + contenido) de la cuenta.
func (s *Service) Usage(ctx context.Context, userID string) (*Usage, error) {
	u := &Usage{QuotaBytes: s.quotaBytes}
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) error {
		var folders int64
		if err := tx.QueryRow(ctx, `SELECT
			coalesce(sum(pg_column_size(payload) + pg_column_size(wrapped_key)) FILTER (WHERE deleted_at IS NULL), 0),
			coalesce(sum(pg_column_size(payload) + pg_column_size(wrapped_key)) FILTER (WHERE deleted_at IS NOT NULL), 0)
			FROM notes`).Scan(&u.NotesBytes, &u.TrashBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(pg_column_size(payload) + pg_column_size(wrapped_key)), 0) FROM folders`).Scan(&folders); err != nil {
			return err
		}
		u.NotesBytes += folders // las carpetas cuentan como notas
		return nil
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	u.UsedBytes = u.NotesBytes + u.TrashBytes + u.ImagesBytes
	return u, nil
}
