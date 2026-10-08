// Package share implementa los enlaces públicos de solo lectura (ADR 0005). El cliente cifra una copia
// de la nota con una clave propia del enlace y elige el slug; la clave va en el fragmento de la URL
// (`#k=…`) y nunca llega al servidor, que solo guarda y sirve texto cifrado.
package share

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
)

var (
	slugRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	sealedRe = regexp.MustCompile(`^a1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$`)
)

const (
	maxKeyLen     = 512
	maxPayloadLen = 1_500_000
)

type SharedNote struct {
	ID              string    `json:"id"`
	NoteID          string    `json:"noteId"`
	Slug            string    `json:"slug"`
	WrappedShareKey string    `json:"wrappedShareKey"`
	Payload         string    `json:"payload"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type ShareInput struct {
	Slug            string `json:"slug"`
	WrappedShareKey string `json:"wrappedShareKey"`
	Payload         string `json:"payload"`
}

type PublicNote struct {
	Payload   string    `json:"payload"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Service guarda y sirve los enlaces.
type Service struct {
	pool    *pgxpool.Pool
	limiter *ratelimit.Limiter
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, limiter *ratelimit.Limiter) *Service {
	return &Service{pool: pool, limiter: limiter, now: time.Now}
}

func sealedOK(s string, max int) bool { return len(s) <= max && sealedRe.MatchString(s) }

func validNoteID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u.String() == id
}

const linkCols = `id::text, note_id::text, slug, wrapped_key, payload, created_at, updated_at`

func scanLink(row pgx.Row) (*SharedNote, error) {
	var l SharedNote
	err := row.Scan(&l.ID, &l.NoteID, &l.Slug, &l.WrappedShareKey, &l.Payload, &l.CreatedAt, &l.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &l, err
}

// Get devuelve el enlace de la nota, o nil si no tiene.
func (s *Service) Get(ctx context.Context, userID, noteID string) (*SharedNote, error) {
	if !validNoteID(noteID) {
		return nil, apperrors.NotFound("note")
	}
	var l *SharedNote
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) (err error) {
		l, err = scanLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM share_links WHERE note_id = $1`, noteID))
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return l, nil
}

// Create crea el enlace de una nota sincronizada y fuera de la papelera, o devuelve el existente.
func (s *Service) Create(ctx context.Context, userID, noteID string, in *ShareInput) (*SharedNote, error) {
	if !validNoteID(noteID) {
		return nil, apperrors.NotFound("note")
	}
	f := map[string]string{}
	if !slugRe.MatchString(in.Slug) {
		f["slug"] = "invalid-slug"
	}
	if !sealedOK(in.WrappedShareKey, maxKeyLen) {
		f["wrappedShareKey"] = "invalid-payload"
	}
	if !sealedOK(in.Payload, maxPayloadLen) {
		f["payload"] = "invalid-payload"
	}
	if len(f) > 0 {
		return nil, apperrors.Validation(f)
	}
	var out *SharedNote
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) error {
		var trashed *time.Time
		err := tx.QueryRow(ctx, `SELECT deleted_at FROM notes WHERE id = $1 FOR UPDATE`, noteID).Scan(&trashed)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && trashed != nil) {
			return apperrors.NotFound("note")
		}
		if err != nil {
			return err
		}
		if out, err = scanLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM share_links WHERE note_id = $1`, noteID)); err != nil || out != nil {
			return err // ya tenía enlace: se devuelve el existente y se ignora lo enviado
		}
		now := s.now()
		out, err = scanLink(tx.QueryRow(ctx, `INSERT INTO share_links (slug, note_id, user_id, wrapped_key, payload, created_at, updated_at)
			VALUES ($1, $2, app_user_id(), $3, $4, $5, $5) RETURNING `+linkCols, in.Slug, noteID, in.WrappedShareKey, in.Payload, now))
		return err
	})
	if err != nil {
		var ae *apperrors.Error
		if errors.As(err, &ae) {
			return nil, ae
		}
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, apperrors.Validation(map[string]string{"slug": "slug-taken"})
		}
		return nil, apperrors.Internal(err)
	}
	return out, nil
}

// Revoke borra el enlace y su copia cifrada. Es idempotente.
func (s *Service) Revoke(ctx context.Context, userID, noteID string) error {
	if !validNoteID(noteID) {
		return nil
	}
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM share_links WHERE note_id = $1`, noteID)
		return err
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	return nil
}

// UpdatePayload cambia la copia cifrada del enlace (al editar la nota).
func (s *Service) UpdatePayload(ctx context.Context, userID, noteID, payload string) error {
	if !validNoteID(noteID) {
		return apperrors.NotFound("note")
	}
	if !sealedOK(payload, maxPayloadLen) {
		return apperrors.Validation(map[string]string{"payload": "invalid-payload"})
	}
	var found bool
	err := database.WithUser(ctx, s.pool, userID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE share_links SET payload = $2, updated_at = $3 WHERE note_id = $1`, noteID, payload, s.now())
		found = tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return apperrors.Internal(err)
	}
	if !found {
		return apperrors.NotFound("share")
	}
	return nil
}

// ReadPublic sirve la copia cifrada de un enlace, sin sesión. Un enlace inexistente, revocado o con
// forma inválida dan el mismo 404, y el acceso por IP está limitado.
func (s *Service) ReadPublic(ctx context.Context, ip, slug string) (*PublicNote, error) {
	res, err := s.limiter.Take(ctx, s.limiter.Key("public-share", ip), ratelimit.PublicShare)
	if err != nil {
		return nil, apperrors.Unavailable(err)
	}
	if !res.Allowed {
		return nil, apperrors.RateLimited(res.RetryAfter)
	}
	if !slugRe.MatchString(slug) {
		return nil, apperrors.NotFound("share")
	}
	var out PublicNote
	var found bool
	err = database.WithPublicSlug(ctx, s.pool, slug, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT payload, updated_at FROM share_links WHERE slug = $1`, slug).Scan(&out.Payload, &out.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	if !found {
		return nil, apperrors.NotFound("share")
	}
	return &out, nil
}
