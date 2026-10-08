package notesync

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

const noteSelect = `SELECT id::text, folder_id::text, created_at, updated_at, deleted_at, revision, coalesce(last_edited_device_id::text, ''), wrapped_key, payload, seq FROM notes`

func scanNote(row pgx.Row) (*EncryptedNote, int64, error) {
	var n EncryptedNote
	var seq int64
	err := row.Scan(&n.ID, &n.FolderID, &n.CreatedAt, &n.UpdatedAt, &n.DeletedAt, &n.Revision, &n.LastEditedDeviceID, &n.WrappedKey, &n.Payload, &seq)
	return &n, seq, err
}

func (s *Service) readNote(ctx context.Context, tx pgx.Tx, id string) (*EncryptedNote, error) {
	n, _, err := scanNote(tx.QueryRow(ctx, noteSelect+` WHERE id = $1`, id))
	return n, err
}

// NotesPage es una página de notas cifradas.
type NotesPage struct {
	Items      []EncryptedNote `json:"items"`
	NextCursor *string         `json:"nextCursor"`
}

// NotesQuery son los filtros de GET /notes.
type NotesQuery struct {
	Trashed      *bool
	UpdatedSince *time.Time
	Cursor       string
	Limit        int
}

// ListNotes devuelve las notas cifradas de la cuenta, paginadas por `seq`.
func (s *Service) ListNotes(ctx context.Context, p Principal, q NotesQuery) (*NotesPage, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	var after int64
	if q.Cursor != "" {
		c := q.Cursor
		var ok bool
		if after, ok = parseCursor(&c); !ok {
			return nil, apperrors.Validation(map[string]string{"cursor": "invalid-payload"})
		}
	}
	page := &NotesPage{Items: []EncryptedNote{}}
	err := database.WithUser(ctx, s.pool, p.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, noteSelect+` WHERE seq > $1
			AND ($2::boolean IS NULL OR (deleted_at IS NOT NULL) = $2)
			AND ($3::timestamptz IS NULL OR updated_at >= $3)
			ORDER BY seq LIMIT $4`, after, q.Trashed, q.UpdatedSince, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var last int64
		for rows.Next() {
			n, seq, err := scanNote(rows)
			if err != nil {
				return err
			}
			if len(page.Items) == limit {
				next := strconv.FormatInt(last, 10)
				page.NextCursor = &next
				break
			}
			page.Items = append(page.Items, *n)
			last = seq
		}
		return rows.Err()
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return page, nil
}

// GetNote devuelve una nota cifrada de la cuenta (404 si no existe o es de otra cuenta).
func (s *Service) GetNote(ctx context.Context, p Principal, id string) (*EncryptedNote, error) {
	if !validUUID(id) {
		return nil, apperrors.NotFound("note")
	}
	var n *EncryptedNote
	err := database.WithUser(ctx, s.pool, p.UserID, func(tx pgx.Tx) error {
		var err error
		n, err = s.readNote(ctx, tx, id)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.NotFound("note")
	}
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return n, nil
}

// ListFolders devuelve las carpetas cifradas de la cuenta.
func (s *Service) ListFolders(ctx context.Context, p Principal) ([]EncryptedFolder, error) {
	out := []EncryptedFolder{}
	err := database.WithUser(ctx, s.pool, p.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, created_at, updated_at, revision, wrapped_key, payload FROM folders ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f EncryptedFolder
			if err := rows.Scan(&f.ID, &f.CreatedAt, &f.UpdatedAt, &f.Revision, &f.WrappedKey, &f.Payload); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, apperrors.Internal(err)
	}
	return out, nil
}
