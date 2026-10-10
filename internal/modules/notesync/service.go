package notesync

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/database"
)

// Limits son los topes por petición y por cuenta.
type Limits struct {
	MaxChanges int
	MaxNotes   int
	MaxFolders int
	// MaxRemote y RemoteBytes acotan lo que baja cada /sync (el cliente repite mientras haya más).
	MaxRemote   int
	RemoteBytes int64
	// QuotaBytes limita los textos cifrados de la cuenta (0 = sin límite).
	QuotaBytes int64
}

// Service aplica los cambios del cliente y entrega los remotos.
type Service struct {
	pool   *pgxpool.Pool
	limits Limits
}

func NewService(pool *pgxpool.Pool, l Limits) *Service { return &Service{pool: pool, limits: l} }

const unknownDevice = "Otro dispositivo"

// Sync aplica la cola de cambios en una sola transacción y devuelve lo aplicado, lo remoto y los
// conflictos. Todo se valida antes de tocar nada: una petición inválida no deja cambios a medias.
func (s *Service) Sync(ctx context.Context, p Principal, req *Request) (*Response, error) {
	changes, bad := validate(req, s.limits.MaxChanges)
	if bad != nil {
		return nil, apperrors.Validation(bad)
	}
	since, _ := parseCursor(req.Cursor)
	res := &Response{Applied: []Applied{}, RemoteChanges: []RemoteChange{}, Conflicts: []ConflictReport{}}

	err := database.WithUser(ctx, s.pool, p.UserID, func(tx pgx.Tx) error {
		res = &Response{Applied: []Applied{}, RemoteChanges: []RemoteChange{}, Conflicts: []ConflictReport{}}
		touched := map[string]bool{}
		// Revisión de cada nota justo antes de que, en esta misma petición, el borrado de su carpeta
		// se la subiera de rebote (ver applyFolder/applyNote): así el upsert de esa nota que llegue con
		// esa revisión anterior no choca contra un cambio que, en los hechos, él mismo provocó.
		folderBump := map[string]int{}
		if len(changes) > 0 {
			// Serializa las escrituras de la cuenta desde el principio: evita interbloqueos y hace que el
			// orden de `seq` coincida con el de confirmación.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, p.UserID); err != nil {
				return err
			}
			if apperr := s.checkQuota(ctx, tx, changes); apperr != nil {
				return apperr
			}
		}
		for _, c := range changes {
			var err error
			if c.Entity == "folder" {
				err = s.applyFolder(ctx, tx, c, res, touched, folderBump)
			} else {
				err = s.applyNote(ctx, tx, p, c, res, touched, folderBump)
			}
			if err != nil {
				return err
			}
		}

		// Cursor: el seq de la cuenta. Todo lo ≤ cursor ya está confirmado (las escrituras de la cuenta
		// están serializadas), así que no se salta nada.
		var top int64
		if err := tx.QueryRow(ctx, `SELECT account_seq FROM users WHERE id = $1`, p.UserID).Scan(&top); err != nil {
			return err
		}
		res.Cursor = strconv.FormatInt(top, 10)
		remote, cursor, more, err := s.changesSince(ctx, tx, since, top, touched)
		if err != nil {
			return err
		}
		res.RemoteChanges = remote
		res.HasMore = more
		if more {
			res.Cursor = strconv.FormatInt(cursor, 10) // la página no llega hasta `top`
		}
		return nil
	})
	if err != nil {
		var ae *apperrors.Error
		if errors.As(err, &ae) {
			return nil, ae
		}
		if isUnique(err) {
			// Un id que ya pertenece a otra cuenta (o duplicado en la petición): se rechaza sin detalles.
			return nil, apperrors.Validation(map[string]string{"changes": "invalid-payload"})
		}
		return nil, apperrors.Internal(err)
	}
	return res, nil
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// checkQuota rechaza la petición si crearía más notas o carpetas de las permitidas.
func (s *Service) checkQuota(ctx context.Context, tx pgx.Tx, changes []parsed) error {
	newNotes, newFolders := 0, 0
	for _, c := range changes {
		if c.Op == "upsert" && c.BaseRevision == 0 {
			if c.Entity == "note" {
				newNotes++
			} else {
				newFolders++
			}
		}
	}
	if s.limits.QuotaBytes > 0 {
		var incoming int64
		for _, c := range changes {
			if c.Op != "upsert" {
				continue
			}
			if c.note != nil {
				incoming += int64(len(c.note.Payload) + len(c.note.WrappedKey))
			} else if c.folder != nil {
				incoming += int64(len(c.folder.Payload) + len(c.folder.WrappedKey))
			}
		}
		if incoming > 0 {
			// Cálculo prudente: no descuenta lo que reemplaza, así que cerca del límite puede rechazar de más.
			var used int64
			if err := tx.QueryRow(ctx, `SELECT
				(SELECT coalesce(sum(pg_column_size(payload) + pg_column_size(wrapped_key)), 0) FROM notes) +
				(SELECT coalesce(sum(pg_column_size(payload) + pg_column_size(wrapped_key)), 0) FROM folders)`).Scan(&used); err != nil {
				return err
			}
			if used+incoming > s.limits.QuotaBytes {
				return apperrors.Forbidden("quota-exceeded")
			}
		}
	}
	if newNotes == 0 && newFolders == 0 {
		return nil
	}
	var notes, folders int
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM notes), (SELECT count(*) FROM folders)`).Scan(&notes, &folders); err != nil {
		return err
	}
	if notes+newNotes > s.limits.MaxNotes || folders+newFolders > s.limits.MaxFolders {
		return apperrors.Forbidden("limit-reached")
	}
	return nil
}

func nextSeq(ctx context.Context, tx pgx.Tx) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT next_seq()`).Scan(&n)
	return n, err
}

// ── Notas ──────────────────────────────────────────────────────────

func (s *Service) applyNote(ctx context.Context, tx pgx.Tx, p Principal, c parsed, res *Response, touched map[string]bool, folderBump map[string]int) error {
	key := "note:" + c.ID
	var rev int
	err := tx.QueryRow(ctx, `SELECT revision FROM notes WHERE id = $1 FOR UPDATE`, c.ID).Scan(&rev)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if c.Op == "delete" {
		if exists {
			if _, err := tx.Exec(ctx, `DELETE FROM notes WHERE id = $1`, c.ID); err != nil {
				return err
			}
			if err := putTombstone(ctx, tx, "note", c.ID, rev); err != nil {
				return err
			}
		}
		res.Applied = append(res.Applied, Applied{Entity: "note", ID: c.ID, Revision: rev})
		touched[key] = true
		return nil
	}

	n := c.note
	if n.DeletedAt != nil {
		// Una nota en la papelera deja de ser pública: se revoca su enlace.
		if _, err := tx.Exec(ctx, `DELETE FROM share_links WHERE note_id = $1`, c.ID); err != nil {
			return err
		}
	}
	if !exists {
		seq, err := nextSeq(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notes (id, user_id, folder_id, revision, seq, created_at, updated_at, deleted_at, last_edited_device_id, wrapped_key, payload)
			VALUES ($1, app_user_id(), $2, 1, $3, $4, $5, $6, $7, $8, $9)`,
			c.ID, n.FolderID, seq, n.CreatedAt, n.UpdatedAt, n.DeletedAt, p.DeviceID, n.WrappedKey, n.Payload); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM tombstones WHERE entity = 'note' AND id = $1`, c.ID); err != nil {
			return err
		}
		res.Applied = append(res.Applied, Applied{Entity: "note", ID: c.ID, Revision: 1})
		touched[key] = true
		return nil
	}

	prior, bumped := folderBump[c.ID]
	if rev != c.BaseRevision && !(bumped && prior == c.BaseRevision) {
		// El servidor no pisa: devuelve su versión y el cliente decide (local, remota o ambas).
		remote, err := s.readNote(ctx, tx, c.ID)
		if err != nil {
			return err
		}
		res.Conflicts = append(res.Conflicts, ConflictReport{NoteID: c.ID, Remote: *remote, RemoteDeviceName: s.deviceName(ctx, tx, remote.LastEditedDeviceID)})
		return nil
	}
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE notes SET folder_id = $2, revision = revision + 1, seq = $3, created_at = $4, updated_at = $5,
		deleted_at = $6, last_edited_device_id = $7, wrapped_key = $8, payload = $9 WHERE id = $1`,
		c.ID, n.FolderID, seq, n.CreatedAt, n.UpdatedAt, n.DeletedAt, p.DeviceID, n.WrappedKey, n.Payload); err != nil {
		return err
	}
	res.Applied = append(res.Applied, Applied{Entity: "note", ID: c.ID, Revision: rev + 1})
	touched[key] = true
	return nil
}

func putTombstone(ctx context.Context, tx pgx.Tx, entity, id string, revision int) error {
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tombstones (user_id, entity, id, revision, seq) VALUES (app_user_id(), $1, $2, $3, $4)
		ON CONFLICT (user_id, entity, id) DO UPDATE SET revision = EXCLUDED.revision, seq = EXCLUDED.seq, created_at = now()`, entity, id, revision, seq)
	return err
}

// deviceName devuelve el nombre del dispositivo que hizo el último cambio (aunque ya esté cerrado).
func (s *Service) deviceName(ctx context.Context, tx pgx.Tx, deviceID string) string {
	if !validUUID(deviceID) {
		return unknownDevice
	}
	var name string
	if err := tx.QueryRow(ctx, `SELECT name FROM devices WHERE id = $1`, deviceID).Scan(&name); err != nil {
		return unknownDevice
	}
	return name
}

// ── Carpetas ───────────────────────────────────────────────────────

// Las carpetas no tienen conflictos: gana el último cambio.
func (s *Service) applyFolder(ctx context.Context, tx pgx.Tx, c parsed, res *Response, touched map[string]bool, folderBump map[string]int) error {
	key := "folder:" + c.ID
	touched[key] = true
	var rev int
	err := tx.QueryRow(ctx, `SELECT revision FROM folders WHERE id = $1 FOR UPDATE`, c.ID).Scan(&rev)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	next := rev + 1

	if c.Op == "delete" {
		if exists {
			if _, err := tx.Exec(ctx, `DELETE FROM folders WHERE id = $1`, c.ID); err != nil {
				return err
			}
			if err := putTombstone(ctx, tx, "folder", c.ID, next); err != nil {
				return err
			}
			// Sus notas pasan a "sin carpeta" también en el servidor (es un metadato; no hace falta descifrar).
			// Un seq por nota: el cursor de /sync necesita que sean únicos para poder paginar sin perder cambios.
			rows, err := tx.Query(ctx, `SELECT id::text, revision FROM notes WHERE folder_id = $1 FOR UPDATE`, c.ID)
			if err != nil {
				return err
			}
			type noteRev struct {
				id  string
				rev int
			}
			var notes []noteRev
			for rows.Next() {
				var nr noteRev
				if err := rows.Scan(&nr.id, &nr.rev); err != nil {
					rows.Close()
					return err
				}
				notes = append(notes, nr)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, nr := range notes {
				seq, err := nextSeq(ctx, tx)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE notes SET folder_id = NULL, revision = revision + 1, seq = $2 WHERE id = $1`, nr.id, seq); err != nil {
					return err
				}
				// Guarda la revisión que tenía antes de esta subida de rebote: un upsert/delete de esta
				// misma petición con esa baseRevision no es un conflicto real (ver applyNote).
				folderBump[nr.id] = nr.rev
			}
		}
		res.Applied = append(res.Applied, Applied{Entity: "folder", ID: c.ID, Revision: next})
		return nil
	}

	f := c.folder
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return err
	}
	if exists {
		_, err = tx.Exec(ctx, `UPDATE folders SET revision = $2, seq = $3, created_at = $4, updated_at = $5, wrapped_key = $6, payload = $7 WHERE id = $1`,
			c.ID, next, seq, f.CreatedAt, f.UpdatedAt, f.WrappedKey, f.Payload)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO folders (id, user_id, revision, seq, created_at, updated_at, wrapped_key, payload) VALUES ($1, app_user_id(), $2, $3, $4, $5, $6, $7)`,
			c.ID, next, seq, f.CreatedAt, f.UpdatedAt, f.WrappedKey, f.Payload)
		if err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM tombstones WHERE entity = 'folder' AND id = $1`, c.ID)
		}
	}
	if err != nil {
		return err
	}
	res.Applied = append(res.Applied, Applied{Entity: "folder", ID: c.ID, Revision: next})
	return nil
}

// ── Lo que cambió en otros dispositivos ───────────────────────────────────

// changesSince devuelve una PÁGINA acotada (por número de elementos y por bytes) de lo cambiado con
// seq en (since, top], en orden de seq. Si no cabe todo devuelve more=true y el cursor del último
// elemento incluido; los que comparten seq con él se incluyen todos (si no, se perderían). Así una
// cuenta grande no obliga al servidor a armar una respuesta de cientos de MB en memoria.
func (s *Service) changesSince(ctx context.Context, tx pgx.Tx, since, top int64, touched map[string]bool) (out []RemoteChange, cursor int64, more bool, err error) {
	maxItems, maxBytes := s.limits.MaxRemote, s.limits.RemoteBytes
	if maxItems < 1 {
		maxItems = 500
	}
	if maxBytes < 1 {
		maxBytes = 8 << 20
	}

	// 1) Solo metadatos (entidad, id, seq, tamaño): barato aunque haya muchas filas.
	rows, err := tx.Query(ctx, `
		SELECT entity, id, seq, sz, rev FROM (
			SELECT 'folder' AS entity, id::text AS id, seq, (pg_column_size(payload) + pg_column_size(wrapped_key))::bigint AS sz, revision::bigint AS rev FROM folders WHERE seq > $1 AND seq <= $2
			UNION ALL
			SELECT 'note', id::text, seq, (pg_column_size(payload) + pg_column_size(wrapped_key))::bigint, revision::bigint FROM notes WHERE seq > $1 AND seq <= $2
			UNION ALL
			SELECT 'tomb-' || entity, id::text, seq, 0::bigint, revision::bigint FROM tombstones WHERE seq > $1 AND seq <= $2
		) x ORDER BY seq, entity, id LIMIT $3`, since, top, int64(maxItems+len(touched)+1))
	if err != nil {
		return nil, 0, false, err
	}
	type meta struct {
		entity, id     string
		seq, size, rev int64
	}
	var metas []meta
	for rows.Next() {
		var m meta
		if err := rows.Scan(&m.entity, &m.id, &m.seq, &m.size, &m.rev); err != nil {
			rows.Close()
			return nil, 0, false, err
		}
		metas = append(metas, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	scanned := len(metas) >= maxItems+len(touched)+1 // el LIMIT cortó: puede haber más

	// 2) Se eligen los que caben, sin partir un grupo con el mismo seq.
	var picked []meta
	var bytes int64
	included := 0
	for _, m := range metas {
		// Los seq son únicos por cuenta (cada escritura toma el suyo), así que cortar entre dos
		// elementos nunca separa cambios que compartan cursor.
		if touched[strings.TrimPrefix(m.entity, "tomb-")+":"+m.id] {
			cursor = m.seq
			continue
		}
		if included > 0 && (included >= maxItems || bytes+m.size > maxBytes) {
			more = true
			break
		}
		picked = append(picked, m)
		included++
		bytes += m.size
		cursor = m.seq
	}
	if !more && scanned {
		more = true // había más filas tras el LIMIT
	}
	if !more {
		cursor = top
	}

	// 3) Se leen completas solo las elegidas.
	var noteIDs, folderIDs []string
	for _, m := range picked {
		switch m.entity {
		case "note":
			noteIDs = append(noteIDs, m.id)
		case "folder":
			folderIDs = append(folderIDs, m.id)
		}
	}
	notes := map[string]*EncryptedNote{}
	if len(noteIDs) > 0 {
		r, err := tx.Query(ctx, noteSelect+` WHERE id = ANY($1::uuid[])`, noteIDs)
		if err != nil {
			return nil, 0, false, err
		}
		for r.Next() {
			n, _, err := scanNote(r)
			if err != nil {
				r.Close()
				return nil, 0, false, err
			}
			notes[n.ID] = n
		}
		r.Close()
		if err := r.Err(); err != nil {
			return nil, 0, false, err
		}
	}
	folders := map[string]*EncryptedFolder{}
	if len(folderIDs) > 0 {
		r, err := tx.Query(ctx, `SELECT id::text, created_at, updated_at, revision, wrapped_key, payload FROM folders WHERE id = ANY($1::uuid[])`, folderIDs)
		if err != nil {
			return nil, 0, false, err
		}
		for r.Next() {
			var f EncryptedFolder
			if err := r.Scan(&f.ID, &f.CreatedAt, &f.UpdatedAt, &f.Revision, &f.WrappedKey, &f.Payload); err != nil {
				r.Close()
				return nil, 0, false, err
			}
			folders[f.ID] = &f
		}
		r.Close()
		if err := r.Err(); err != nil {
			return nil, 0, false, err
		}
	}

	// Carpetas antes que notas, y cada grupo por orden de cambio (picked ya viene por seq).
	rank := func(entity string) int {
		if entity == "folder" {
			return 0
		}
		return 1
	}
	sort.SliceStable(picked, func(i, j int) bool { return rank(picked[i].entity) < rank(picked[j].entity) })
	for _, m := range picked {
		switch m.entity {
		case "folder":
			if f := folders[m.id]; f != nil {
				out = append(out, RemoteChange{Entity: "folder", ID: f.ID, Revision: f.Revision, Folder: f})
			}
		case "note":
			if n := notes[m.id]; n != nil {
				out = append(out, RemoteChange{Entity: "note", ID: n.ID, Revision: n.Revision, Note: n})
			}
		default: // lápida
			out = append(out, RemoteChange{Entity: strings.TrimPrefix(m.entity, "tomb-"), ID: m.id, Deleted: true, Revision: int(m.rev)})
		}
	}
	if out == nil {
		out = []RemoteChange{}
	}
	return out, cursor, more, nil
}
