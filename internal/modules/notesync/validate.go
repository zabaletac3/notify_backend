package notesync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var sealedRe = regexp.MustCompile(`^a1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$`)

const (
	maxWrappedKeyLen  = 512
	maxNotePayloadLen = 1_500_000
	maxFolderPayload  = 65_536
	minYear, maxYear  = 1970, 2100
	maxCursorDigits   = 18
)

// parsed es un cambio ya validado.
type parsed struct {
	Change
	note   *NoteFields
	folder *FolderFields
}

func validUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == strings.ToLower(s)
}

func validTime(t time.Time) bool { return t.Year() >= minYear && t.Year() <= maxYear }

func sealed(s string, max int) bool { return len(s) <= max && sealedRe.MatchString(s) }

// parseCursor: null o vacío = desde el principio.
func parseCursor(c *string) (int64, bool) {
	if c == nil || *c == "" {
		return 0, true
	}
	if len(*c) > maxCursorDigits {
		return 0, false
	}
	n, err := strconv.ParseInt(*c, 10, 64)
	return n, err == nil && n >= 0
}

// validate comprueba toda la petición antes de aplicar nada. Devuelve campo → código de validación.
func validate(req *Request, maxChanges int) ([]parsed, map[string]string) {
	f := map[string]string{}
	if _, ok := parseCursor(req.Cursor); !ok {
		f["cursor"] = "invalid-payload"
	}
	if len(req.Changes) > maxChanges {
		f["changes"] = "invalid-payload"
		return nil, f
	}
	out := make([]parsed, 0, len(req.Changes))
	for i, c := range req.Changes {
		key := func(field string) string { return fmt.Sprintf("changes.%d.%s", i, field) }
		p := parsed{Change: c}
		if c.Entity != "note" && c.Entity != "folder" {
			f[key("entity")] = "invalid-payload"
		}
		if c.Op != "upsert" && c.Op != "delete" {
			f[key("op")] = "invalid-payload"
		}
		if !validUUID(c.ID) {
			f[key("id")] = "invalid-payload"
		}
		if c.BaseRevision < 0 || c.BaseRevision > 1<<30 {
			f[key("baseRevision")] = "invalid-payload"
		}
		if c.Op == "upsert" {
			if err := decodeData(&p); err != "" {
				f[key("data")] = err
			}
		}
		out = append(out, p)
	}
	if len(f) > 0 {
		return nil, f
	}
	return out, nil
}

func decodeData(p *parsed) string {
	if len(p.Data) == 0 || bytes.Equal(bytes.TrimSpace(p.Data), []byte("null")) {
		return "required"
	}
	dec := json.NewDecoder(bytes.NewReader(p.Data))
	dec.DisallowUnknownFields()
	switch p.Entity {
	case "note":
		var n NoteFields
		if dec.Decode(&n) != nil || !validTime(n.CreatedAt) || !validTime(n.UpdatedAt) ||
			(n.DeletedAt != nil && !validTime(*n.DeletedAt)) || (n.FolderID != nil && !validUUID(*n.FolderID)) {
			return "invalid-payload"
		}
		if !sealed(n.WrappedKey, maxWrappedKeyLen) || !sealed(n.Payload, maxNotePayloadLen) {
			return "invalid-payload"
		}
		p.note = &n
	case "folder":
		var fo FolderFields
		if dec.Decode(&fo) != nil || !validTime(fo.CreatedAt) || !validTime(fo.UpdatedAt) {
			return "invalid-payload"
		}
		if !sealed(fo.WrappedKey, maxWrappedKeyLen) || !sealed(fo.Payload, maxFolderPayload) {
			return "invalid-payload"
		}
		p.folder = &fo
	}
	return ""
}
