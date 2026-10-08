package notesync

import (
	"encoding/json"
	"testing"
)

// FuzzValidate: ninguna petición, por rara que sea, provoca un pánico; y si se acepta, todo está bien formado.
func FuzzValidate(f *testing.F) {
	f.Add([]byte(`{"cursor":null,"changes":[]}`))
	f.Add([]byte(`{"cursor":"12","changes":[{"entity":"note","id":"01a119d2-bc8e-7d83-b461-8de8e246853f","op":"upsert","baseRevision":1,"data":{"folderId":null,"createdAt":"2026-03-01T10:00:00Z","updatedAt":"2026-03-01T10:00:00Z","deletedAt":null,"wrappedKey":"a1.AAAAAAAAAAAAAAAA.QUJDRA","payload":"a1.BBBBBBBBBBBBBBBB.QUJDREVGRw"}}]}`))
	f.Add([]byte(`{"changes":[{"entity":"folder","id":"x","op":"delete","baseRevision":-1}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var req Request
		if json.Unmarshal(raw, &req) != nil {
			return
		}
		parsed, bad := validate(&req, 500)
		if (parsed == nil) == (bad == nil) && len(req.Changes) > 0 {
			t.Fatalf("o hay cambios válidos o errores, no ambos ni ninguno: %v %v", parsed, bad)
		}
		for _, p := range parsed {
			if !validUUID(p.ID) || p.BaseRevision < 0 {
				t.Fatalf("aceptó un cambio mal formado: %+v", p.Change)
			}
			if p.Op == "upsert" && p.note == nil && p.folder == nil {
				t.Fatalf("upsert sin datos aceptado: %+v", p.Change)
			}
			if p.note != nil && (!sealed(p.note.Payload, maxNotePayloadLen) || !sealed(p.note.WrappedKey, maxWrappedKeyLen)) {
				t.Fatalf("texto sin cifrar aceptado: %+v", p.note)
			}
		}
		if n, ok := parseCursor(req.Cursor); ok && n < 0 {
			t.Fatalf("cursor negativo aceptado: %d", n)
		}
	})
}
