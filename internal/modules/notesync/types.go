// Package notesync implementa la sincronización de notas y carpetas cifradas (ADR 0004 y 0005):
// POST /sync más la lectura de notas y carpetas. El servidor solo ve metadatos y textos "a1.<iv>.<ct>";
// nunca descifra. Los conflictos de notas se devuelven al cliente, que decide.
package notesync

import (
	"encoding/json"
	"time"
)

// ── Filas tal como las guarda el servidor ───────────────────────────────────

type EncryptedNote struct {
	ID                 string     `json:"id"`
	FolderID           *string    `json:"folderId"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
	DeletedAt          *time.Time `json:"deletedAt"`
	Revision           int        `json:"revision"`
	LastEditedDeviceID string     `json:"lastEditedDeviceId"`
	WrappedKey         string     `json:"wrappedKey"`
	Payload            string     `json:"payload"`
}

type EncryptedFolder struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Revision   int       `json:"revision"`
	WrappedKey string    `json:"wrappedKey"`
	Payload    string    `json:"payload"`
}

// ── Petición ───────────────────────────────────────────────────────────

// NoteFields y FolderFields son lo que sube el cliente en un upsert.
type NoteFields struct {
	FolderID   *string    `json:"folderId"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	DeletedAt  *time.Time `json:"deletedAt"`
	WrappedKey string     `json:"wrappedKey"`
	Payload    string     `json:"payload"`
}

type FolderFields struct {
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	WrappedKey string    `json:"wrappedKey"`
	Payload    string    `json:"payload"`
}

type Change struct {
	Entity       string          `json:"entity"`
	ID           string          `json:"id"`
	Op           string          `json:"op"`
	BaseRevision int             `json:"baseRevision"`
	Data         json.RawMessage `json:"data,omitempty"`
}

// Request: deviceId y deviceName se aceptan por compatibilidad con el contrato, pero el servidor usa
// el dispositivo del token (el cliente no decide quién es).
type Request struct {
	DeviceID   string   `json:"deviceId"`
	DeviceName string   `json:"deviceName"`
	Cursor     *string  `json:"cursor"`
	Changes    []Change `json:"changes"`
}

// ── Respuesta ──────────────────────────────────────────────────────────

type Applied struct {
	Entity   string `json:"entity"`
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}

type RemoteChange struct {
	Entity   string           `json:"entity"`
	ID       string           `json:"id"`
	Deleted  bool             `json:"deleted"`
	Revision int              `json:"revision"`
	Note     *EncryptedNote   `json:"note,omitempty"`
	Folder   *EncryptedFolder `json:"folder,omitempty"`
}

type ConflictReport struct {
	NoteID           string        `json:"noteId"`
	Remote           EncryptedNote `json:"remote"`
	RemoteDeviceName string        `json:"remoteDeviceName"`
}

type Response struct {
	Cursor        string           `json:"cursor"`
	Applied       []Applied        `json:"applied"`
	RemoteChanges []RemoteChange   `json:"remoteChanges"`
	Conflicts     []ConflictReport `json:"conflicts"`
	// HasMore indica que quedan cambios remotos: el cliente debe volver a sincronizar con este cursor.
	HasMore bool `json:"hasMore"`
}

// Principal es quien sincroniza: cuenta y dispositivo del token.
type Principal struct{ UserID, DeviceID string }
