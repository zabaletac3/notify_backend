package mailer

import (
	"context"
	"sync"
)

// MemoryMailer guarda los correos en memoria. Es el adaptador de las pruebas.
type MemoryMailer struct {
	mu   sync.Mutex
	sent []Message
	// Err, si no es nil, se devuelve en cada envío (para probar fallos).
	Err error
}

func (m *MemoryMailer) Send(_ context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.sent = append(m.sent, msg)
	return nil
}

// Sent devuelve una copia de lo enviado.
func (m *MemoryMailer) Sent() []Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Message(nil), m.sent...)
}
