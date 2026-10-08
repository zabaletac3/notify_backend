// Package mailer define el puerto de envío de correo y sus adaptadores.
//
// El resto de la aplicación depende solo de la interfaz Mailer. Para cambiar de
// proveedor (Resend, SES, SMTP...) se escribe un adaptador nuevo y se registra
// en New; no se toca ningún módulo de negocio.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// Message es un correo transaccional a un único destinatario.
type Message struct {
	To      string // dirección simple, sin nombre
	Subject string
	Text    string // versión en texto plano (obligatoria)
	HTML    string // opcional
	// IdempotencyKey evita duplicados si se reintenta el envío (si el proveedor lo admite).
	IdempotencyKey string
}

// Mailer es el puerto. Las implementaciones deben ser seguras para uso concurrente.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

var (
	// ErrInvalidMessage: el mensaje no es válido; reintentar no sirve.
	ErrInvalidMessage = errors.New("mailer: invalid message")
	// ErrTemporary: fallo transitorio del proveedor (red, 429, 5xx); se puede reintentar.
	ErrTemporary = errors.New("mailer: temporary failure")
	// ErrRejected: el proveedor rechazó el envío de forma definitiva.
	ErrRejected = errors.New("mailer: rejected by provider")
)

// Validate comprueba el mensaje antes de entregarlo a un adaptador. Impide la
// inyección de cabeceras (saltos de línea) en destinatario y asunto.
func (m Message) Validate() error {
	if strings.ContainsAny(m.To, "\r\n") || strings.ContainsAny(m.Subject, "\r\n") {
		return fmt.Errorf("%w: saltos de línea en cabeceras", ErrInvalidMessage)
	}
	addr, err := mail.ParseAddress(m.To)
	if err != nil || addr.Address != m.To {
		return fmt.Errorf("%w: destinatario", ErrInvalidMessage)
	}
	if strings.TrimSpace(m.Subject) == "" || strings.TrimSpace(m.Text) == "" {
		return fmt.Errorf("%w: asunto y texto son obligatorios", ErrInvalidMessage)
	}
	return nil
}

// MaskEmail oculta el usuario de una dirección para los logs (a***@dominio).
func MaskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at <= 0 {
		return "***"
	}
	return addr[:1] + "***" + addr[at:]
}
