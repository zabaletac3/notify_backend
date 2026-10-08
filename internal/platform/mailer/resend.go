package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const resendEndpoint = "https://api.resend.com/emails"

// ResendMailer es el adaptador de Resend (API HTTP, sin SDK).
type ResendMailer struct {
	apiKey   string
	from     string
	endpoint string
	client   *http.Client
}

// NewResend crea el adaptador. endpoint vacío usa el de Resend (se cambia solo en pruebas).
func NewResend(apiKey, from, endpoint string) *ResendMailer {
	if endpoint == "" {
		endpoint = resendEndpoint
	}
	return &ResendMailer{
		apiKey: apiKey, from: from, endpoint: endpoint,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

type resendPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
	HTML    string   `json:"html,omitempty"`
}

func (r *ResendMailer) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(resendPayload{From: r.from, To: []string{msg.To}, Subject: msg.Subject, Text: msg.Text, HTML: msg.HTML})
	if err != nil {
		return fmt.Errorf("%w: serialización", ErrInvalidMessage)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: petición", ErrTemporary)
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if msg.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", msg.IdempotencyKey)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		// No se envuelve err: la URL/cabeceras no deben acabar en logs.
		return fmt.Errorf("%w: red", ErrTemporary)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%w: estado %d", ErrTemporary, resp.StatusCode)
	default:
		return fmt.Errorf("%w: estado %d", ErrRejected, resp.StatusCode)
	}
}
