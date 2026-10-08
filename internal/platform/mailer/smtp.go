package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"time"
)

const smtpTimeout = 15 * time.Second

// SMTPMailer es el adaptador SMTP (sin dependencias externas).
//
// Puerto 465: TLS implícito. Cualquier otro (587): STARTTLS obligatorio; si el servidor no lo ofrece se
// rechaza el envío, para que la contraseña nunca viaje en claro.
type SMTPMailer struct {
	host, port string
	auth       smtp.Auth
	from       mail.Address
	// requireTLS solo se desactiva en pruebas, contra un servidor local sin TLS.
	requireTLS bool
}

// NewSMTP crea el adaptador. from admite "Nombre <dirección>" o solo la dirección.
func NewSMTP(host string, port int, user, password, from string) (*SMTPMailer, error) {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("mailer: MAIL_FROM no es válido")
	}
	return &SMTPMailer{
		host: host, port: strconv.Itoa(port),
		auth:       smtp.PlainAuth("", user, password, host),
		from:       *addr,
		requireTLS: true,
	}, nil
}

func (s *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	body, err := s.build(msg)
	if err != nil {
		return err
	}
	if err := s.deliver(ctx, msg.To, body); err != nil {
		return classifySMTP(err)
	}
	return nil
}

func (s *SMTPMailer) deliver(ctx context.Context, to string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()

	addr := net.JoinHostPort(s.host, s.port)
	tlsCfg := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if s.port == "465" {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()

	if s.port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return err
			}
		} else if s.requireTLS {
			return errors.New("smtp: el servidor no ofrece STARTTLS")
		}
	}
	if err := c.Auth(s.auth); err != nil {
		return err
	}
	if err := c.Mail(s.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// classifySMTP separa los fallos definitivos (5xx) de los transitorios (red, 4xx). No se envuelve el error
// original: podría contener el servidor o datos de la sesión y no debe acabar en logs.
func classifySMTP(err error) error {
	var tp *textproto.Error
	if errors.As(err, &tp) {
		if tp.Code >= 500 {
			return fmt.Errorf("%w: código %d", ErrRejected, tp.Code)
		}
		return fmt.Errorf("%w: código %d", ErrTemporary, tp.Code)
	}
	return fmt.Errorf("%w: smtp", ErrTemporary)
}

// build arma el mensaje RFC 5322: cabeceras codificadas, texto (y HTML si hay) en UTF-8 / quoted-printable.
func (s *SMTPMailer) build(msg Message) ([]byte, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("%w: id", ErrTemporary)
	}
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", s.from.String())
	h("To", msg.To)
	h("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domainOf(s.from.Address)+">")
	h("MIME-Version", "1.0")

	part := func(w *bytes.Buffer, ctype, content string) error {
		w.WriteString("Content-Type: " + ctype + "; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
		q := quotedprintable.NewWriter(w)
		if _, err := q.Write([]byte(content)); err != nil {
			return err
		}
		return q.Close()
	}

	if msg.HTML == "" {
		if err := part(&b, "text/plain", msg.Text); err != nil {
			return nil, fmt.Errorf("%w: cuerpo", ErrInvalidMessage)
		}
		return b.Bytes(), nil
	}
	boundary := "b-" + hex.EncodeToString(id)
	h("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, p := range []struct{ ctype, body string }{{"text/plain", msg.Text}, {"text/html", msg.HTML}} {
		b.WriteString("--" + boundary + "\r\n")
		if err := part(&b, p.ctype, p.body); err != nil {
			return nil, fmt.Errorf("%w: cuerpo", ErrInvalidMessage)
		}
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes(), nil
}

func domainOf(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			return addr[i+1:]
		}
	}
	return "localhost"
}
