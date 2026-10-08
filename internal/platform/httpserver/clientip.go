package httpserver

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP devuelve la IP del cliente. Con trustProxy (detrás de Caddy) usa la última entrada de
// X-Forwarded-For, la que añadió nuestro proxy; las anteriores las puede falsificar el cliente y se
// ignoran. Sin proxy de confianza usa la dirección de la conexión y no mira la cabecera.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return "unknown"
}
