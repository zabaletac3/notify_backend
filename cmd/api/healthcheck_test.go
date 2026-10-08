package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   int
	}{{"listo", http.StatusOK, 0}, {"no listo", http.StatusServiceUnavailable, 1}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ready" {
				t.Errorf("ruta inesperada: %s", r.URL.Path)
			}
			w.WriteHeader(tc.status)
		}))
		_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
		t.Setenv("PORT", port)
		if got := healthcheck(); got != tc.want {
			t.Errorf("%s: código %d, esperaba %d", tc.name, got, tc.want)
		}
		srv.Close()
	}
	t.Setenv("PORT", "1") // nadie escucha
	if healthcheck() != 1 {
		t.Error("sin servidor debe fallar")
	}
}
