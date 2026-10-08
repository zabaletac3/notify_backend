// Package contract comprueba que las rutas del router coinciden con el contrato
// openapi.yaml del repositorio de la web (docs/api/openapi.yaml).
//
// La ruta del contrato se lee de OPENAPI_PATH; sin esa variable se buscan las
// rutas relativas habituales (los repos viven uno al lado del otro). Si no hay
// contrato, en local la prueba se omite con un aviso y en CI (CI=true) falla:
// el contrato es obligatorio para poder compararlo.
package contract

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/zabaletac3/notify_backend/internal/testutil"
)

// openapiRelativas se prueban, en orden, cuando no hay OPENAPI_PATH.
var openapiRelativas = []string{
	filepath.Join("..", "notify_web", "docs", "api", "openapi.yaml"),             // relativa al paquete
	filepath.Join("..", "..", "notify_web", "docs", "api", "openapi.yaml"),       // hermano del repositorio (layout local)
	filepath.Join("..", "..", "..", "notify_web", "docs", "api", "openapi.yaml"), // hermano del workspace (CI)
}

// excepcion es una ruta que vive en el router pero fuera del contrato de la app.
// Si el contrato llega a describirla, hay que quitarla de esta lista (el test
// falla si una excepción deja de ser necesaria).
type excepcion struct {
	method string
	path   string
	why    string
}

func (e excepcion) clave() string { return e.method + " " + e.path }

var excepciones = []excepcion{
	{method: http.MethodGet, path: "/health", why: "sonda de vida del contenedor, fuera de /v1 y sin contrato"},
	{method: http.MethodGet, path: "/ready", why: "sonda de disponibilidad del contenedor, fuera de /v1 y sin contrato"},
}

// paramRe normaliza los parámetros de ruta ({id}, {slug}, {deviceId}…) a {}.
var paramRe = regexp.MustCompile(`\{[^{}]*}`)

func normaliza(ruta string) string { return paramRe.ReplaceAllString(ruta, "{}") }

func TestRouterMatchesOpenAPI(t *testing.T) {
	contrato := rutaContrato(t)

	env := testutil.New(t)
	mux, ok := env.H.(chi.Router)
	if !ok {
		t.Fatalf("el router del harness no implementa chi.Router: %T", env.H)
	}

	router := rutasRouter(t, mux)
	spec := rutasContrato(t, contrato)
	t.Logf("%d rutas en el router, %d en el contrato", len(router), len(spec))
	if len(router) == 0 {
		t.Fatal("chi.Walk no devolvió ninguna ruta del router")
	}
	if len(spec) == 0 {
		t.Fatalf("el contrato %s no declara ninguna ruta", contrato)
	}

	porClave := map[string]excepcion{}
	for _, ex := range excepciones {
		porClave[ex.clave()] = ex
	}
	uso := map[string]bool{}

	var enRouterNoContrato, enContratoNoRouter []string
	for ruta := range router {
		if spec[ruta] {
			continue
		}
		if _, ok := porClave[ruta]; ok {
			uso[ruta] = true
			continue
		}
		enRouterNoContrato = append(enRouterNoContrato, ruta)
	}
	for ruta := range spec {
		if router[ruta] {
			continue
		}
		if _, ok := porClave[ruta]; ok {
			uso[ruta] = true
			continue
		}
		enContratoNoRouter = append(enContratoNoRouter, ruta)
	}

	sort.Strings(enRouterNoContrato)
	sort.Strings(enContratoNoRouter)
	for _, ruta := range enRouterNoContrato {
		t.Errorf("en el router y no en el contrato: %s", ruta)
	}
	for _, ruta := range enContratoNoRouter {
		t.Errorf("en el contrato y no en el router: %s", ruta)
	}
	for _, ex := range excepciones {
		if !uso[ex.clave()] {
			t.Errorf("la excepción ya no hace falta: %s (%s); quítala de la lista de excepciones", ex.clave(), ex.why)
		}
	}
}

// rutaContrato devuelve la ruta del openapi.yaml: OPENAPI_PATH si está definida,
// o en su defecto las rutas relativas conocidas. Sin contrato: skip en local y
// fallo en CI.
func rutaContrato(t *testing.T) string {
	t.Helper()
	if ruta := os.Getenv("OPENAPI_PATH"); ruta != "" {
		if _, err := os.Stat(ruta); err != nil {
			t.Fatalf("OPENAPI_PATH=%q no se puede leer: %v", ruta, err)
		}
		return ruta
	}
	probadas := make([]string, 0, len(openapiRelativas))
	for _, rel := range openapiRelativas {
		if _, err := os.Stat(rel); err == nil {
			return rel
		}
		probadas = append(probadas, rel)
	}
	aviso := "no se encontró openapi.yaml (probado: " + strings.Join(probadas, ", ") + "); define OPENAPI_PATH"
	if os.Getenv("CI") == "true" {
		t.Fatalf("%s: en CI el contrato es obligatorio", aviso)
	}
	t.Skipf("%s: se omite la comprobación de rutas", aviso)
	return ""
}

// rutasRouter recorre el router con chi.Walk y devuelve "MÉTODO /ruta" con los
// parámetros normalizados. Ignora HEAD y OPTIONS.
func rutasRouter(t *testing.T, r chi.Router) map[string]bool {
	t.Helper()
	rutas := map[string]bool{}
	err := chi.Walk(r, func(method, ruta string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodHead || method == http.MethodOptions {
			return nil
		}
		rutas[method+" "+normaliza(ruta)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("recorriendo el router con chi.Walk: %v", err)
	}
	return rutas
}

type servidor struct {
	URL string `yaml:"url"`
}

type contrato struct {
	Servers []servidor                `yaml:"servers"`
	Paths   map[string]map[string]any `yaml:"paths"`
}

// metodos son las claves de método de un PathItem en el YAML y su nombre HTTP.
// head y options se reconocen (para no tumbar el parseo) pero se ignoran.
var metodos = []struct{ yaml, http string }{
	{"get", http.MethodGet},
	{"post", http.MethodPost},
	{"put", http.MethodPut},
	{"patch", http.MethodPatch},
	{"delete", http.MethodDelete},
	{"head", http.MethodHead},
	{"options", http.MethodOptions},
}

// clavesPathItem son las claves de un PathItem que no son métodos (OpenAPI 3.1).
var clavesPathItem = map[string]bool{
	"$ref":        true,
	"description": true,
	"parameters":  true,
	"servers":     true,
	"summary":     true,
}

// rutasContrato arma "MÉTODO /ruta" a partir del YAML, con el prefijo de `servers`
// (p. ej. /v1) y los parámetros normalizados.
func rutasContrato(t *testing.T, ruta string) map[string]bool {
	t.Helper()
	datos, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("leyendo el contrato %s: %v", ruta, err)
	}
	var doc contrato
	if err := yaml.Unmarshal(datos, &doc); err != nil {
		t.Fatalf("parseando el contrato %s con gopkg.in/yaml.v3: %v", ruta, err)
	}
	prefijo := prefijoServidores(t, doc.Servers)

	rutas := map[string]bool{}
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/") {
			t.Fatalf("ruta del contrato sin barra inicial: %q", path)
		}
		for clave := range item {
			if strings.HasPrefix(clave, "x-") || clavesPathItem[clave] || esMetodo(clave) {
				continue
			}
			t.Fatalf("clave desconocida en %q del contrato: %q (¿método mal escrito?)", path, clave)
		}
		for _, m := range metodos {
			if _, ok := item[m.yaml]; !ok || m.http == http.MethodHead || m.http == http.MethodOptions {
				continue
			}
			rutas[m.http+" "+prefijo+normaliza(path)] = true
		}
	}
	return rutas
}

func esMetodo(clave string) bool {
	for _, m := range metodos {
		if m.yaml == clave {
			return true
		}
	}
	return false
}

// prefijoServidores devuelve el prefijo de ruta común a todos los `servers`
// del contrato (p. ej. /v1 para https://api.apunte.app/v1).
func prefijoServidores(t *testing.T, servidores []servidor) string {
	t.Helper()
	if len(servidores) == 0 {
		t.Fatal("el contrato no declara `servers`: hace falta el prefijo (p. ej. /v1)")
	}
	prefijo := ""
	for i, s := range servidores {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatalf("servers[%d] (%q) no es una URL: %v", i, s.URL, err)
		}
		p := strings.TrimSuffix(u.Path, "/")
		if i == 0 {
			prefijo = p
			continue
		}
		if p != prefijo {
			t.Fatalf("los servers del contrato no comparten prefijo: %q frente a %q", servidores[0].URL, s.URL)
		}
	}
	return prefijo
}
