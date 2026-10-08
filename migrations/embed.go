// Package migrations incluye las migraciones SQL dentro del binario.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
