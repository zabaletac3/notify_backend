.PHONY: migrate migrate-status test-db run build test lint vuln fmt up down tidy
run:   ; go run ./cmd/api
build: ; go build ./...
test:  ; go test -race -cover ./...
lint:  ; golangci-lint run
vuln:  ; go run golang.org/x/vuln/cmd/govulncheck@latest ./...
fmt:   ; gofmt -w .
tidy:  ; go mod tidy
up:    ; docker compose up -d postgres
down:  ; docker compose down
migrate:        ; go run ./cmd/migrate up
migrate-status: ; go run ./cmd/migrate status
# Pruebas con PostgreSQL real: TEST_DATABASE_URL apunta a un administrador (p. ej. el de `make up`).
test-db: ; TEST_DATABASE_URL=postgres://apunte:apunte@localhost:5432/postgres?sslmode=disable go test -race -count=1 ./...
