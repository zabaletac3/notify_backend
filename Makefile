.PHONY: run build test lint vuln fmt up down tidy
run:   ; go run ./cmd/api
build: ; go build ./...
test:  ; go test -race -cover ./...
lint:  ; golangci-lint run
vuln:  ; go run golang.org/x/vuln/cmd/govulncheck@latest ./...
fmt:   ; gofmt -w .
tidy:  ; go mod tidy
up:    ; docker compose up -d postgres
down:  ; docker compose down
