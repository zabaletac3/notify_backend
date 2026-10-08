# ---- builder ----
FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN for c in api migrate purge; do CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/$c ./cmd/$c; done

# ---- runner: sin shell, sin root, sistema de archivos de solo lectura al ejecutar ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/api /api
COPY --from=builder /out/migrate /migrate
COPY --from=builder /out/purge /purge
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/api"]
