-- +goose Up
-- Bloqueo progresivo: cada vez que se supera el límite sube `strikes` y se duplica el bloqueo.
ALTER TABLE rate_limits ADD COLUMN strikes integer NOT NULL DEFAULT 0 CHECK (strikes >= 0);

-- +goose Down
ALTER TABLE rate_limits DROP COLUMN strikes;
