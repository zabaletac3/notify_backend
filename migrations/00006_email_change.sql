-- +goose Up
-- Cambio de correo: el código se envía al correo nuevo, que se guarda aquí hasta confirmarlo.
ALTER TABLE verification_codes ADD COLUMN new_email text CHECK (new_email IS NULL OR (new_email = lower(new_email) AND length(new_email) <= 254));

-- +goose Down
ALTER TABLE verification_codes DROP COLUMN new_email;
