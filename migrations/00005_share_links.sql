-- +goose Up
-- Enlaces públicos: id propio (lo expone el contrato), fecha de actualización y clave del enlace obligatoria.
ALTER TABLE share_links ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE share_links ADD CONSTRAINT share_links_id_key UNIQUE (id);
ALTER TABLE share_links ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE share_links ALTER COLUMN wrapped_key SET NOT NULL;
ALTER TABLE share_links ADD CONSTRAINT share_links_wrapped_key_len CHECK (length(wrapped_key) <= 512);

-- +goose Down
ALTER TABLE share_links DROP CONSTRAINT share_links_wrapped_key_len;
ALTER TABLE share_links ALTER COLUMN wrapped_key DROP NOT NULL;
ALTER TABLE share_links DROP COLUMN updated_at;
ALTER TABLE share_links DROP CONSTRAINT share_links_id_key;
ALTER TABLE share_links DROP COLUMN id;
