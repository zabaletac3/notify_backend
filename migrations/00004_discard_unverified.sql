-- +goose Up
-- La API no puede borrar usuarios (sin DELETE). Para sustituir un registro sin verificar —quien lo hizo
-- no era dueño del correo— se ofrece esta única vía, que solo toca filas sin verificar.
-- +goose StatementBegin
CREATE FUNCTION discard_unverified_user(p_email text) RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
  WITH d AS (DELETE FROM users WHERE email = p_email AND email_verified_at IS NULL RETURNING 1)
  SELECT count(*)::integer FROM d
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION discard_unverified_user(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION discard_unverified_user(text) TO apunte_app;

-- +goose Down
DROP FUNCTION discard_unverified_user(text);
