-- ============================================================================
-- pin_04_dispense.sql
-- The hot path: destructive SKIP LOCKED head-drain. NO crypto, NO count/modulo,
-- NO random draw, NO shared-state write. Returns ciphertext + CodeId handle.
-- ============================================================================
CREATE OR REPLACE FUNCTION pin.usp_dispense_pins(p_count int)
RETURNS TABLE (codeid bigint, codeencrypted bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_wm bigint;
BEGIN
    IF p_count IS NULL OR p_count < 1 OR p_count > 1000 THEN
        RAISE EXCEPTION 'usp_dispense_pins: @count must be 1..1000 (got %)', p_count;
    END IF;

    -- Read the seek floor from the SEPARATE control table (never blocked by a
    -- long seed txn). Purely a performance aid; correctness does not depend on it.
    SELECT watermark_code_id INTO v_wm FROM pin.pin_dispense_control WHERE id;

    -- FOR UPDATE SKIP LOCKED is the exact READPAST + UPDLOCK + ROWLOCK analog.
    -- Per the manual: "any selected rows that cannot be immediately locked are
    -- skipped." Under READ COMMITTED (Postgres default), N concurrent callers
    -- skip each other's locked head rows and each claims N distinct rows: zero
    -- blocking, zero deadlocks, zero retries. A rollback makes the row reappear.
    RETURN QUERY
    DELETE FROM pin.pin p
     WHERE p.ctid IN (
            SELECT s.ctid
            FROM pin.pin s
            WHERE s.codeid > v_wm
            ORDER BY s.codeid
            LIMIT p_count
            FOR UPDATE SKIP LOCKED
     )
    RETURNING p.codeid, p.codeencrypted;   -- OUTPUT deleted.* analog
END;
$$;
ALTER FUNCTION pin.usp_dispense_pins(int) OWNER TO pin_owner;

REVOKE ALL ON FUNCTION pin.usp_dispense_pins(int) FROM PUBLIC;
-- The dispenser can POP pins but the function returns only ciphertext; it can
-- never read plaintext because it is not granted EXECUTE on usp_decrypt_pin.
GRANT EXECUTE ON FUNCTION pin.usp_dispense_pins(int) TO pin_dispenser;
