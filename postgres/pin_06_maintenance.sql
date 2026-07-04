-- ============================================================================
-- pin_06_maintenance.sql
-- Watermark advance, integrity audit, pool stats. NO REINDEX jobs: the
-- sliding-window pattern keeps the B-tree healthy; autovacuum handles the rest.
-- ============================================================================

-- Advance the dispense seek floor. Monotonic and conservative: MIN(codeid)-1,
-- or next_code_id-1 if the table is empty. Never moves backward (GREATEST).
CREATE OR REPLACE FUNCTION pin.usp_advance_pin_watermark()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_min  bigint;
    v_next bigint;
    v_new  bigint;
BEGIN
    SELECT min(codeid) INTO v_min FROM pin.pin;
    SELECT next_code_id INTO v_next FROM pin.pin_seed_control WHERE id;
    v_new := COALESCE(v_min - 1, v_next - 1);
    UPDATE pin.pin_dispense_control
       SET watermark_code_id = GREATEST(watermark_code_id, v_new)
     WHERE id
    RETURNING watermark_code_id INTO v_new;
    RETURN v_new;
END;
$$;
ALTER FUNCTION pin.usp_advance_pin_watermark() OWNER TO pin_owner;

-- Integrity backstop that REPLACES the (deliberately absent) unique index:
-- recompute F_K(codeid) for the TOP-N head rows and compare against the
-- decrypted stored value. A mismatch means an invariant was violated
-- (key/round change) or the row was tampered with.
CREATE OR REPLACE FUNCTION pin.usp_audit_pin_integrity(p_top int DEFAULT 1000)
RETURNS TABLE (codeid bigint, expected text, stored text, ok boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_fkey bytea;
BEGIN
    SELECT feistel_key INTO v_fkey FROM pin.pin_secret WHERE id;
    RETURN QUERY
    WITH head AS (
        SELECT p.codeid, p.codeencrypted
        FROM pin.pin p ORDER BY p.codeid LIMIT p_top
    )
    SELECT h.codeid,
           lpad(pin.feistel_encrypt(h.codeid, v_fkey)::text, 10, '0') AS expected,
           pin.usp_decrypt_pin(h.codeid, h.codeencrypted)             AS stored,
           lpad(pin.feistel_encrypt(h.codeid, v_fkey)::text, 10, '0')
             = pin.usp_decrypt_pin(h.codeid, h.codeencrypted)         AS ok
    FROM head h;
END;
$$;
ALTER FUNCTION pin.usp_audit_pin_integrity(int) OWNER TO pin_owner;

-- Pool stats: approximate live count from planner stats + counters + remaining
-- space. Uses pg_class.reltuples (cheap, no full scan). For a fresher estimate
-- combine with pg_stat_user_tables.n_live_tup.
CREATE OR REPLACE FUNCTION pin.usp_get_pin_pool_stats()
RETURNS TABLE (approx_rows bigint, next_code_id bigint, watermark bigint, remaining_space bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT
      (SELECT GREATEST(c.reltuples, 0)::bigint
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='pin' AND c.relname='pin'),
      (SELECT next_code_id FROM pin.pin_seed_control WHERE id),
      (SELECT watermark_code_id FROM pin.pin_dispense_control WHERE id),
      (SELECT 10000000000 - next_code_id FROM pin.pin_seed_control WHERE id);
$$;
ALTER FUNCTION pin.usp_get_pin_pool_stats() OWNER TO pin_owner;

REVOKE ALL ON FUNCTION pin.usp_advance_pin_watermark()      FROM PUBLIC;
REVOKE ALL ON FUNCTION pin.usp_audit_pin_integrity(int)     FROM PUBLIC;
REVOKE ALL ON FUNCTION pin.usp_get_pin_pool_stats()         FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pin.usp_advance_pin_watermark()  TO pin_seeder;
GRANT EXECUTE ON FUNCTION pin.usp_audit_pin_integrity(int) TO pin_seeder;  -- uses decrypt path internally via definer
GRANT EXECUTE ON FUNCTION pin.usp_get_pin_pool_stats()     TO pin_seeder;

-- --------------------------------------------------------------------------
-- WHY NO REINDEX/REORG JOBS (MVCC honesty):
--   Seeds append strictly at the max codeid; dispense deletes strictly at the
--   min. Left-edge B-tree leaf pages empty completely and are recycled by
--   VACUUM (btree page deletion). Front heap pages become fully dead and are
--   REUSED by new seed inserts via the FSM. Postgres only truncates *trailing*
--   empty heap pages, so front-deletes don't shrink the file -- that's fine,
--   because seeds refill those pages. "No maintenance ever" (SQL Server) thus
--   becomes "autovacuum handles it; no manual REINDEX needed" in Postgres.
--   Because rows are never updated, HOT is irrelevant and fillfactor=100 is
--   optimal. Keep autovacuum aggressive (see pin_02 storage params). If a long
--   read/seed transaction ever holds back the xmin horizon, dead entries at the
--   head can linger; the dispense watermark keeps scans off them regardless.
-- --------------------------------------------------------------------------

-- SMOKE TEST (run as a privileged setup role):
--   SELECT pin.usp_seed_pins(1000);                       -- expect 1000
--   SELECT count(*) FROM pin.pin;                         -- expect 1000
--   SELECT * FROM pin.usp_dispense_pins(5);               -- 5 distinct rows
--   SELECT pin.usp_decrypt_pin(codeid, codeencrypted)     -- 10-digit text
--     FROM pin.usp_dispense_pins(1);
--   SELECT * FROM pin.usp_audit_pin_integrity(100);       -- all ok = true
--   SELECT * FROM pin.usp_get_pin_pool_stats();

-- pgbench CONCURRENCY TEST (replaces SQL Server ostress). Save as dispense.sql:
--   SELECT pin.usp_dispense_pins(10);
-- Run:  pgbench -n -c 64 -j 8 -T 60 -f dispense.sql "dbname=... user=pin_dispenser_login"
-- EXPECT: zero deadlocks, monotonically increasing total distinct codeids,
--   throughput scaling with -c up to CPU/IO limits (SKIP LOCKED => no convoy).
--   To assert distinctness, log returned ids to a scratch table and check
--   COUNT(*) = COUNT(DISTINCT codeid) afterward.
