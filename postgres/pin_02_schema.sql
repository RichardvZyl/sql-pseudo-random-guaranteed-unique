-- ============================================================================
-- pin_02_schema.sql
-- Pin table (exactly ONE index), plus the two single-row control tables.
-- ============================================================================

-- The pin table. bigint PK = the clustered analog (Postgres has no clustered
-- index; the PK B-tree on codeid IS the only index). ONE index by design:
-- there is NO unique index on the encrypted value because the Feistel
-- bijection guarantees uniqueness by construction (see pin_01 invariants).
CREATE TABLE IF NOT EXISTS pin.pin (
    codeid         bigint  PRIMARY KEY,
    codeencrypted  bytea   NOT NULL,
    CONSTRAINT pin_codeid_range CHECK (codeid BETWEEN 0 AND 9999999999)
)
WITH (
    -- Rows are NEVER updated, so leave no free space for HOT updates.
    fillfactor = 100,
    -- High-churn table: make autovacuum aggressive so dead tuples/index
    -- entries at the drained head are reclaimed promptly and heap pages are
    -- returned to the FSM for reuse by new seed inserts.
    autovacuum_vacuum_scale_factor  = 0.02,
    autovacuum_vacuum_threshold     = 1000,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_insert_scale_factor = 0.02   -- PG13+; harmless if ignored
);
ALTER TABLE pin.pin OWNER TO pin_owner;

-- Gapless, reuse-free counter. Deliberately a manually-owned counter (NOT a
-- SEQUENCE): sequences are non-transactional and would leave gaps AND could
-- allow reuse on rollback. Because the seed function runs in the caller's
-- transaction, UPDATE ... RETURNING here is reverted on rollback -> gapless
-- (INVARIANT 3). This intentionally serializes concurrent seeds on this row.
CREATE TABLE IF NOT EXISTS pin.pin_seed_control (
    id           boolean PRIMARY KEY DEFAULT true CHECK (id),
    next_code_id bigint  NOT NULL DEFAULT 0 CHECK (next_code_id BETWEEN 0 AND 10000000000)
);
ALTER TABLE pin.pin_seed_control OWNER TO pin_owner;
INSERT INTO pin.pin_seed_control (id, next_code_id) VALUES (true, 0)
ON CONFLICT (id) DO NOTHING;

-- Dispense seek floor. PURELY a performance aid to skip drained/ghost head
-- rows; NEVER a correctness dependency. Kept in a SEPARATE table so a long
-- seed transaction (which locks pin_seed_control) never blocks dispense reads.
CREATE TABLE IF NOT EXISTS pin.pin_dispense_control (
    id                boolean PRIMARY KEY DEFAULT true CHECK (id),
    watermark_code_id bigint  NOT NULL DEFAULT -1
);
ALTER TABLE pin.pin_dispense_control OWNER TO pin_owner;
INSERT INTO pin.pin_dispense_control (id, watermark_code_id) VALUES (true, -1)
ON CONFLICT (id) DO NOTHING;

REVOKE ALL ON pin.pin, pin.pin_seed_control, pin.pin_dispense_control FROM PUBLIC;
