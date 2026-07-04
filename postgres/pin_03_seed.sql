-- ============================================================================
-- pin_03_seed.sql
-- Set-based 6-round Feistel + gapless reservation + encrypt-then-MAC.
-- ============================================================================

-- Feistel round-function core, F_K(CodeId). IMMUTABLE so the planner can treat
-- it as constant per (codeid, key). plpgsql is NOT inlinable, but 6 rounds of
-- SHA-256 make a SQL-language inline version unwieldy; the batch is still
-- generated set-based (generate_series) with one call per row, which
-- parallelizes fine and keeps the code readable. Byte semantics MUST match the
-- T-SQL implementation exactly:
--   digest = SHA-256( key || round_byte(0x01..0x06) || R_as_4byte_bigendian )
--   F_i(R) = (first 7 bytes of digest as big-endian integer) mod 100000
CREATE OR REPLACE FUNCTION pin.feistel_encrypt(p_codeid bigint, p_key bytea)
RETURNS bigint
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    l   int := (p_codeid / 100000)::int;   -- high half, [0,100000)
    r   int := (p_codeid % 100000)::int;   -- low  half, [0,100000)
    i   int;
    d   bytea;
    f   bigint;
    nxt int;
BEGIN
    FOR i IN 1..6 LOOP
        -- int4send(r) is 4-byte big-endian (r < 100000 < 2^31, always positive).
        -- set_byte('\x00',0,i) is the single round byte 0x01..0x06.
        d := digest(p_key || set_byte('\x00'::bytea, 0, i) || int4send(r), 'sha256');
        -- first 7 bytes, big-endian -> bigint (max 2^56-1, fits in int8):
        f := (get_byte(d,0)::bigint << 48) | (get_byte(d,1)::bigint << 40)
           | (get_byte(d,2)::bigint << 32) | (get_byte(d,3)::bigint << 24)
           | (get_byte(d,4)::bigint << 16) | (get_byte(d,5)::bigint <<  8)
           |  get_byte(d,6)::bigint;
        nxt := ((l + (f % 100000)) % 100000)::int;   -- (L + F_i(R)) mod 100000
        l := r;
        r := nxt;
    END LOOP;
    RETURN l::bigint * 100000 + r;   -- recombine to [0,10^10)
END;
$$;
ALTER FUNCTION pin.feistel_encrypt(bigint, bytea) OWNER TO pin_owner;

-- Encrypt-then-MAC helper: AES-256-CBC (random IV) + HMAC-SHA-256 over
-- (codeid || iv || ct). The CodeId binding is the pgcrypto analog of the
-- ENCRYPTBYKEY authenticator: a ciphertext copied to another row verifies
-- against a different CodeId, the MAC fails, and decrypt raises.
-- Layout of codeencrypted: iv(16) || ciphertext(N) || mac(32).
CREATE OR REPLACE FUNCTION pin.pin_seal(p_codeid bigint, p_plain bytea,
                                        p_aes_key bytea, p_mac_key bytea)
RETURNS bytea
LANGUAGE sql VOLATILE          -- VOLATILE: gen_random_bytes must run per row
SET search_path = pg_catalog, pg_temp
AS $$
    WITH iv AS (SELECT gen_random_bytes(16) AS v),
         ct AS (SELECT iv.v AS v,
                       encrypt_iv(p_plain, p_aes_key, iv.v, 'aes-cbc/pad:pkcs') AS c
                FROM iv)
    SELECT ct.v || ct.c
         || hmac(int8send(p_codeid) || ct.v || ct.c, p_mac_key, 'sha256')
    FROM ct;
$$;
ALTER FUNCTION pin.pin_seal(bigint,bytea,bytea,bytea) OWNER TO pin_owner;

-- Seed function. A plain function (not PROCEDURE) on purpose: it runs in the
-- CALLER's transaction, so if the caller rolls back, the counter UPDATE is
-- reverted automatically -> gapless AND reuse-free (INVARIANT 3) with no extra
-- code. p_count in [1, 1000000].
CREATE OR REPLACE FUNCTION pin.usp_seed_pins(p_count int)
RETURNS bigint            -- number of rows seeded
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_start   bigint;
    v_fkey    bytea;
    v_akey    bytea;
    v_mkey    bytea;
    v_seeded  bigint;
BEGIN
    IF p_count IS NULL OR p_count < 1 OR p_count > 1000000 THEN
        RAISE EXCEPTION 'usp_seed_pins: @count must be 1..1000000 (got %)', p_count;
    END IF;

    -- Atomic range reservation. The UPDATE takes a row lock on the single
    -- control row (serializing concurrent seeds by design) and RETURNS the
    -- pre-increment value as the start of our reserved range.
    UPDATE pin.pin_seed_control
       SET next_code_id = next_code_id + p_count
     WHERE id
    RETURNING next_code_id - p_count INTO v_start;

    -- Exhaustion guard: never exceed the 10^10 space.
    IF v_start + p_count > 10000000000 THEN
        RAISE EXCEPTION 'usp_seed_pins: 10^10 pin space would be exhausted (start=%, count=%)',
              v_start, p_count;
    END IF;

    -- Load immutable keys (just reading the locked-down secret table).
    SELECT feistel_key, aes_key, mac_key INTO v_fkey, v_akey, v_mkey
    FROM pin.pin_secret WHERE id;

    -- Set-based generation: no scalar loops over the batch. Each CodeId maps
    -- to a bijective Feistel value, zero-padded to char(10), sealed.
    WITH ids AS (
        SELECT gs AS codeid
        FROM generate_series(v_start, v_start + p_count - 1) AS gs
    ), gen AS (
        SELECT codeid,
               lpad(pin.feistel_encrypt(codeid, v_fkey)::text, 10, '0') AS pin_text
        FROM ids
    )
    INSERT INTO pin.pin (codeid, codeencrypted)
    SELECT codeid,
           pin.pin_seal(codeid, convert_to(pin_text, 'SQL_ASCII'), v_akey, v_mkey)
    FROM gen;

    GET DIAGNOSTICS v_seeded = ROW_COUNT;
    RETURN v_seeded;
    -- On ANY error the whole function (and the counter UPDATE) rolls back with
    -- the caller's transaction: the counter reverts -> gapless. Keys are just
    -- local variables; nothing to "close" (unlike a T-SQL open symmetric key).
END;
$$;
ALTER FUNCTION pin.usp_seed_pins(int) OWNER TO pin_owner;

REVOKE ALL ON FUNCTION pin.usp_seed_pins(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pin.usp_seed_pins(int) TO pin_seeder;
