-- ============================================================================
-- pin_05_decrypt.sql
-- Separate, privileged decrypt operation. Separate role: pin_decryptor.
-- ============================================================================
CREATE OR REPLACE FUNCTION pin.usp_decrypt_pin(p_codeid bigint, p_codeencrypted bytea)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_akey bytea;
    v_mkey bytea;
    v_iv   bytea;
    v_ct   bytea;
    v_mac  bytea;
    v_calc bytea;
    v_plain bytea;
    v_len  int;
BEGIN
    SELECT aes_key, mac_key INTO v_akey, v_mkey FROM pin.pin_secret WHERE id;

    v_len := octet_length(p_codeencrypted);
    IF v_len IS NULL OR v_len < 48 THEN   -- iv(16) + mac(32) minimum
        RAISE EXCEPTION 'usp_decrypt_pin: malformed ciphertext for codeid %', p_codeid;
    END IF;

    v_iv  := substring(p_codeencrypted FROM 1 FOR 16);
    v_ct  := substring(p_codeencrypted FROM 17 FOR v_len - 48);
    v_mac := substring(p_codeencrypted FROM v_len - 31 FOR 32);

    -- Verify the CodeId-bound MAC BEFORE decrypting (encrypt-then-MAC).
    -- Wrong-row ciphertext, tampering, or corruption -> MAC mismatch -> hard
    -- error. This is the ENCRYPTBYKEY-authenticator (NULL-on-mismatch) analog.
    -- IS DISTINCT FROM is a constant-time-ish bytea compare; for strict
    -- constant time you could compare digests instead.
    v_calc := hmac(int8send(p_codeid) || v_iv || v_ct, v_mkey, 'sha256');
    IF v_calc IS DISTINCT FROM v_mac THEN
        RAISE EXCEPTION 'usp_decrypt_pin: integrity/authenticator failure for codeid % (tamper, corruption, or wrong-row ciphertext)', p_codeid;
    END IF;

    v_plain := decrypt_iv(v_ct, v_akey, v_iv, 'aes-cbc/pad:pkcs');
    IF v_plain IS NULL THEN
        RAISE EXCEPTION 'usp_decrypt_pin: decryption returned NULL for codeid %', p_codeid;
    END IF;

    -- Plaintext is returned to the caller only; never logged, never persisted.
    RETURN convert_from(v_plain, 'SQL_ASCII');
END;
$$;
ALTER FUNCTION pin.usp_decrypt_pin(bigint, bytea) OWNER TO pin_owner;

REVOKE ALL ON FUNCTION pin.usp_decrypt_pin(bigint, bytea) FROM PUBLIC;
-- Privilege separation: ONLY pin_decryptor may read plaintext. The dispensing
-- system (pin_dispenser) can pop pins it can never read.
GRANT EXECUTE ON FUNCTION pin.usp_decrypt_pin(bigint, bytea) TO pin_decryptor;
