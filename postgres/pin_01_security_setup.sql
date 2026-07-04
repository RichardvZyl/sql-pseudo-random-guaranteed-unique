-- ============================================================================
-- pin_01_security_setup.sql
-- Encryption hierarchy, definer role, secret table, key generation.
-- PostgreSQL 13+. Requires pgcrypto (trusted ext on RDS/Aurora PG13+;
-- allowlist via azure.extensions on Azure Flexible Server; default postgres
-- user on Cloud SQL). No superuser needed beyond CREATE EXTENSION.
--
-- THREE INVARIANTS THE UNIQUENESS DEPENDS ON (documented at key creation):
--   (1) The Feistel key NEVER changes.
--   (2) The round count (6) NEVER changes.
--   (3) A CodeId is NEVER issued twice (gapless, reuse-free counter).
-- Violating any one silently breaks the bijection and can double-issue a pin.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Definer role owns the tables and the keys. All SECURITY DEFINER functions
-- run as this role. It is NOLOGIN: nobody connects as it directly.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pin_owner') THEN
    CREATE ROLE pin_owner NOLOGIN;
  END IF;
END$$;

-- Operational roles (NOLOGIN; GRANT them to real login roles as needed).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pin_seeder')    THEN CREATE ROLE pin_seeder    NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pin_dispenser') THEN CREATE ROLE pin_dispenser NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pin_decryptor') THEN CREATE ROLE pin_decryptor NOLOGIN; END IF;
END$$;

CREATE SCHEMA IF NOT EXISTS pin AUTHORIZATION pin_owner;

-- --------------------------------------------------------------------------
-- Secret table. Postgres has NO DMK/certificate hierarchy, so this is the
-- most portable pattern: a locked-down single-row table holding the keys,
-- readable ONLY by SECURITY DEFINER functions owned by pin_owner.
--
-- HONEST LIMITATION: cell-level crypto with in-database keys is still exposed
-- to a superuser (who can read any table and can SET ROLE). If you need keys
-- invisible to the DBA, pass them as function parameters from the app per call
-- or store only KMS-wrapped keys here. Default chosen: in-DB keys in a table
-- no login role can SELECT, which matches the T-SQL DMK/cert model's practical
-- trust boundary (a sysadmin can always open the cert too).
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pin.pin_secret (
    id            boolean      PRIMARY KEY DEFAULT true CHECK (id),  -- forces one row
    feistel_key   bytea        NOT NULL,   -- 32 bytes, immutable (INVARIANT 1)
    aes_key       bytea        NOT NULL,   -- 32 bytes, AES-256 confidentiality
    mac_key       bytea        NOT NULL,   -- 32 bytes, HMAC-SHA-256 integrity
    rounds        smallint     NOT NULL DEFAULT 6 CHECK (rounds = 6), -- INVARIANT 2
    created_at    timestamptz  NOT NULL DEFAULT now()
);
ALTER TABLE pin.pin_secret OWNER TO pin_owner;

-- Insert-once semantics: the PK + CHECK(id) guarantees a single row; a second
-- insert fails on the PK. Keys come from the CSPRNG (pgcrypto gen_random_bytes,
-- the analog of SQL Server's CRYPT_GEN_RANDOM).
INSERT INTO pin.pin_secret (id, feistel_key, aes_key, mac_key)
VALUES (true, gen_random_bytes(32), gen_random_bytes(32), gen_random_bytes(32))
ON CONFLICT (id) DO NOTHING;

-- Lock the secret down: no PUBLIC access at all.
REVOKE ALL ON pin.pin_secret FROM PUBLIC;
-- (No role is granted SELECT: only definer functions owned by pin_owner read it.)

-- CERTIFICATE/KEY BACKUP WARNING (analog of "back up your certificate"):
--   Back up pin.pin_secret the moment it is created. If feistel_key is lost you
--   CANNOT recompute or audit any issued pin; if aes_key/mac_key are lost every
--   stored ciphertext is unrecoverable. Losing the key == losing the data.
