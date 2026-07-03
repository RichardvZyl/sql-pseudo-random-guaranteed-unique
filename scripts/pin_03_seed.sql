/* =============================================================================
   pin_03_seed.sql
   usp_SeedPins - batch generation. This is where randomness and uniqueness
   are minted; everything downstream is plain storage mechanics.

   Deploy order : 3 of 6

   How a code is made:
     n = next counter value (never repeats)
     split: L = n / 100000, R = n % 100000
     six rounds of: (L, R) <- (R, (L + F_i(R)) mod 100000)
        where F_i(R) = int56( SHA-256( key || i || R ) ) mod 100000
     code = L * 100000 + R, zero-padded to char(10)

   Why this is unique:  each round is invertible (R = L'; L = (R' - F(L'))
   mod 100000 - the hash is only ever run FORWARD, so any round function
   yields a reversible round), a composition of invertible steps is a
   bijection on [0, 10^10), and unique inputs through a bijection are unique
   outputs. No unique index, no dedup, no retry - across all seed runs.

   Why this is random:  the key is 256 CSPRNG bits and the keyed-hash Feistel
   is a pseudorandom permutation (Luby-Rackoff; same construction family as
   NIST FF1/FF3), so F_K(0), F_K(1), F_K(2), ... is computationally
   indistinguishable from uniform 10-digit draws WITHOUT replacement. FIFO
   dispensing therefore already emits a cryptographically secure pseudorandom
   sequence - selection-time shuffling would add nothing.

   Concurrency: the counter reservation serializes concurrent seed runs (an
   ops/batch activity, by design - and it is what makes seeding gapless: a
   failed insert rolls the counter back too). Seeding appends at the max end
   of the B-tree while dispensing deletes at the min end, so the two run
   concurrently without touching.
   ============================================================================= */

SET XACT_ABORT ON;
GO

CREATE OR ALTER PROCEDURE dbo.usp_SeedPins
    @Count int
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @Count IS NULL OR @Count < 1 OR @Count > 1000000
        THROW 50011, 'usp_SeedPins: @Count must be between 1 and 1,000,000 per run.', 1;

    BEGIN TRY
        BEGIN TRANSACTION;

        ------------------------------------------------------------------
        -- Atomic range reservation: [@first, @first + @Count - 1].
        ------------------------------------------------------------------
        DECLARE @res TABLE (FirstId bigint NOT NULL);

        UPDATE dbo.PinSeedControl
           SET NextCodeId = NextCodeId + @Count
        OUTPUT deleted.NextCodeId INTO @res;

        DECLARE @first bigint = (SELECT FirstId FROM @res);

        IF @first + @Count - 1 > 9999999999
            THROW 50012, 'usp_SeedPins: 10-digit code space exhausted.', 1;

        ------------------------------------------------------------------
        -- Load the immutable key.
        ------------------------------------------------------------------
        OPEN SYMMETRIC KEY PinCodeKey DECRYPTION BY CERTIFICATE PinCodeCert;

        DECLARE @fk varbinary(32) =
            (SELECT DECRYPTBYKEY(SecretValue)
             FROM dbo.PinSecret WHERE SecretName = N'FeistelKey');

        IF @fk IS NULL
            THROW 50013, 'usp_SeedPins: FeistelKey missing or undecryptable. Run pin_01_security_setup.sql.', 1;

        ------------------------------------------------------------------
        -- Set-based Feistel: no scalar UDFs, no loops, no data movement.
        -- SUBSTRING(hash, 1, 7) is a non-negative 56-bit value, so no sign
        -- handling is needed; modulo bias at 2^56 -> 10^5 is ~2^-40 per
        -- round: constant, key-independent, cryptographically irrelevant.
        ------------------------------------------------------------------
        ;WITH T (x) AS (SELECT 0 FROM (VALUES (0),(0),(0),(0),(0),(0),(0),(0),(0),(0)) v(x)), -- 10
        T3 (x) AS (SELECT 0 FROM T a CROSS JOIN T b CROSS JOIN T c),                           -- 10^3
        Nums AS (SELECT TOP (@Count)
                        i = ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1
                 FROM T3 a CROSS JOIN T3 b),                                                   -- up to 10^6
        Seed AS (SELECT CodeId = @first + n.i,
                        L = (@first + n.i) / 100000,
                        R = (@first + n.i) % 100000
                 FROM Nums n),
        F1 AS (SELECT s.CodeId, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x01 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM Seed s),
        F2 AS (SELECT s.CodeId, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x02 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F1 s),
        F3 AS (SELECT s.CodeId, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x03 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F2 s),
        F4 AS (SELECT s.CodeId, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x04 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F3 s),
        F5 AS (SELECT s.CodeId, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x05 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F4 s),
        F6 AS (SELECT s.CodeId, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x06 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F5 s),
        Final AS (SELECT CodeId,
                         Code = CONVERT(char(10),
                                RIGHT(REPLICATE('0', 10)
                                      + CONVERT(varchar(10), L * 100000 + R), 10))
                  FROM F6)
        INSERT dbo.Pin (CodeId, CodeEncrypted)
        SELECT f.CodeId,
               -- CodeId as authenticator: ciphertext is cryptographically
               -- bound to its handle; a copied/moved ciphertext decrypts to
               -- NULL instead of double-issuing a pin.
               ENCRYPTBYKEY(KEY_GUID('PinCodeKey'), f.Code,
                            1, CONVERT(varbinary(8), f.CodeId))
        FROM Final f;

        CLOSE SYMMETRIC KEY PinCodeKey;
        COMMIT TRANSACTION;

        SELECT FirstCodeId = @first,
               LastCodeId  = @first + @Count - 1,
               PinsSeeded  = @Count;
    END TRY
    BEGIN CATCH
        IF EXISTS (SELECT 1 FROM sys.openkeys WHERE key_name = 'PinCodeKey')
            CLOSE SYMMETRIC KEY PinCodeKey;
        IF XACT_STATE() <> 0
            ROLLBACK TRANSACTION;   -- counter reverts with the insert: gapless
        THROW;
    END CATCH;
END
GO

------------------------------------------------------------------------------
-- Seeding is an operational task, not an API capability.
------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'PinSeederRole' AND type = 'R')
    CREATE ROLE PinSeederRole;
GO
GRANT EXECUTE ON dbo.usp_SeedPins TO PinSeederRole;
GO
