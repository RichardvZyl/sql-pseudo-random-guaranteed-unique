/* =============================================================================
   pin_04_dispense.sql
   usp_DispensePins - the hot path. Single responsibility: destructively
   return random, unique, still-encrypted pins.

   Deploy order : 4 of 6

   What this statement does NOT contain - by design:
     * no crypto            (values were minted random at seed; the symmetric
                             key is never opened here; decryption is pin_05,
                             owned by the downstream system)
     * no random draw       (FIFO over F_K(counter) IS the cryptographically
                             secure pseudorandom sequence)
     * no count / modulo    (no density invariant exists to maintain)
     * no swap              (a uniform set is uniform in every consumption
                             order; data movement would buy nothing)
     * no shared state      (no tail mutex, no exact-count read)

   Concurrency: ROWLOCK + UPDLOCK + READPAST is the canonical parallel queue
   pop - N concurrent callers skip each other's locked rows and claim N
   DISTINCT head rows with zero blocking, zero deadlocks, zero retries.
   Throughput scales with cores. Under READ COMMITTED as specified.

   Rollback safety: if a caller's transaction rolls back, the row simply
   reappears at the head and is claimed by the next caller - a hole is
   harmless here, unlike under dense-keyspace addressing.

   Fragmentation: deletes are strictly head-side; pages empty in key order
   and deallocate whole. The watermark read is a performance aid that lets
   the seek start past ghost records under massive delete volume - never a
   correctness dependency (watermark = -1 forever would still be correct).
   ============================================================================= */

SET XACT_ABORT ON;
GO

CREATE OR ALTER PROCEDURE dbo.usp_DispensePins
    @Count int = 1
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @Count IS NULL OR @Count < 1 OR @Count > 1000
        THROW 50014, 'usp_DispensePins: @Count must be between 1 and 1,000.', 1;

    DECLARE @wm bigint = (SELECT WatermarkCodeId FROM dbo.PinDispenseControl);

    DECLARE @out TABLE
    (
        CodeId        bigint        NOT NULL,
        CodeEncrypted varbinary(96) NOT NULL
    );

    ;WITH head AS
    (
        SELECT TOP (@Count) CodeId, CodeEncrypted
        FROM dbo.Pin WITH (ROWLOCK, UPDLOCK, READPAST)
        WHERE CodeId > @wm
        ORDER BY CodeId
    )
    DELETE FROM head
    OUTPUT deleted.CodeId, deleted.CodeEncrypted INTO @out;

    IF NOT EXISTS (SELECT 1 FROM @out)
        THROW 50015, 'usp_DispensePins: pool exhausted. Run usp_SeedPins.', 1;

    -- Returns ciphertext plus the handle needed by pin_05 (the CodeId is the
    -- ENCRYPTBYKEY authenticator). Partial fulfilment is possible when the
    -- pool holds fewer than @Count rows; the caller sees the row count.
    SELECT CodeId, CodeEncrypted
    FROM @out
    ORDER BY CodeId;
END
GO

------------------------------------------------------------------------------
-- The dispensing system can pop pins but can never decrypt them.
------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'PinDispenserRole' AND type = 'R')
    CREATE ROLE PinDispenserRole;
GO
GRANT EXECUTE ON dbo.usp_DispensePins TO PinDispenserRole;
GO
