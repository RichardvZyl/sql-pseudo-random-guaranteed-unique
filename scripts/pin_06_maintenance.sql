/* =============================================================================
   pin_06_maintenance.sql
   Maintenance owns the counters and the invariant audit. Note what is ABSENT:
   there is no REORGANIZE, no REBUILD, no defragmentation job of any kind -
   the sliding-window access pattern makes them structurally unnecessary.

   Deploy order : 6 of 6
   ============================================================================= */

SET XACT_ABORT ON;
GO

/* =============================================================================
   usp_AdvancePinWatermark
   Moves the dispense seek floor past confirmed-gone CodeIds so head seeks
   skip ghost records when delete volume outruns ghost cleanup. Lazy, cheap,
   safe to run on any schedule (or never - correctness does not depend on it).
   Monotonic by construction and conservative: MIN(CodeId) is read without
   READPAST so an in-flight (potentially rolling back) dispense can only make
   the watermark lower than optimal, never too high.
   ============================================================================= */
CREATE OR ALTER PROCEDURE dbo.usp_AdvancePinWatermark
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @floor bigint =
        ISNULL((SELECT MIN(CodeId) FROM dbo.Pin),
               (SELECT NextCodeId FROM dbo.PinSeedControl)) - 1;

    UPDATE dbo.PinDispenseControl
       SET WatermarkCodeId = @floor
     WHERE WatermarkCodeId < @floor;

    SELECT WatermarkCodeId FROM dbo.PinDispenseControl;
END
GO

/* =============================================================================
   usp_AuditPinIntegrity
   The backstop that replaced the unique index. Every row is independently
   verifiable: recompute F_K(CodeId) and compare with the decrypted value.
   A mismatch means one of the three invariants was violated (key changed,
   round count changed, counter reused) or the row was tampered with.
   Audits head-first (@MaxRows) since those rows are dispensed next;
   @MaxRows = NULL scans the full pool.
   ============================================================================= */
CREATE OR ALTER PROCEDURE dbo.usp_AuditPinIntegrity
    @MaxRows int = 10000
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @take bigint = ISNULL(CONVERT(bigint, @MaxRows), 9223372036854775807);

    BEGIN TRY
        OPEN SYMMETRIC KEY PinCodeKey DECRYPTION BY CERTIFICATE PinCodeCert;

        DECLARE @fk varbinary(32) =
            (SELECT DECRYPTBYKEY(SecretValue)
             FROM dbo.PinSecret WHERE SecretName = N'FeistelKey');

        IF @fk IS NULL
            THROW 50022, 'usp_AuditPinIntegrity: FeistelKey missing or undecryptable.', 1;

        ;WITH Seed AS (SELECT TOP (@take)
                              CodeId, CodeEncrypted,
                              L = CodeId / 100000,
                              R = CodeId % 100000
                       FROM dbo.Pin
                       ORDER BY CodeId),
        F1 AS (SELECT s.CodeId, s.CodeEncrypted, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x01 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM Seed s),
        F2 AS (SELECT s.CodeId, s.CodeEncrypted, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x02 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F1 s),
        F3 AS (SELECT s.CodeId, s.CodeEncrypted, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x03 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F2 s),
        F4 AS (SELECT s.CodeId, s.CodeEncrypted, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x04 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F3 s),
        F5 AS (SELECT s.CodeId, s.CodeEncrypted, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x05 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F4 s),
        F6 AS (SELECT s.CodeId, s.CodeEncrypted, L = s.R,
                      R = (s.L + CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256',
                              @fk + 0x06 + CONVERT(binary(4), CONVERT(int, s.R))), 1, 7))) % 100000
               FROM F5 s),
        Checked AS (SELECT CodeId,
                           Expected = CONVERT(char(10),
                                      RIGHT(REPLICATE('0', 10)
                                            + CONVERT(varchar(10), L * 100000 + R), 10)),
                           Actual   = CONVERT(char(10),
                                      DECRYPTBYKEY(CodeEncrypted, 1, CONVERT(varbinary(8), CodeId)))
                    FROM F6)
        SELECT RowsChecked = COUNT_BIG(*),
               Mismatches  = SUM(CASE WHEN Actual IS NULL OR Actual <> Expected THEN 1 ELSE 0 END)
        FROM Checked;

        CLOSE SYMMETRIC KEY PinCodeKey;
    END TRY
    BEGIN CATCH
        IF EXISTS (SELECT 1 FROM sys.openkeys WHERE key_name = 'PinCodeKey')
            CLOSE SYMMETRIC KEY PinCodeKey;
        THROW;
    END CATCH;
END
GO

/* =============================================================================
   usp_GetPinPoolStats
   Monitoring without touching the pool: row count from partition stats
   (no scan, no locks), plus counters and remaining code space.
   ============================================================================= */
CREATE OR ALTER PROCEDURE dbo.usp_GetPinPoolStats
AS
BEGIN
    SET NOCOUNT ON;

    SELECT ApproxAvailablePins = (SELECT SUM(ps.row_count)
                                  FROM sys.dm_db_partition_stats ps
                                  WHERE ps.object_id = OBJECT_ID('dbo.Pin')
                                    AND ps.index_id IN (0, 1)),
           NextCodeId          = (SELECT NextCodeId FROM dbo.PinSeedControl),
           WatermarkCodeId     = (SELECT WatermarkCodeId FROM dbo.PinDispenseControl),
           CodeSpaceRemaining  = 10000000000 - (SELECT NextCodeId FROM dbo.PinSeedControl);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'PinSeederRole' AND type = 'R')
    CREATE ROLE PinSeederRole;
GO
GRANT EXECUTE ON dbo.usp_AdvancePinWatermark TO PinSeederRole;
GRANT EXECUTE ON dbo.usp_AuditPinIntegrity   TO PinSeederRole;
GRANT EXECUTE ON dbo.usp_GetPinPoolStats     TO PinSeederRole;
GO

/* -----------------------------------------------------------------------------
   Smoke test (privileged user):

   EXEC dbo.usp_SeedPins @Count = 100000;
   EXEC dbo.usp_GetPinPoolStats;

   DECLARE @t TABLE (CodeId bigint, CodeEncrypted varbinary(96));
   INSERT @t EXEC dbo.usp_DispensePins @Count = 1;

   DECLARE @id bigint, @ct varbinary(96);
   SELECT @id = CodeId, @ct = CodeEncrypted FROM @t;
   EXEC dbo.usp_DecryptPin @CodeId = @id, @CodeEncrypted = @ct;

   EXEC dbo.usp_AuditPinIntegrity @MaxRows = 10000;   -- expect Mismatches = 0
   EXEC dbo.usp_AdvancePinWatermark;

   Concurrency proof (from a client box):
     ostress -n64 -r200 -Q"EXEC dbo.usp_DispensePins" ...
   Expect: 12,800 distinct CodeIds dispensed, zero deadlocks, zero blocking
   chains, and dm_db_index_physical_stats showing ~100% page density on
   PK_Pin before and after.
   ----------------------------------------------------------------------------- */
