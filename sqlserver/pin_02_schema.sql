/* =============================================================================
   pin_02_schema.sql
   The pin pool: a sliding-window B-tree with exactly one index.

   Deploy order : 2 of 6
   Target       : SQL Server 2019+ (OPTIMIZE_FOR_SEQUENTIAL_KEY; remove the
                  option on 2016/2017 - correctness is unaffected)

   Fragmentation model (why no REORG/REBUILD is ever needed):
     * Seeding appends strictly at the max end (monotonic CodeId, FILLFACTOR
       100 packs pages completely; no interior inserts ever occur).
     * Dispensing deletes strictly from the min end; pages empty in key order
       and deallocate whole.
     * No column of a live row is ever updated, so no row can grow and no
       page can split. The B-tree slides forward at ~100% density for the
       lifetime of the table.
     * There is no second index. Uniqueness needs none (it holds by
       construction: unique CodeIds through the bijection F_K), and this
       component never looks up by value - so the only structure that could
       fragment does not exist.
   ============================================================================= */

SET XACT_ABORT ON;
GO

------------------------------------------------------------------------------
-- The pool. CodeId is an internal handle only: it is never returned by the
-- dispense path alone as a secret, it reveals nothing about the pin value
-- without the key (value = F_K(CodeId)), and it doubles as the ENCRYPTBYKEY
-- authenticator so a ciphertext copied or moved to another row fails
-- decryption instead of silently double-issuing a pin.
------------------------------------------------------------------------------
IF OBJECT_ID('dbo.Pin') IS NULL
BEGIN
    CREATE TABLE dbo.Pin
    (
        CodeId        bigint        NOT NULL,
        CodeEncrypted varbinary(96) NOT NULL,

        CONSTRAINT PK_Pin PRIMARY KEY CLUSTERED (CodeId)
            WITH (FILLFACTOR = 100, OPTIMIZE_FOR_SEQUENTIAL_KEY = ON),

        CONSTRAINT CK_Pin_CodeId CHECK (CodeId >= 0 AND CodeId <= 9999999999)
    );
END
GO

------------------------------------------------------------------------------
-- Seed counter: the "never reuse a CodeId" invariant, made explicit and
-- auditable. Reserved atomically inside the seed transaction, so a failed
-- seed rolls the counter back with it: gapless AND reuse-free. Deliberately
-- not IDENTITY and not a SEQUENCE - maintenance owns it, exactly one row.
------------------------------------------------------------------------------
IF OBJECT_ID('dbo.PinSeedControl') IS NULL
BEGIN
    CREATE TABLE dbo.PinSeedControl
    (
        LockId     char(1) NOT NULL CONSTRAINT PK_PinSeedControl PRIMARY KEY
                           CONSTRAINT CK_PinSeedControl_Lock CHECK (LockId = 'X'),
        NextCodeId bigint  NOT NULL
    );
    INSERT dbo.PinSeedControl (LockId, NextCodeId) VALUES ('X', 0);
END
GO

------------------------------------------------------------------------------
-- Dispense watermark: pure performance aid, never a correctness dependency.
-- Semantics: every CodeId <= WatermarkCodeId is confirmed gone, so the
-- dispense seek starts past any ghost records left when delete volume
-- outruns ghost cleanup. Advanced lazily by pin_06; separate table from the
-- seed counter so a long seed transaction can never block a dispense read.
------------------------------------------------------------------------------
IF OBJECT_ID('dbo.PinDispenseControl') IS NULL
BEGIN
    CREATE TABLE dbo.PinDispenseControl
    (
        LockId          char(1) NOT NULL CONSTRAINT PK_PinDispenseControl PRIMARY KEY
                                CONSTRAINT CK_PinDispenseControl_Lock CHECK (LockId = 'X'),
        WatermarkCodeId bigint  NOT NULL
    );
    INSERT dbo.PinDispenseControl (LockId, WatermarkCodeId) VALUES ('X', -1);
END
GO
