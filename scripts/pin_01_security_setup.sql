/* =============================================================================
   pin_01_security_setup.sql
   Encryption hierarchy + the single immutable generation secret.

   Deploy order : 1 of 6
   Target       : SQL Server 2016+
   Permissions  : CONTROL on the database

   Final design (converged):
     * Randomness and uniqueness live at GENERATION: value = F_K(CodeId),
       a keyed 6-round Feistel bijection over [0, 10^10). Unique counters
       through a one-to-one function = unique codes, by construction.
     * The dispense hot path carries no crypto, no counts, no random draws.
     * No LookupPepper / hash column exists in this component: nothing here
       ever looks up by code value, so the only fragmenting index is gone.
   ============================================================================= */

SET XACT_ABORT ON;
GO

------------------------------------------------------------------------------
-- 1. Database master key (skip if one already exists)
------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
BEGIN
    -- Source from your vault; do not commit.
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'CHANGE_ME__vaulted_password__1!';
END
GO

------------------------------------------------------------------------------
-- 2. Certificate protecting the AES data key
------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'PinCodeCert')
BEGIN
    CREATE CERTIFICATE PinCodeCert
        WITH SUBJECT     = 'Protects PinCodeKey (pin cell encryption)',
             EXPIRY_DATE = '2099-12-31';
END
GO

/* CRITICAL - back the certificate up immediately and vault the files.
   Losing it makes every encrypted pin permanently unrecoverable.

BACKUP CERTIFICATE PinCodeCert
    TO FILE = 'D:\secure\PinCodeCert.cer'
    WITH PRIVATE KEY (
        FILE = 'D:\secure\PinCodeCert.pvk',
        ENCRYPTION BY PASSWORD = 'CHANGE_ME__vaulted_backup_password!');
*/
GO

------------------------------------------------------------------------------
-- 3. AES-256 data key (encrypts pin values at rest)
------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = 'PinCodeKey')
BEGIN
    CREATE SYMMETRIC KEY PinCodeKey
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE PinCodeCert;
END
GO

------------------------------------------------------------------------------
-- 4. The Feistel key: 256 bits from the OS CSPRNG, written exactly once.
--
--    THE THREE INVARIANTS (uniqueness is conditional on all three):
--      1. This key never changes            (a new key = a new permutation;
--                                            outputs of two permutations can
--                                            collide)
--      2. The round count (6) never changes (same reason)
--      3. A CodeId is never issued twice    (enforced by pin_03's atomic,
--                                            monotonic counter reservation)
--    Under these, F_K is one fixed shuffle of the full 10^10-value deck and
--    every seed run deals the next contiguous positions of that same deck:
--    zero collision checks needed, across all runs, forever.
------------------------------------------------------------------------------
IF OBJECT_ID('dbo.PinSecret') IS NULL
BEGIN
    CREATE TABLE dbo.PinSecret
    (
        SecretName  sysname        NOT NULL CONSTRAINT PK_PinSecret PRIMARY KEY,
        SecretValue varbinary(256) NOT NULL,   -- ENCRYPTBYKEY output
        CreatedUtc  datetime2(3)   NOT NULL
            CONSTRAINT DF_PinSecret_CreatedUtc DEFAULT SYSUTCDATETIME()
    );
END
GO

OPEN SYMMETRIC KEY PinCodeKey DECRYPTION BY CERTIFICATE PinCodeCert;

IF NOT EXISTS (SELECT 1 FROM dbo.PinSecret WHERE SecretName = N'FeistelKey')
    INSERT dbo.PinSecret (SecretName, SecretValue)
    VALUES (N'FeistelKey',
            ENCRYPTBYKEY(KEY_GUID('PinCodeKey'), CRYPT_GEN_RANDOM(32)));

CLOSE SYMMETRIC KEY PinCodeKey;
GO
