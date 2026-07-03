/* =============================================================================
   pin_05_decrypt.sql
   usp_DecryptPin - decryption as its own script, exactly as specified: the
   dispense path stays crypto-free, and only the downstream system that
   assigns value/tracks allocation ever sees plaintext.

   Deploy order : 5 of 6

   Integrity: DECRYPTBYKEY is called with the CodeId authenticator. A NULL
   result means the ciphertext was tampered with, corrupted, or was not
   minted for this CodeId (e.g. copied from another row in an attempt to
   double-issue a pin) - it is surfaced as a hard error, never a silent NULL.

   Operational rule: the plaintext exists only in this result set. Never log
   it, never persist it in this component.
   ============================================================================= */

SET XACT_ABORT ON;
GO

CREATE OR ALTER PROCEDURE dbo.usp_DecryptPin
    @CodeId        bigint,
    @CodeEncrypted varbinary(96)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @CodeId IS NULL OR @CodeEncrypted IS NULL
        THROW 50020, 'usp_DecryptPin: @CodeId and @CodeEncrypted are required.', 1;

    DECLARE @pin char(10);

    BEGIN TRY
        OPEN SYMMETRIC KEY PinCodeKey DECRYPTION BY CERTIFICATE PinCodeCert;

        SET @pin = CONVERT(char(10),
                   DECRYPTBYKEY(@CodeEncrypted, 1, CONVERT(varbinary(8), @CodeId)));

        CLOSE SYMMETRIC KEY PinCodeKey;
    END TRY
    BEGIN CATCH
        IF EXISTS (SELECT 1 FROM sys.openkeys WHERE key_name = 'PinCodeKey')
            CLOSE SYMMETRIC KEY PinCodeKey;
        THROW;
    END CATCH;

    IF @pin IS NULL
        THROW 50021, 'usp_DecryptPin: integrity failure - ciphertext invalid or not minted for this CodeId.', 1;

    SELECT CodeId = @CodeId, Pin = @pin;
END
GO

------------------------------------------------------------------------------
-- Grant to the downstream allocation/value system ONLY. Keeping this role
-- disjoint from PinDispenserRole is the separation the design promises:
-- popping a pin and reading a pin are different privileges.
------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'PinDecryptorRole' AND type = 'R')
    CREATE ROLE PinDecryptorRole;
GO
GRANT EXECUTE ON dbo.usp_DecryptPin TO PinDecryptorRole;
GO
