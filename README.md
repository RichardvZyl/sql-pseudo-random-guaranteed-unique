# sql-pseudo-random-guaranteed-unique

A SQL Server engine for generating **pseudo-random, guaranteed-unique** codes —
suitable for voucher codes, PINs, redemption codes, gift-card numbers, or any
system that must hand out codes that are unpredictable to the recipient yet
provably free of collisions.

> **License / usage:** This is **proprietary software**. It is published for
> reference only. You may **not** use, copy, modify, or deploy any part of it
> without the prior written permission of the owner. See [LICENSE](LICENSE) and
> [§ License & Permission](#license--permission) below.

---

## What it does

It mints 10-digit codes (`0000000000`–`9999999999`) with two properties that
are usually in tension:

- **Unique — by construction, not by retry.** Codes are produced by a keyed
  [Feistel network](https://en.wikipedia.org/wiki/Feistel_cipher) applied to a
  monotonic counter. A Feistel network is a *bijection* on the code space, so
  distinct counter values map to distinct codes automatically. There is **no
  unique index, no dedup pass, no collision retry loop** — uniqueness is a
  mathematical guarantee across every generation run.
- **Random — cryptographically.** The Feistel round key is 256 CSPRNG bits, and
  the construction is a pseudorandom permutation (Luby–Rackoff; the same family
  as NIST FF1/FF3 format-preserving encryption). The sequence
  `F_K(0), F_K(1), F_K(2), …` is computationally indistinguishable from uniform
  10-digit draws **without replacement**. Because of this, simply consuming the
  pool in order (FIFO) already emits a cryptographically secure pseudo-random
  sequence — no shuffle at dispense time is needed.

Generated codes are stored **encrypted at rest** (AES via `ENCRYPTBYKEY`), bound
to their row handle so a ciphertext copied to another row fails to decrypt
rather than silently double-issuing a code.

## Design highlights

- **Single-index sliding-window table.** Codes are appended at the high end of a
  clustered B-tree (`FILLFACTOR 100`) and dispensed (deleted) from the low end.
  No live row is ever updated, so no page ever splits and the tree slides
  forward at ~100% density. **No `REORGANIZE`/`REBUILD` job is ever required.**
- **Lock-free-feeling parallel dispense.** The hot path is a single
  `DELETE … TOP (@n) … WITH (ROWLOCK, UPDLOCK, READPAST)` statement — the
  canonical parallel-queue pop. N concurrent callers skip each other's locked
  rows and claim N distinct codes with zero blocking, zero deadlocks, zero
  retries. Throughput scales with cores.
- **Gapless, reuse-free counter.** The seed counter is reserved atomically
  inside the seed transaction, so a failed seed rolls the counter back with the
  insert — the code space is never skipped and never reused.
- **Privilege separation.** *Popping* a code and *reading* a code are distinct
  privileges: `PinDispenserRole` can dispense encrypted codes but never see
  plaintext; only `PinDecryptorRole` (the downstream allocation system) can
  decrypt.
- **Index-free integrity audit.** Because every code is independently
  recomputable as `F_K(CodeId)`, an audit procedure re-derives and verifies every
  row — the backstop that replaces a unique index.

## Repository layout

Scripts are numbered in **deploy order** and each has a single responsibility.

| Order | Script | Responsibility |
|:-----:|--------|----------------|
| 1 | [`scripts/pin_01_security_setup.sql`](scripts/pin_01_security_setup.sql) | Encryption hierarchy: certificate, AES-256 symmetric key, and the 256-bit CSPRNG Feistel key, written exactly once. |
| 2 | [`scripts/pin_02_schema.sql`](scripts/pin_02_schema.sql) | The pool table (`dbo.Pin`) plus the seed-counter and dispense-watermark control tables. |
| 3 | [`scripts/pin_03_seed.sql`](scripts/pin_03_seed.sql) | `usp_SeedPins` — batch mint: atomic range reservation, set-based 6-round Feistel, AES encryption. Where randomness and uniqueness are minted. |
| 4 | [`scripts/pin_04_dispense.sql`](scripts/pin_04_dispense.sql) | `usp_DispensePins` — the hot path: destructive FIFO pop of still-encrypted codes. |
| 5 | [`scripts/pin_05_decrypt.sql`](scripts/pin_05_decrypt.sql) | `usp_DecryptPin` — the only place plaintext is exposed, with tamper detection as a hard error. |
| 6 | [`scripts/pin_06_maintenance.sql`](scripts/pin_06_maintenance.sql) | Watermark advance, integrity audit, pool stats, and a concurrency smoke test. |

### ⚠️ Security setup (script 01) — read before deploying

Script 01 builds the encryption hierarchy the rest of the system depends on:

- a certificate **`PinCodeCert`**,
- an AES-256 symmetric key **`PinCodeKey`** (protected by that certificate), and
- a secret table **`dbo.PinSecret`** holding the 256-bit Feistel key generated
  from the OS CSPRNG under row `SecretName = 'FeistelKey'`.

The script is shipped as a **template, not a turnkey secret store.** Before you
run it in any real environment:

- **Replace the placeholder passwords.** `CREATE MASTER KEY … PASSWORD =
  'CHANGE_ME__…'` and the certificate-backup password are deliberately obvious
  placeholders — source the real values from your secrets vault and never commit
  them.
- **Back up `PinCodeCert` immediately** (the commented `BACKUP CERTIFICATE`
  block shows how) and vault the `.cer`/`.pvk` files. **Losing the certificate
  makes every encrypted code permanently unrecoverable.**
- **Protect the Feistel key as the crown jewel.** The security of every generated
  code depends entirely on the secrecy and integrity of that 256-bit key, and on
  the three invariants documented in the script: the key never changes, the round
  count (6) never changes, and a `CodeId` is never issued twice. Never rotate the
  key against a pool that still contains live codes.

## Requirements

- **SQL Server 2019+** recommended. `OPTIMIZE_FOR_SEQUENTIAL_KEY` (in script 02)
  can be removed for SQL Server 2016/2017 with no effect on correctness. Script 01
  targets SQL Server 2016+.
- `CONTROL` on the database to run script 01 (it creates the master key,
  certificate, and symmetric key).
- A secrets vault for the passwords and certificate backup (see the security
  note above).

## Quick start (once you have permission to use the code)

```sql
-- Deploy in order (edit script 01's placeholder passwords first — see above):
--   :r scripts/pin_01_security_setup.sql
--   :r scripts/pin_02_schema.sql
--   :r scripts/pin_03_seed.sql
--   :r scripts/pin_04_dispense.sql
--   :r scripts/pin_05_decrypt.sql
--   :r scripts/pin_06_maintenance.sql

-- Mint a pool:
EXEC dbo.usp_SeedPins @Count = 100000;
EXEC dbo.usp_GetPinPoolStats;

-- Dispense one (still encrypted):
DECLARE @t TABLE (CodeId bigint, CodeEncrypted varbinary(96));
INSERT @t EXEC dbo.usp_DispensePins @Count = 1;

-- Decrypt it (downstream system only):
DECLARE @id bigint, @ct varbinary(96);
SELECT @id = CodeId, @ct = CodeEncrypted FROM @t;
EXEC dbo.usp_DecryptPin @CodeId = @id, @CodeEncrypted = @ct;

-- Verify integrity (expect Mismatches = 0):
EXEC dbo.usp_AuditPinIntegrity @MaxRows = 10000;
```

A 64-way parallel dispense smoke test (via `ostress`) is documented at the end
of `scripts/pin_06_maintenance.sql`.

## How uniqueness is guaranteed (in one paragraph)

Split the counter value `n` into `(L, R)` halves. Run six Feistel rounds where
each round replaces one half with `(other_half + F_i(half)) mod 100000` and
`F_i` is a keyed SHA-256 hash. Each round is invertible regardless of what `F_i`
computes (the hash is only ever run *forward*), so the whole six-round
composition is a bijection on `[0, 10^10)`. Distinct counter values in →
distinct codes out. Because the counter never repeats a value, the codes never
collide — with no index or retry enforcing it.

## License & Permission

**Copyright © 2026 Richard van Zyl. All Rights Reserved.**

This code is proprietary. It is made visible for reference and evaluation of the
author's work only. **No license to use, copy, modify, distribute, or deploy any
part of it is granted** except by the owner's prior written permission.

To request permission, contact **richardvzyl@gmail.com**. Full terms are in
[LICENSE](LICENSE).
