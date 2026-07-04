# unique-code-dispenser

A database engine for generating and dispensing **pseudo-random,
guaranteed-unique** codes —
suitable for voucher codes, PINs, redemption codes, gift-card numbers, or any
system that must hand out codes that are unpredictable to the recipient yet
provably free of collisions.

Ships in two faithful, behaviourally-equivalent ports:

- **[`sqlserver/`](sqlserver/)** — Microsoft SQL Server (T-SQL), 2016/2019+.
- **[`postgres/`](postgres/)** — PostgreSQL 13+ (`pgcrypto`).

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
  as NIST SP 800-38G FF1/FF3 format-preserving encryption). The sequence
  `F_K(0), F_K(1), F_K(2), …` is computationally indistinguishable from uniform
  10-digit draws **without replacement**. Because of this, simply consuming the
  pool in order (FIFO) already emits a cryptographically secure pseudo-random
  sequence — no shuffle at dispense time is needed.

Generated codes are stored **encrypted at rest**, cryptographically bound to
their row handle so a ciphertext copied to another row fails to decrypt rather
than silently double-issuing a code.

## Design highlights

- **Single-index sliding-window table.** Codes are appended at the high end of a
  B-tree (`FILLFACTOR 100`) and dispensed (deleted) from the low end. No live
  row is ever updated, so no page ever splits and the tree slides forward at
  ~100% density. **No `REBUILD`/`REINDEX` job is ever required** (on PostgreSQL,
  autovacuum handles reclamation).
- **Lock-free-feeling parallel dispense.** The hot path is a single destructive
  head-pop — `DELETE … TOP (@n) … WITH (ROWLOCK, UPDLOCK, READPAST)` on SQL
  Server, `DELETE … LIMIT n FOR UPDATE SKIP LOCKED … RETURNING` on PostgreSQL.
  N concurrent callers skip each other's locked rows and claim N distinct codes
  with zero blocking, zero deadlocks, zero retries. Throughput scales with cores.
- **Gapless, reuse-free counter.** The seed counter is reserved atomically inside
  the seed transaction, so a failed seed rolls the counter back with the insert —
  the code space is never skipped and never reused. Deliberately **not** an
  `IDENTITY`/`SEQUENCE` (those leak gaps and can reuse on rollback).
- **Privilege separation.** *Popping* a code and *reading* a code are distinct
  privileges: the dispenser role returns ciphertext but never sees plaintext;
  only the decryptor role (the downstream allocation system) can decrypt.
- **Index-free integrity audit.** Because every code is independently
  recomputable as `F_K(CodeId)`, an audit routine re-derives and verifies every
  row — the backstop that replaces a unique index.

## Repository layout

Both ports use the same six-script, one-responsibility-each structure, numbered
in **deploy order**.

| Order | Script | Responsibility |
|:-----:|--------|----------------|
| 1 | `pin_01_security_setup.sql` | Encryption hierarchy + the one-time 256-bit CSPRNG key(s). |
| 2 | `pin_02_schema.sql` | The pool table plus the seed-counter and dispense-watermark control tables. |
| 3 | `pin_03_seed.sql` | Batch mint: atomic range reservation, set-based 6-round Feistel, encryption. |
| 4 | `pin_04_dispense.sql` | The hot path: destructive FIFO pop of still-encrypted codes. |
| 5 | `pin_05_decrypt.sql` | The only place plaintext is exposed, with tamper detection as a hard error. |
| 6 | `pin_06_maintenance.sql` | Watermark advance, integrity audit, pool stats, and a concurrency smoke test. |

```
sqlserver/   pin_01 … pin_06   -- T-SQL, DMK/certificate + AES via ENCRYPTBYKEY
postgres/    pin_01 … pin_06   -- PL/pgSQL, pgcrypto AES-256-CBC + HMAC-SHA-256
```

## Engine differences (same behaviour, different primitives)

The two ports are behaviourally equivalent. The differences are dictated by what
each engine provides:

| Concern | SQL Server | PostgreSQL |
|---|---|---|
| Key hierarchy | Database master key → certificate → AES-256 symmetric key | `pgcrypto`; keys held in a locked-down single-row `pin.pin_secret` table, read only by `SECURITY DEFINER` functions |
| Authenticated encryption | `ENCRYPTBYKEY` with `CodeId` authenticator (NULL on mismatch) | **Encrypt-then-MAC**: AES-256-CBC + `HMAC-SHA-256` over `CodeId ‖ IV ‖ ciphertext` (pgcrypto has no AEAD primitive) |
| Destructive pop | `WITH (ROWLOCK, UPDLOCK, READPAST)` | `FOR UPDATE SKIP LOCKED` |
| Privilege model | `PinSeederRole` / `PinDispenserRole` / `PinDecryptorRole` | `pin_seeder` / `pin_dispenser` / `pin_decryptor`, plus a `pin_owner` definer role |
| Fragmentation control | No `REORGANIZE`/`REBUILD` needed (sliding window) | No manual `REINDEX` needed; aggressive autovacuum reclaims the drained head |
| Search-path hardening | n/a | Every definer function sets `search_path = pg_catalog, pg_temp` (defends CVE-2018-1058) |

### ⚠️ Security setup (script 01) — read before deploying

Script 01 builds the encryption hierarchy the rest of the system depends on. In
**both** ports it is a **template, not a turnkey secret store**. Before running
it in any real environment:

- **SQL Server:** replace the placeholder master-key and certificate-backup
  passwords with vaulted values; **back up `PinCodeCert` immediately** (losing it
  makes every code unrecoverable).
- **PostgreSQL:** ensure `pgcrypto` is available (trusted extension on
  RDS/Aurora PG13+; allowlist via `azure.extensions` on Azure Flexible Server;
  default `postgres` user on Cloud SQL). **Back up `pin.pin_secret` the moment it
  is created** — if `feistel_key` is lost you cannot recompute or audit any code,
  and if `aes_key`/`mac_key` are lost every ciphertext is unrecoverable.
- **Both:** treat the keys as the crown jewels and honour the **three invariants**
  documented at key creation — the key never changes, the round count (6) never
  changes, and a `CodeId` is never issued twice. Never rotate the key against a
  pool that still holds live codes.

> **In-database keys note (PostgreSQL):** keys stored in `pin.pin_secret` remain
> readable by a database superuser (who can also `SET ROLE pin_owner`). If your
> threat model excludes the DBA, pass keys as per-call function parameters from
> the app, or store only KMS-wrapped keys. This matches the practical trust
> boundary of the SQL Server DMK/certificate model.

## Quick start

### SQL Server

```sql
-- Deploy in order (edit script 01's placeholder passwords first):
--   :r sqlserver/pin_01_security_setup.sql
--   :r sqlserver/pin_02_schema.sql   ... through pin_06

EXEC dbo.usp_SeedPins @Count = 100000;      -- mint a pool
EXEC dbo.usp_GetPinPoolStats;

DECLARE @t TABLE (CodeId bigint, CodeEncrypted varbinary(96));
INSERT @t EXEC dbo.usp_DispensePins @Count = 1;   -- pop (still encrypted)

DECLARE @id bigint, @ct varbinary(96);
SELECT @id = CodeId, @ct = CodeEncrypted FROM @t;
EXEC dbo.usp_DecryptPin @CodeId = @id, @CodeEncrypted = @ct;   -- downstream only

EXEC dbo.usp_AuditPinIntegrity @MaxRows = 10000;   -- expect Mismatches = 0
```

### PostgreSQL

```sql
-- Deploy in order (as a privileged setup role):
--   \i postgres/pin_01_security_setup.sql
--   \i postgres/pin_02_schema.sql   ... through pin_06

SELECT pin.usp_seed_pins(100000);                  -- mint a pool
SELECT * FROM pin.usp_get_pin_pool_stats();

SELECT * FROM pin.usp_dispense_pins(1);            -- pop (still encrypted)

-- Decrypt (downstream / pin_decryptor only):
SELECT pin.usp_decrypt_pin(codeid, codeencrypted)
FROM pin.usp_dispense_pins(1);

SELECT * FROM pin.usp_audit_pin_integrity(1000);   -- expect ok = true for all
```

A high-concurrency smoke test is documented at the end of each port's
`pin_06_maintenance.sql` (`ostress` for SQL Server, `pgbench` for PostgreSQL).

## Cross-engine parity

The Feistel value is defined by SHA-256 over an exact byte layout, so the two
ports produce **identical** codes for the same key and counter — but only if the
byte layout matches exactly:

```
digest = SHA-256( key(32B) ‖ round_byte(0x01..0x06) ‖ R_as_4byte_big_endian )
F_i(R) = (first 7 bytes of digest, big-endian) mod 100000
L = n / 100000,  R = n % 100000,  round: (L + F_i(R)) mod 100000
```

Before trusting equivalence across engines, run the PostgreSQL harness below with
the fixed all-zeros 32-byte key, then diff the T-SQL outputs against it. **Do not
hand-transcribe "golden" numbers** — they require actually executing SHA-256, and
any mismatch is a byte-layout bug (round-byte position, `R` endianness, or which
7 digest bytes are taken), not an algebra bug.

```sql
-- PostgreSQL reference vectors:
SELECT n, lpad(pin.feistel_encrypt(n, decode(repeat('00',32),'hex'))::text,10,'0')
FROM (VALUES (0::bigint),(1),(42)) AS t(n)
ORDER BY n;
```

SQL Server integers are little-endian in memory, so the T-SQL side must build the
4-byte big-endian encoding of `R` explicitly and read the digest's leading 7
bytes most-significant-first.

## Why not `System.Random` + a plaintext primary key?

This design supersedes the common naive approach (a C#/Npgsql prototype that
generated 6-digit codes over a ~900,000-value space with the non-cryptographic
`System.Random`, stored them in plaintext as the primary key, and de-duplicated
in an in-memory `HashSet` with no `ON CONFLICT`). That approach is enumerable and
predictable, its collision rate climbs with fill, and a single collision aborts
the whole batch. The **only** idea worth keeping from it — the
`DELETE … SKIP LOCKED … RETURNING` destructive pop — is adopted verbatim in the
PostgreSQL port. Everything else (6-digit space, `System.Random`, plaintext PK,
no-`ON CONFLICT` batch insert) is discarded.

## License & Permission

**Copyright © 2026 Richard van Zyl. All Rights Reserved.**

This code is proprietary. It is made visible for reference and evaluation of the
author's work only. **No license to use, copy, modify, distribute, or deploy any
part of it is granted** except by the owner's prior written permission.

To request permission, contact **richardvzyl@gmail.com**. Full terms are in
[LICENSE](LICENSE).
