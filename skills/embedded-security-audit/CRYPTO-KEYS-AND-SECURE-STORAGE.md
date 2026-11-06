# Cryptography, Keys, and Secure Storage Hunting

#### When to use this file

Reach for this file whenever the device holds keys or secrets, generates randomness, uses cryptographic primitives, or stores data it claims is protected: mbedTLS/wolfSSL/tinycrypt usage, a TRNG/DRBG, flash encryption, PSA Crypto and PSA ITS/PS, secure-element drivers (ATECC, SE050), and any custom crypto. Pair it with `BOOT-CHAIN-AND-SECURE-BOOT.md` and `FIRMWARE-UPDATE-AND-OTA.md` for how signatures are used, with `TRUSTZONE-TEE-AND-ISOLATION.md` for key isolation across worlds, and with `FAULT-INJECTION-AND-SIDE-CHANNEL.md` for timing and glitch angles. This file owns key material, RNG, primitive misuse, constant-time comparison, and secure storage.

Split a large target into key material, RNG/entropy, primitive misuse, constant-time, and secure storage.

## Core discipline (include in every agent prompt for this domain)

```
- Record that a secret exists and where it is, never its value. Distinguish per-device from fleet-shared material; a shared secret's compromise is fleet-wide.
- Judge RNG by how it is seeded and health-checked, not by the function name. Time, chip ID, or a constant seed is not entropy.
- Primitive misuse is usually source-visible: static IV/nonce, ECB, missing MAC, disabled cert verification. Confirm from source; timing side channels on target are `needs_validation`.
- A device-derived key computed from a readable chip UID is not secret storage. Trace where the key really comes from.
- Validate in host builds and vectors only. Never flash, read fuses, or measure timing on silicon; those are `needs_validation` with a bench plan.
```

## Key-material attack classes (subagent_type: `general`)

**Hardcoded keys, certs, and PSKs**
Private keys, symmetric keys, certificates, and PSKs are embedded in source, headers, or build output. Grep for `-----BEGIN`, `static const uint8_t ..._key[]`, `psk`, `0x` byte arrays near crypto calls, and cert/key file paths in the build. A real key that a production path uses is `confirmed` (critical if fleet-shared); a clear test-only key used only by a test target is `informational` unless a release path consumes it.

**Fleet-shared symmetric keys**
One symmetric key is shared across all devices for encryption, authentication, or pairing, so extracting it from one unit compromises the fleet. Determine whether the key is provisioned per-device or baked into firmware. A fleet-shared key protecting a real control is `confirmed` and typically critical.

**Keys left in RAM or `.noinit` and not zeroized**
Key material is copied into RAM, left in a `.noinit`/`.bss` buffer across resets, or not wiped after use (`mbedtls_platform_zeroize`, explicit `memset_s` absent), widening the window for extraction. Check lifetime of key buffers and whether an SE/KMU key is unnecessarily copied into RAM. A key that persists avoidably is a weakness; extraction usually needs a debug or memory-disclosure path, so pair it with that vector.

**Keys exported from a secure element/KMU without need**
Code copies a key out of an ATECC/SE050/KMU into application RAM to perform an operation the element could do internally, defeating the hardware protection. Check whether operations use the element's own API or pull the key out. Unnecessary export is `confirmed` as a weakened boundary; impact depends on the reachable disclosure path.

## RNG and entropy attack classes (subagent_type: `general`)

**Non-cryptographic RNG for security values**
`rand()`, `srand()`, an LFSR, or a linear PRNG produces keys, nonces, IVs, tokens, or challenge values. Grep for `rand(`, `srand(`, `% `, and custom PRNGs feeding crypto. Predictable security values are `confirmed`.

**DRBG seeded from time, chip ID, or a constant**
The DRBG/CTR_DRBG is seeded from `time()`, a device serial/UID, a build constant, or an uninitialized buffer, producing predictable or cross-device-identical output, especially on first boot before any entropy accumulates. Trace the seed source and whether a hardware TRNG is actually used and health-checked. A weak seed is `confirmed`.

**TRNG not health-checked**
A hardware TRNG is used directly without startup/continuous health tests, so a stuck or biased source silently weakens every key. Check for health-test code around the TRNG read. Missing health checks are a weakness; demonstrating low entropy on target is `needs_validation` with a bench plan.

**Nonce/IV reuse across reboots**
A GCM/CCM/ChaCha20-Poly1305 nonce counter lives in RAM and resets on reboot, or an IV is fixed, so the same (key, nonce) pair repeats — catastrophic for these modes. Trace nonce/counter storage and reset behavior across power cycles. Reuse that is source-visible is `confirmed`.

## Primitive-misuse attack classes (subagent_type: `general`)

**Weak modes and missing authentication**
ECB mode, CBC without a MAC (unauthenticated encryption), a static IV, a truncated MAC, RSA without padding/verification checks, an ECDSA nonce from a weak RNG, or unvalidated ECC points/curves. Grep for `_ECB`, `set_iv` with a constant, encrypt calls without a following MAC, and signature verify calls that ignore padding. Source-visible misuse is `confirmed`.

**Disabled certificate/peer verification**
TLS/DTLS client code disables verification: `MBEDTLS_SSL_VERIFY_NONE`, `wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ...)`, a no-op verify callback, no hostname/identity check, or no time source so validity is skipped. Grep for `VERIFY_NONE`, `authmode`, and custom verify callbacks returning success. Disabled verification on a security-relevant channel is `confirmed`.

**Custom/home-grown crypto**
A device-specific cipher, MAC, KDF, or signature scheme replaces a vetted primitive. Treat any custom construction as suspect and look for structural weaknesses (reversibility, key-recovery, no diffusion). A broken custom construction demonstrable in source/vectors is `confirmed`; a subtle one may be `needs_validation` with analysis.

## Constant-time attack classes (subagent_type: `general`)

**Non-constant-time comparison of secrets**
`memcmp`, `strcmp`, or an early-exit loop compares a MAC, tag, PIN, password, or token, leaking match length through timing. Grep for `memcmp(` and `strcmp(` on secret buffers and prefer a constant-time compare (`mbedtls_ct_memcmp`, a volatile accumulate-XOR). A non-constant-time compare of a secret is `confirmed` as a logic defect; whether the timing is exploitable on target is `needs_validation`.

**Secret-dependent branches and table lookups**
Table-based AES on a core with a data cache, or branches/indexing that depend on key bits, leak through timing/cache. Note these for cores with caches (Cortex-M7/A) and recommend constant-time/bitsliced implementations. Timing exploitability on the specific target is `needs_validation` with a bench plan; keep the logical observation as the record.

## Secure-storage attack classes (subagent_type: `general`)

**"Encryption" with a key derived from a readable UID**
Data is "encrypted" with a key computed from the chip serial/UID or another value any attacker can read, so the encryption adds no secrecy. Trace the key-derivation input. A key derived solely from readable identifiers is `confirmed`.

**Flash-encryption configuration gaps**
Flash/OTA encryption is in development mode, disabled, or keyed weakly: ESP32 `FLASH_CRYPT_CNT`/development vs release mode, a plaintext partition holding secrets, or an NVS/settings subsystem storing keys in the clear. Check the flash-encryption config and whether secrets land in encrypted regions. A plaintext secret store or dev-mode encryption shipped to production is `confirmed`; the actual fuse/mode state may be `needs_validation`.

**PSA ITS/PS and key-store misuse**
PSA Internal/Protected Storage or the PSA key store is used without the intended attributes (exportable keys that should be non-exportable, persistent keys with weak lifetime/usage flags), or secrets are written to ordinary settings instead of PS. Check `psa_set_key_usage_flags`, `psa_set_key_lifetime`, and whether sensitive data uses ITS/PS. Exportable or misattributed keys are `confirmed` as a weakened boundary.

**Secrets not erased on factory reset; key wear**
Keys, credentials, and Wi-Fi passwords survive a factory reset, or key storage is rewritten so often it wears out flash. Trace the reset path and what it wipes, and the write frequency of key storage. Secrets surviving reset are `confirmed` (see `DEVICE-LIFECYCLE-AND-PROVISIONING.md`).

## Key-hierarchy and identity attack classes (subagent_type: `general`)

**Per-device identity, attestation-key protection, and revocation**
Review how per-device identity keys and certificates are generated, stored, and protected, whether attestation keys are isolated from application code, and whether compromised keys can be revoked. A per-device key reachable from application code, or an identity scheme with no revocation, is a weakness; downstream impact may be `needs_validation`. Cross-reference `DEVICE-LIFECYCLE-AND-PROVISIONING.md` for issuance.

## Universal moves (apply across the above)

- Inventory every secret: what it is, where it lives, per-device vs shared, and which operations use it. Severity follows the blast radius of its compromise.
- For each crypto call, check mode, IV/nonce source and uniqueness, key source, and whether authentication (a MAC or AEAD) is present and verified.
- Trace RNG from the primitive back to its seed and health checks; a good API with a bad seed is still predictable.
- Separate a source-visible logic defect (`confirmed`) from a timing/power side channel on target (`needs_validation`, with the logical observation retained and severity capped per the physical-invasive rules where applicable).
- When the decisive fact is a fuse, flash-encryption mode, or on-target timing, record the vector and give a bounded bench plan.

## Validation rules (apply before reporting ANY finding here)

1. Name the secret or primitive, the boundary it protects, and the concrete consequence of its weakness (forgery, decryption, prediction, key recovery, fleet compromise).
2. Record that a secret exists and where, never its value; mark per-device vs fleet-shared, because that sets severity.
3. Confirm source-visible misuse (static IV, ECB, VERIFY_NONE, weak seed, non-constant-time compare) with code evidence; a test-only artifact unused by production is not a finding.
4. Treat timing/power side channels and fuse/flash-mode facts as `needs_validation` with a bench plan; keep the logical observation and cap severity per the physical-invasive rules.
5. For secure storage, prove the key's true source and whether the store is actually protected; a UID-derived key or plaintext NVS is `confirmed`.
6. Return `confirmed` only with a source trace and bounded host/vector evidence; return `needs_validation` with the exact on-target or provisioning fact an owner must confirm.
