# Boot Chain and Secure Boot Hunting

#### When to use this file

Reach for this file whenever the target contains a ROM/first-stage/second-stage bootloader, a secure-boot verification routine, image header/TLV parsing, anti-rollback enforcement, or a recovery/DFU path: MCUboot, U-Boot and U-Boot SPL, TF-A BL1/BL2/BL31, a vendor ROM loader, or a custom verifier. Pair it with `FIRMWARE-UPDATE-AND-OTA.md` for the update transport and manifest that feed images into this chain, with `CRYPTO-KEYS-AND-SECURE-STORAGE.md` for the signature primitives and key storage, and with `FAULT-INJECTION-AND-SIDE-CHANNEL.md` for single-point boot decisions. This file owns the verify-then-execute decision; the update file owns delivery.

Split a large boot chain by stage (ROM, BL1/SPL, BL2/U-Boot, app), then by concern: image parsing, signature logic, anti-rollback, and recovery/DFU.

## Core discipline (include in every agent prompt for this domain)

```
- Each stage must verify the next stage completely before transferring control, and the region it verifies must equal the region it executes. A header-declared size that differs from the loaded/executed size is a TOCTOU.
- Image header and TLV parsing runs before verification; it is the highest-value bug surface. Treat every offset, length, and address field as attacker-controlled.
- A verification function has exactly one accept path. Read every error, early-return, and default branch for a route that boots anyway.
- Never assume production lock state. Secure boot that is compiled out, keyed with an all-FF slot, or disabled in a release config is the defect; prove it from the shipped configuration.
- Validate logic in source and in host/emulator parsers only. A bypass that requires glitching is `needs_validation` and capped per the severity rules; recommend hardened flow-integrity patterns as the fix.
```

## Chain-of-trust attack classes (subagent_type: `general`)

**Verified region does not equal executed region**
The loader hashes or verifies one range but loads, maps, or executes another: it trusts a header-declared image size while copying a different length, verifies a slot then executes from external flash via XIP (a verify-then-execute-in-place TOCTOU), or omits a TLV that affects execution from the hashed region. Compare the bytes covered by the hash with the bytes that run, including the vector table and any post-verify relocation. A source-visible mismatch is `confirmed`; an XIP race that depends on external-flash timing is `needs_validation`.

**Protected TLVs and header fields excluded from the hash**
Image metadata (load address, entry point, dependency records, security counter) lives in a TLV area where only some entries are covered by the signature, so an attacker edits an unprotected field. In MCUboot terms, check which TLVs are inside `IMAGE_TLV_PROT` versus the unprotected area, and that `load_addr`/entry are validated against allowed memory. An execution-affecting field outside the protected region is `confirmed`.

**Stage transfers control without verifying the successor**
A stage jumps to the next image before (or without) checking its signature, relies on a sibling/recovery path that skips verification, or verifies only on the first boot. Trace every function-pointer jump and `((void(*)(void))addr)()` to the check that must precede it. Missing verification on any reachable transfer is `confirmed`.

## Signature-verification-logic attack classes (subagent_type: `general`)

**Return-value and error-path confusion**
The verifier conflates success and failure: `0` means success in one convention and failure in another, an error path falls through to boot, a non-zero return from a crypto call is ignored, or a `switch`/`if` default accepts. Grep for `verify`, `rc == 0`, `ret`, `BOOT_` result codes, and read each caller's handling. A reachable accept-on-error is `confirmed` and typically critical.

**Weak comparison and unprovisioned key slots**
A key-hash or digest comparison uses a wrong length (`memcmp(a, b, sizeof(a))` where `a` is a pointer), accepts multiple key slots including an all-`0xFF`/erased or unprovisioned slot, or treats an empty key as valid. Check the key-selection loop, the comparison length, and whether an unwritten OTP/flash key region reads as all-ones and is accepted. Accepting an attacker-settable or blank key is `confirmed`.

**Algorithm and signature-type downgrade**
The verifier accepts a weaker or absent algorithm: a `BOOT_SIGNATURE_TYPE_NONE` build, an image that declares SHA-only "integrity" instead of a signature, or a negotiable algorithm field that selects a broken primitive. Grep release configs for `MCUBOOT_SIGN_*`, `CONFIG_SECURE_BOOT`, `BOOT_SIGNATURE_TYPE_NONE`, and any algorithm selector read from the image. A downgrade reachable in the shipped build is `confirmed`.

**Pre-verification image parsing overflow**
Header and TLV parsing (sizes, counts, offsets) happens before the signature is checked, so a classic memory-safety bug in the parser runs on fully attacker-controlled bytes — the most valuable class in a bootloader. Apply `FIRMWARE-MEMORY-SAFETY.md` discipline to the pre-verify parser specifically, and range-check `load_addr`, entry point, and TLV offsets against allowed memory. A reachable overflow here is `confirmed`.

## Anti-rollback attack classes (subagent_type: `general`)

**Security counter present but not enforced**
The image carries a security/rollback counter TLV, but the loader does not compare it against a stored floor, or compares but still boots on failure. Trace the counter read to the accept decision. A counter that is parsed but never gates boot is `confirmed` (downgrade to a signed-but-vulnerable image).

**Counter stored in rewritable flash, not monotonic storage**
The rollback floor lives in ordinary rewritable flash or RAM rather than OTP/eFuse or a monotonic counter, so an attacker (or a glitch) resets it. Identify where the floor is stored and whether it is write-once. Rewritable storage is `confirmed` as a design weakness where the attacker can reach that flash; if reaching it needs hardware access, mark the vector and `needs_validation` for the physical step.

**Counter update ordering (brick or no-op)**
The floor is advanced before the new image is confirmed bootable (bricking the device on a bad update) or is never advanced after a successful update (rollback stays possible). Review the update-commit sequence against the counter write. State whether the effect is denial of service or a persistent downgrade.

## Recovery, DFU, and environment attack classes (subagent_type: `general`)

**Recovery/DFU accepts unsigned images or allows readback**
A serial-recovery, USB-DFU, or vendor rescue mode loads images without the same signature check as the normal path, or permits flash readback, defeating secure boot through the back door. Find the recovery entry (button/strap, magic command, failed-boot fallback) and verify it enforces the same authenticity and readout rules. An unsigned-accept recovery path is `confirmed`.

**Boot-mode strap or pin that skips verification**
A GPIO strap, fuse, or environment flag selects a boot mode that bypasses verification or enables a console. Check the mode-selection code and whether the bypass mode can ship enabled. A strap-selectable bypass reachable without opening the device is high severity; one needing internal access is `needs_validation` with the physical vector recorded.

**U-Boot environment, bootcmd, and FIT verification gaps**
On U-Boot targets, check for an interruptible console (`bootdelay` with `CONFIG_AUTOBOOT_KEYED` absent), environment stored in unprotected, writable storage (`CONFIG_ENV_IS_IN_*` without a `CONFIG_ENV_WRITEABLE_LIST` allowlist), `bootcmd`/`bootargs` injection, a FIT image whose `required` signature property is missing so unsigned configurations load, and a Linux `init=`/cmdline override. Each reachable gap that loads unverified code or changes the kernel command line is `confirmed`.

**Measured boot / DICE claims that omit mutable code**
On devices with measured boot or DICE, the CDI/attestation measurement must cover all mutable code and configuration that affects execution; a stage excluded from the measurement lets attacker code attest as trusted. Compare what each stage measures with what it executes. A measurement gap is `confirmed` for attestation integrity, though downstream impact may be `needs_validation`.

**Fault-sensitive single boot decision**
A single compare-and-branch decides boot, debug unlock, or verification with no redundancy or flow-integrity check, making it a prime glitch target. Flag it here and cross-reference `FAULT-INJECTION-AND-SIDE-CHANNEL.md`; recommend MCUboot `FIH_*`/TF-M `fih` hardened patterns. Glitch susceptibility itself is `needs_validation` and capped at medium unless it yields a fleet-wide secret.

## Universal moves (apply across the above)

- Draw the boot graph: each stage, what it verifies, what it executes, where keys and counters live, and every recovery/fallback edge. Most boot findings are a missing or mismatched edge.
- Separate the shipped/release configuration from development defaults. A secure-boot Kconfig that is on in `prj.conf` but off in the release build is the real posture.
- Treat the pre-verification parser as the primary memory-safety target and apply the memory-safety companion to it.
- Range-check every address and size field (`load_addr`, entry point, copy length, TLV offset) against the allowed memory map; an unchecked address is both a corruption and a trust-region escape.
- When the decisive step is a fuse value, option byte, ROM behavior, or glitch, record the attack vector and stop at `needs_validation` with a bench plan the owner runs.

## Validation rules (apply before reporting ANY finding here)

1. Name the stage, the lower-trust input (update image, recovery command, environment, strap), and the exact verification invariant that fails.
2. Separate a logic bug visible in source (`confirmed` with a host/emulator parser reproduction) from a bypass that needs glitching or physical access (`needs_validation`, severity-capped, vector recorded).
3. Prove that the verified region differs from the executed region, or that the accept path is reachable on an error, downgrade, blank-key, or recovery route, before claiming a bypass.
4. For anti-rollback, show whether the counter is enforced, where it is stored, and the update ordering; classify the effect as downgrade or brick.
5. Never infer production secure-boot or lock state from a development config; a dev default is `needs_validation` for the shipped unit.
6. Return `confirmed` only with a complete source trace and bounded local evidence; return `needs_validation` with the exact fuse, ROM, timing, or configuration fact an owner must confirm on the bench.
