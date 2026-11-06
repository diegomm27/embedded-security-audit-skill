# Firmware Update and OTA Hunting

#### When to use this file

Reach for this file whenever the device receives new firmware: OTA over Wi-Fi/cellular/MQTT, BLE or serial DFU (SMP/mcumgr, Nordic DFU), USB mass-storage updates, A/B slot swaps, delta/patch updates, and the manifest or metadata that describes them. Pair it with `BOOT-CHAIN-AND-SECURE-BOOT.md` (the loader that ultimately verifies and runs the image), `CRYPTO-KEYS-AND-SECURE-STORAGE.md` (signature and key handling), and `DEVICE-PROTOCOLS-AND-CLOUD-LINK.md` (the transport that triggers updates). This file owns update authenticity, versioning, transfer, and channel authentication; the boot file owns the final verify-then-execute.

Split a large updater into authenticity/manifest, rollback/freeze, transfer/storage, and update-channel authentication.

## Core discipline (include in every agent prompt for this domain)

```
- The device itself must authenticate the full image and its manifest. TLS to the server, or verification only in the phone app or cloud, is not device-side authenticity.
- Version and metadata are security-relevant: downgrade, freeze, vendor/class mismatch, and offset handling decide what runs.
- Decompression and delta application run on attacker-controlled data before the image is trusted; apply memory-safety discipline to them.
- The update transport command (start/write/confirm) needs its own authentication; an unauthenticated DFU command is a remote or adjacent takeover even if the image is signed, when the signing is not enforced on the device.
- Validate signature and parsing logic in source and host/emulator fixtures. Reaching a specific slot, radio, or server state that is not in source is `needs_validation`.
```

## Authenticity attack classes (subagent_type: `general`)

**Signature not verified on the device**
The image is signed and checked on the server or in the companion app, but the device applies it after only a transport (TLS) check, or the on-device verify call exists but its result is ignored. Trace the received image to the exact on-device verification and its accept decision. A device that installs without checking the image signature is `confirmed` and typically critical.

**Signature covers the image but not the manifest (or vice versa)**
The firmware bytes are signed but the manifest (version, target, install instructions) is not, or the manifest is signed but the payload digest in it is not enforced, so an attacker swaps one. Check that the signature binds the manifest and the payload digest together and that the device recomputes and compares the digest. An unbound manifest/payload is `confirmed`.

**Companion app or cloud as the only verifier**
Authenticity depends on a trusted phone app or cloud backend performing the check, with the device trusting a "verified" flag or a plain TLS channel. Identify where the decision is actually made. If the device cannot independently reject a forged image, it is `confirmed`; residual reliance on an unseen server policy is `needs_validation`.

## Manifest and metadata attack classes (subagent_type: `general`)

**Manifest parsing bugs (SUIT/Uptane/custom)**
The manifest parser (SUIT CBOR, Uptane JSON, or a custom format) has the same bounds/integer/type bugs as any parser, and it runs before the image is trusted. Apply `FIRMWARE-MEMORY-SAFETY.md` to the manifest decoder and check that every field used for installation (component IDs, offsets, sizes) is range-checked. A reachable parser overflow is `confirmed`.

**Version comparison weaknesses**
Version checks use string compare instead of numeric, a signed field that can go negative, or ignore pre-release/build fields, letting a lower or crafted version be accepted as newer. Grep for version comparison code and confirm it is monotonic and numeric. A comparison that permits a downgrade is `confirmed` (see rollback below).

**Missing vendor/class/target binding**
The updater does not check that the image is for this product, hardware class, or component, so an image signed for a different device in the same fleet/PKI installs. Verify vendor ID, class ID, and board/target checks against the image/manifest. A missing binding that allows a cross-product image is `confirmed`.

## Rollback and freeze attack classes (subagent_type: `general`)

**Downgrade to a signed-but-vulnerable version**
A validly signed older image with a known defect is accepted because anti-rollback is absent or not enforced (see `BOOT-CHAIN-AND-SECURE-BOOT.md` for the counter). Trace the version/counter check in the update path specifically. An accepted downgrade is `confirmed`.

**Freeze and timestamp attacks**
An attacker withholds updates or replays old metadata to keep the device on a vulnerable version; Uptane timestamp/snapshot roles exist precisely to prevent this. Check whether the device enforces metadata freshness and expiry. A missing freshness check is often `needs_validation` because it depends on server/metadata behavior, unless the device code clearly never checks.

**A/B slot confirm and revert logic**
The device swaps to a new slot but the confirm (`boot_set_confirmed`/mark-valid) or revert logic is wrong, so an unconfirmed or reverted image persists, or a failed update is not rolled back. Trace the swap/confirm/revert state machine. A logic error that persists an unverified image or bricks on revert is `confirmed`.

## Transfer and storage attack classes (subagent_type: `general`)

**Partial/resumed download offset handling**
Resumable transfers trust an attacker-supplied offset or length when writing chunks, allowing writes outside the staging area or an inconsistent assembled image. Check offset/length validation against the staging partition size on every chunk, including resume. An out-of-partition write is `confirmed`.

**Staging-area and decompression overflow**
The received image or a decompressed stream (LZ4, zlib, heatshrink) exceeds the staging buffer/partition, or a decompression bomb exhausts flash/RAM, because the expanded size is not bounded. Check size limits after each decompression stage and against the destination. A reachable overflow or unbounded expansion is `confirmed`; see `SAFETY-AND-AVAILABILITY.md` for the exhaustion angle.

**Delta/patch application bounds**
Delta updates (bsdiff, detools) apply a patch against the current image; attacker-controlled patch control data can drive writes outside the target buffer or produce an image that skips verification. Review the patch interpreter's bounds and that the final image is verified like a full image. A patch-driven out-of-bounds write is `confirmed`.

**Writing outside the target partition**
Component or multi-image updates compute the write destination from manifest fields without checking it stays within the intended partition, overwriting the bootloader, keys, or another slot. Verify destination bounds for every component. An out-of-partition write is `confirmed`.

## Update-channel attack classes (subagent_type: `general`)

**Unauthenticated DFU/SMP transport commands**
BLE/serial DFU and SMP/mcumgr `img_mgmt` accept start/write/confirm commands without authenticating the requester, so a nearby or connected attacker drives an update; if image signing is also not enforced on the device, this is a full takeover. Check the mcumgr transport auth, the `img_mgmt` upload handler, and Nordic DFU bonding requirements. Unauthenticated control of the update state is `confirmed` (severity depends on whether signing is enforced).

**Dangerous mcumgr/SMP groups enabled in production**
The `os`, `fs`, and `shell` mcumgr groups expose filesystem access and a command shell over the DFU transport; left enabled in production they allow file read/write or command execution. Grep the config for `CONFIG_MCUMGR_GRP_FS`, `CONFIG_MCUMGR_GRP_SHELL`, and `CONFIG_MCUMGR_GRP_OS_*`. A production-enabled `fs`/`shell` group reachable by an attacker is `confirmed`.

**Update triggers from unauthenticated topics/messages**
Cellular/MQTT/CoAP update triggers subscribe to a topic or accept a message that any party can publish, starting a download from an attacker URL. Trace the trigger handler to the download and verify the source and the image check. An unauthenticated trigger that fetches and installs an unverified image is `confirmed`.

**USB mass-storage drag-and-drop updates**
A UF2/MSC bootloader accepts a dropped file and flashes it with weak or no verification, so physical or malware-on-host access flashes arbitrary firmware. Check the MSC update handler's verification. Reachability needs physical/host access, so record the vector; unsigned-accept is `confirmed` with the physical vector noted.

## Fleet and server-side-in-repo attack classes (subagent_type: `general`)

**Signing keys and unsigned artifacts in CI**
Update signing keys live in the repository or CI, images are published unsigned, or the signing step is skipped for some channels. Grep CI for signing commands, key material, and artifact publication. A committed signing key or an unsigned published artifact is `confirmed` (see `TOOLCHAIN-SDK-AND-SUPPLY-CHAIN.md`).

**Key rotation and revocation gaps**
The update system cannot rotate or revoke a compromised signing key, or the device trusts a single immutable key with no backup/rotation path. Review the key hierarchy and revocation handling in the repo. A missing revocation path is a design weakness; downstream impact is often `needs_validation`.

## Universal moves (apply across the above)

- Trace one image end to end: trigger, transport, manifest parse, version/target check, signature verify, decompression/patch, staging write, slot confirm, and the boot-time re-verification. Mark where authenticity is actually decided.
- Separate transport authentication (who may start/write an update) from image authenticity (what bytes are accepted); both must hold.
- Apply memory-safety discipline to manifest decoders, decompressors, and patch interpreters, which all run on attacker data before trust.
- Check the shipped configuration for enabled DFU/SMP groups and disabled signing, not the default sample config.
- When reaching a slot, radio, or server state is not source-visible, stop at `needs_validation` with the exact owner-observed step.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust actor (adjacent DFU peer, network attacker, malicious server, physical USB) and the exact authenticity or versioning invariant that fails.
2. Confirm where the device itself verifies image and manifest; server/app-only verification is a device-side `confirmed` defect.
3. Reproduce parser, decompression, patch, and offset bugs in a host/emulator fixture; reaching a specific slot or radio/server state that is not in source is `needs_validation`.
4. For rollback/freeze, show whether version and freshness are enforced and where the floor is stored; classify downgrade versus brick.
5. Distinguish an unauthenticated update transport from unenforced image signing; state the severity for each and for their combination.
6. Return `confirmed` only with a complete source trace and bounded evidence; return `needs_validation` with the precise slot, radio, server, or metadata fact an owner must observe.
