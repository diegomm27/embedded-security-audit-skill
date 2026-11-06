# Firmware Image Analysis Hunting

#### When to use this file

Reach for this file when the only input is a firmware **image** (a binary), not a source tree: a `.bin`, `.hex`, `.uf2`, `.elf`, FIT/uImage, or a Linux filesystem image (SquashFS/UBI/JFFS2/CPIO). It is the secondary operating mode of this skill; a source tree always takes priority. Once you recover source, strings, or decompiled functions, route findings into the matching companion (`FIRMWARE-MEMORY-SAFETY.md`, `BOOT-CHAIN-AND-SECURE-BOOT.md`, `EMBEDDED-LINUX-AND-USERSPACE.md`, `CRYPTO-KEYS-AND-SECURE-STORAGE.md`, and so on). This file owns extraction, triage, static recovery, and the limits of emulation.

Split a large image into extraction/triage, static analysis, and emulation; treat each extracted component as its own untrusted sub-target.

## Core discipline (include in every agent prompt for this domain)

```
- Extract and analyze only inside the sandbox with already-installed tools. Never execute an extracted binary outside emulation; never flash or run it on hardware.
- Treat every extracted archive as untrusted input: no symlink following, apply the promotion-procedure size limits, and quarantine extracted files to scratch.
- Record the location of a hardcoded secret or key, never its value.
- Rehosting differs from real hardware; most dynamic results from emulation are needs_validation unless the code path is peripheral-independent.
- For image findings, the source-trace file is the image path plus offset/function address, line is 1, and the address or offset goes in the trace scope.
```

## Extraction and triage attack classes (subagent_type: `general`)

**Format identification and unpacking**
Identify the container and code format before anything else: ELF, Intel HEX, raw binary with a vector table at the base, UF2, FIT/uImage, SquashFS, UBI/UBIFS, JFFS2, or CPIO. Use already-installed tools only (`file`, `binwalk`, `unblob`, `ubireader`, `jefferson`, `sasquatch`, `dtc`) inside the sandbox, with no symlink following and the promotion size limits applied. A misidentified format wastes the pass; record the identified layout and partitions as the starting map.

**Encryption and entropy triage**
Check whether the image or a partition is encrypted/compressed by entropy (high uniform entropy suggests encryption or compression). High entropy that blocks static analysis is a fact to record, not a vulnerability, and it makes most deeper findings `needs_validation` pending a source or key. Note where entropy drops (headers, config partitions) as analyzable regions.

**Hardcoded secrets and credentials in the image**
Scan for keys, certs, passwords, and tokens with `strings` and targeted searches (`-----BEGIN`, `password`, known default creds), and locate `/etc/shadow`, Wi-Fi configs, and key files in extracted filesystems. Record the location (image path plus offset) only, never the value. A real secret reachable by a production path is `confirmed`; a value you cannot tie to a code path is `needs_validation`.

**Component version and web-root triage**
Identify BusyBox, OpenSSL/mbedTLS, kernel, and server versions from strings/banners, and scan the web root and CGI directory in a Linux image. Record versions and describe risk generically (do not invent CVE numbers; cite a real well-known example where apt). Route web/CGI findings to `EMBEDDED-LINUX-AND-USERSPACE.md`.

## Static-analysis attack classes (subagent_type: `general`)

**Memory-map and vector-table recovery**
For a bare-metal image, recover the memory map from the vector table (initial SP and reset vector at the image base) and any SVD/peripheral description, so disassembly lands at the right base address. An incorrect base makes every later address wrong. Record the recovered base/entry and use it as `scope` context in traces.

**Parser and handler discovery via string references**
Use Ghidra headless or radare2 (only if installed) to find parsers and command handlers by cross-referencing format/error strings and command tables, then apply the memory-safety and protocol companions to the recovered functions. A recovered parser bug is reported with the function address in `scope`, file = image path, line = 1. Decompiler-only findings without a reproducible path are `needs_validation`.

**Boot and verification logic recovery**
Locate the bootloader/verification routine by its strings and the reset path, and apply `BOOT-CHAIN-AND-SECURE-BOOT.md` to the recovered logic (accept-on-error, downgrade, unverified recovery). A clearly recovered logic flaw is `confirmed`; one that depends on silicon state is `needs_validation`.

## Emulation attack classes (subagent_type: `general`)

**Offline rehosting only**
Emulate only with already-installed, fully offline tools: QEMU user/system, Renode, Unicorn, or a Firmadyne/FirmAE-style rehost for Linux images, with no network and no host-device passthrough. Rehosting substitutes or stubs peripherals, so behavior can differ from real hardware. Never run an extracted binary outside emulation.

**Peripheral-independent vs peripheral-dependent results**
A dynamic result on a code path that does not depend on real peripherals (a pure parser fed a fixture under emulation) can be `confirmed`; a result that depends on peripheral behavior the emulator stubs is `needs_validation`. State which category each emulation result falls into and why.

**Linux-image service rehosting**
Rehosting a Linux image can start its web server and daemons under emulation for analysis; findings there route to `EMBEDDED-LINUX-AND-USERSPACE.md`. Emulation artifacts (missing NVRAM, stubbed hardware) commonly cause false behavior, so corroborate with static analysis before confirming.

## Universal moves (apply across the above)

- Build an image map first: format, partitions, load/base addresses, entropy per region, and extracted components; treat each component as its own untrusted sub-target.
- Use only already-installed tools inside the sandbox, never follow symlinks on extraction, and apply the promotion size limits to extracted files.
- Record secret and finding locations as image path plus offset/function address, with line = 1 and the address in `scope`; do not record secret values.
- Corroborate decompiler and emulation results with static evidence; peripheral-dependent dynamic results are `needs_validation`.
- When you recover source-level structure, hand the finding to the matching domain companion and apply its validation rules.

## Validation rules (apply before reporting ANY finding here)

1. Name the attacker and the invariant as for any finding, and record the image path plus offset/function address (file = image path, line = 1, address in `scope`).
2. Extract and emulate only inside the sandbox with installed tools, offline, with no symlink following and the promotion size limits applied; never execute outside emulation or on hardware.
3. Record secret/key locations only, never values, and tie a `confirmed` secret to a production code path.
4. Treat high entropy (likely encryption) as a fact that blocks analysis, not a finding, and mark blocked deeper analysis `needs_validation`.
5. A peripheral-independent emulated or statically proven path can be `confirmed`; peripheral-dependent or rehosting-artifact results are `needs_validation`.
6. State component versions without inventing CVE numbers; return `confirmed` only with a corroborated path and `needs_validation` with the exact source, key, or on-target fact an owner must supply.
