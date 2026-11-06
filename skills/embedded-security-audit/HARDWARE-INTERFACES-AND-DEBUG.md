# Hardware Interfaces and Debug Hunting

#### When to use this file

Reach for this file when the target exposes debug ports, console interfaces, test/factory modes, external memories, or trust-sensitive buses: JTAG/SWD, UART consoles, USB/serial test commands, XIP from external QSPI, external EEPROM/flash config, SD-card boot, and the I2C/SPI link to a secure element. Pair it with `BOOT-CHAIN-AND-SECURE-BOOT.md` (debug-mode effect on boot), `DEVICE-LIFECYCLE-AND-PROVISIONING.md` (who locks the device and when), and `FAULT-INJECTION-AND-SIDE-CHANNEL.md` (debug-unlock glitching). This file reasons from source and provisioning scripts; it never attaches a probe or reads a fuse.

Split a large target into debug ports, console/UART, test/factory modes, external memories, and bus trust.

## Core discipline (include in every agent prompt for this domain)

```
- Judge debug/lock state from provisioning scripts and option-byte/fuse programming code, not from a dev-board default. Never assume production is locked or unlocked.
- Debug and console findings need an attacker vector (physical pins, exposed header, accessible port) recorded, and physical-only paths are capped per the severity rules.
- Runtime re-enable of debug, or a console command that dumps/writes memory, defeats a lock even if the fuse is set.
- An external memory or bus that carries secrets or boot code without integrity/encryption is interposable or replaceable; state the physical vector.
- Never touch hardware. Any fact that needs silicon (actual fuse value, lock level, glitch behavior) is needs_validation with a bench plan.
```

## Debug-port attack classes (subagent_type: `general`)

**JTAG/SWD not locked in production provisioning**
The provisioning flow does not program the debug-lock mechanism, or programs a weak level: STM32 RDP level and option-byte writes, nRF `APPROTECT`/`UICR` settings, ESP32 `JTAG_DISABLE` eFuse, NXP debug authentication, SAM `SECURITY` bit. Grep provisioning scripts and option-byte/fuse code for these symbols and what level they set. A provisioning flow that leaves debug open is `confirmed` as a design/process defect; the actual shipped fuse state is `needs_validation` with a bench read.

**Runtime re-enable of debug**
Application or bootloader code re-enables the debug port, lowers RDP, or clears a lock at runtime under some condition (a command, a strap, a failed check), undoing the provisioned lock. Grep for writes to debug-control/option-byte registers after boot. A reachable re-enable is `confirmed`.

**Weak debug-authentication challenge**
A challenge-response debug-unlock implementation uses a static secret, a weak/predictable challenge, a non-constant-time compare, or a fleet-shared unlock key. Review the debug-auth handler. A weak or shared unlock is `confirmed` (fleet-shared is severe); timing exploitability is `needs_validation`.

## Console and UART attack classes (subagent_type: `general`)

**Bootloader/app console enabled in release**
A U-Boot console, bootloader menu, or application UART shell is enabled in the release build and reachable on an accessible header, exposing boot interruption, memory dump, or flash write. Check the release config for console enablement and the commands exposed. A reachable release console with dangerous commands is `confirmed`, physical vector recorded.

**Login-less root shell on serial**
The serial console drops to a root shell with no authentication, or `/etc/inittab`/getty spawns an unauthenticated shell. Grep init/getty config. An unauthenticated serial root shell is `confirmed`.

**Console commands that dump or modify memory/flash/config**
Console or monitor commands read memory, write flash, or change configuration without authorization, turning console access into key extraction or persistence. Enumerate command handlers for `md`/`mw`/`flash`/peek/poke-style operations and config writes. Dangerous commands reachable on the console are `confirmed`.

## Test and factory-mode attack classes (subagent_type: `general`)

**Magic GPIO/button or strap sequences**
A GPIO strap, button combination, or boot-pin sequence enters a test/factory mode that bypasses auth, enables debug, or exposes commands, and it can ship enabled. Grep for strap/button reads that select a mode. A reachable test mode in production is `confirmed`, physical vector recorded.

**Test-mode commands over USB/serial and hidden USB requests**
A vendor USB control request, HID report, or serial command enters manufacturing/test functionality (calibration, key injection, raw flash access) left reachable in production. Grep USB descriptor/control-request handlers and serial command tables for undocumented entries. A reachable test command is `confirmed`.

**Manufacturing/test firmware left in production**
A test image, bootloader, or partition with elevated capability ships alongside production. Check the build/partition layout for test artifacts. A present and reachable test firmware is `confirmed`.

## External-memory attack classes (subagent_type: `general`)

**XIP from external QSPI without encryption/authentication**
The MCU executes in place from external QSPI flash that is neither encrypted nor authenticated, so an attacker who reprograms or interposes the flash runs arbitrary code. Check the XIP configuration and whether on-the-fly decryption/authentication (OTFDEC-style) is used. Unauthenticated XIP is `confirmed` with the physical flash-access vector recorded.

**External EEPROM/flash storing config or secrets without integrity**
Configuration, keys, or calibration lives in an external EEPROM/flash without integrity protection, so it can be read or modified by replacing or reading the chip. Check what the external part stores and whether it is authenticated/encrypted. Unprotected secret/config storage is `confirmed`, physical vector recorded.

**SD card / USB mass storage loading config or scripts at boot**
The device reads config, scripts, or firmware from removable media at boot without authentication, so swapped media changes behavior. Grep boot/init for mounts and config/script loads from removable media. An unauthenticated load is `confirmed`, removable-media vector recorded.

## Bus-trust attack classes (subagent_type: `general`)

**Interposable I2C/SPI peripherals**
A peripheral on an accessible I2C/SPI bus can be replaced or interposed, and the MCU trusts its responses for a security decision (see peripheral-trust in `FIRMWARE-MEMORY-SAFETY.md` for the parsing side). Identify security-relevant peripherals on external buses. Reliance on a replaceable peripheral for a security decision is `confirmed` with the physical vector; parsing bugs are confirmed separately.

**Secure-element link not bound or encrypted**
The I2C link to an ATECC/SE050/secure element carries authentication results or key operations without an encrypted/authenticated session (I/O protection), so the link is sniffable or replayable. Check whether the SE's encrypted-session/IO-protection features are used. An unbound SE link is `confirmed` with the bus-access vector recorded.

**Sensor spoofing affecting security or safety decisions**
A security or safety decision depends on a sensor value that a physical attacker can spoof (a Hall sensor for tamper, a current sensor for a safety interlock). Trace the decision to the sensor input. Reliance on a spoofable sensor for a security/safety control is `confirmed` or `safety_relevant`, with the physical vector and, if the actuator path is not fully source-visible, `needs_validation`.

## Universal moves (apply across the above)

- Read the provisioning/manufacturing scripts and option-byte/fuse code to learn what the production flow actually locks; treat the dev-board default as unknown.
- For every debug/console/test entry, record the physical access required and the attacker vector; physical-only findings cap at medium unless they yield a fleet-wide secret.
- Check for runtime paths that undo a provisioned lock (debug re-enable, RDP regression, console-triggered unlock).
- For external memories and buses, state whether boot code, config, or secrets cross them without integrity/encryption, and name the replace/interpose/sniff vector.
- Never attach a probe or read a fuse; keep silicon facts as `needs_validation` with a precise bench plan the owner runs.

## Validation rules (apply before reporting ANY finding here)

1. Name the physical attacker vector (exposed pins/header, accessible port, removable media, replaceable chip, bus access) and the exact control defeated.
2. Base debug/lock claims on provisioning and option-byte/fuse code; the shipped fuse/RDP state is `needs_validation` with a bench read, never assumed from a dev config.
3. Cap physical-invasive-only findings at medium unless they yield a fleet-wide secret, and set `attack_vector` and a hardware-configuration condition accordingly.
4. For runtime re-enable and dangerous console/test commands, show the reachable code path; a command gated behind a lock you cannot prove is set is `needs_validation`.
5. For external memory/bus trust, prove from source that boot code, config, or secrets cross without integrity/encryption; the physical step is `needs_validation` where it needs confirmation.
6. Return `confirmed` only with a source trace and the recorded vector; return `needs_validation` with the exact fuse, lock-level, or bench observation an owner must perform.
