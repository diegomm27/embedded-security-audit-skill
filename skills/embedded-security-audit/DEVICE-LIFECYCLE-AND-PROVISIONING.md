# Device Lifecycle and Provisioning Hunting

#### When to use this file

Reach for this file when the repository contains manufacturing/provisioning scripts, lifecycle-state transitions, factory-reset and decommissioning logic, device claiming/onboarding, or end-of-life handling. Pair it with `HARDWARE-INTERFACES-AND-DEBUG.md` (what provisioning locks), `CRYPTO-KEYS-AND-SECURE-STORAGE.md` (the keys provisioning injects and reset must erase), and `DEVICE-PROTOCOLS-AND-CLOUD-LINK.md` (claiming and identity). This file owns the device's security posture across its life: factory to field to RMA to retirement.

Split a large target into manufacturing/provisioning, lifecycle state, factory reset/decommissioning, onboarding/claiming, and end of life.

## Core discipline (include in every agent prompt for this domain)

```
- Provisioning commands and interfaces that are safe in the factory are dangerous if they remain enabled in the field; check what disables them.
- A lock step skipped in provisioning (debug lock, secure-boot enable, key finalization) leaves the fleet open; read the scripts.
- Factory reset must erase every secret and credential; a reset that leaves keys or Wi-Fi passwords is a disclosure path.
- Claiming/onboarding must prevent a stranger from taking ownership; guessable identifiers and first-user-wins are the common failures.
- Provisioning scripts and lifecycle code are source-visible; the resulting silicon state (fuses, lifecycle register) is needs_validation.
```

## Manufacturing and provisioning attack classes (subagent_type: `general`)

**Provisioning commands enabled after the factory**
Commands or interfaces used to inject keys, set config, or run tests remain reachable in field firmware (a provisioning UART menu, a USB test command, a "factory" GATT service) with no gate that disables them post-provisioning. Grep for provisioning/test command handlers and whether a fuse/flag disables them. A field-reachable provisioning command is `confirmed`.

**Provisioning scripts that skip locking**
The provisioning flow does not program the debug lock, enable secure boot, finalize keys, or advance the lifecycle state, so units ship unlocked. Read the provisioning scripts and option-byte/fuse programming for missing lock steps. A provisioning flow missing a lock step is `confirmed` as a process defect; the shipped state is `needs_validation`.

**Shared provisioning secrets**
Provisioning uses a single secret, unlock token, or key across all devices, so compromising the factory secret compromises the fleet. Check whether provisioning material is per-device. A shared provisioning secret is `confirmed` (fleet-wide).

**Keys injected over an unauthenticated channel**
Device keys are injected over plain serial/USB during provisioning with no authentication or encryption of the channel, so anyone with the interface injects or reads keys. Check the key-injection path. An unauthenticated injection interface reachable outside a controlled factory is `confirmed`; factory-only reachability records the vector.

## Lifecycle-state attack classes (subagent_type: `general`)

**PSA lifecycle transition gaps**
PSA lifecycle (`PSA_LIFECYCLE_*`) transitions are not enforced, or the device operates in a debug/assembly lifecycle where it should be in secured, exposing debug or test functionality. Check lifecycle-state reads and the operations gated on them. A missing or wrong lifecycle gate is `confirmed`; the actual lifecycle value is `needs_validation`.

**RMA/return mode re-enabling debug without key erase**
An RMA or service mode re-enables debug or opens the device for diagnostics without first erasing keys/secrets, exposing them to the service path. Check the RMA transition and whether it wipes secrets before unlocking. An RMA path that unlocks without erasing is `confirmed`.

**Secure-debug unlock tokens**
A secure-debug unlock uses a static, fleet-shared, or weakly verified token, letting an attacker unlock any device. Check the unlock-token verification (shared with `HARDWARE-INTERFACES-AND-DEBUG.md`). A shared/weak unlock token is `confirmed`.

## Factory-reset and decommissioning attack classes (subagent_type: `general`)

**Reset that does not wipe secrets**
Factory reset clears user settings but leaves keys, certificates, Wi-Fi passwords, pairing bonds, or user data in flash/NVS, so a resold or discarded device discloses them. Trace the reset handler and enumerate what it erases versus what holds secrets. Secrets surviving reset are `confirmed`.

**Remotely triggerable reset without auth**
A factory reset (or a destructive decommission) can be triggered remotely or by an unauthenticated message, enabling denial of service or forced re-onboarding. Check the reset trigger's authentication. An unauthenticated remote reset is `confirmed` (availability, possibly worse if it enables re-claiming).

**Ownership transfer gaps**
Decommissioning/ownership transfer does not revoke the prior owner's access or cloud binding, so the previous owner retains control after resale. Check the transfer flow. A transfer that leaves prior access is `confirmed`.

## Onboarding and claiming attack classes (subagent_type: `general`)

**Guessable claim codes**
Device claim codes are derived from guessable serials, MACs, or short predictable values, so an attacker claims a device they do not possess. Check how claim codes are generated and their entropy. Guessable claim identifiers are `confirmed`.

**First-user-wins claiming**
The first party to claim an unclaimed device wins, with no proof of possession, so an attacker claims devices before the legitimate owner. Check the claim flow for a possession proof. First-user-wins without possession proof is `confirmed`.

**Default credentials not forced to change**
The device ships with default credentials that onboarding does not force the user to change, leaving a known login. Check whether onboarding mandates a credential change. Unforced default credentials are `confirmed`.

## End-of-life attack classes (subagent_type: `general`)

**Certificate expiry and revocation handling**
Device or CA certificates expire with no renewal path, or there is no way to revoke a compromised device, so the fleet degrades or stays trusting a bad device. Check cert lifetime and revocation handling. A missing renewal/revocation path is a weakness; downstream impact may be `needs_validation`.

## Universal moves (apply across the above)

- Read the provisioning and manufacturing scripts first; they reveal what the production flow actually locks, injects, and finalizes.
- For every provisioning/test/RMA interface, determine what disables it after its phase and whether it is reachable in the field.
- Enumerate every secret in storage and confirm factory reset erases each one; a single survivor is a disclosure path.
- For claiming, require a proof of possession and sufficient claim-code entropy; map the exact window an attacker could claim.
- Keep silicon lifecycle/fuse state as `needs_validation`; the scripts and code are the `confirmed` evidence of a missing or wrong step.

## Validation rules (apply before reporting ANY finding here)

1. Name the actor (field attacker, service technician, prior owner, stranger onboarding) and the exact lifecycle invariant: provisioning gate, lock step, reset erasure, claim possession, or revocation.
2. Base provisioning/lock claims on the scripts and fuse/option-byte code; the resulting silicon state is `needs_validation` with a bench read.
3. For factory reset, enumerate erased vs retained secrets from source; a retained secret is `confirmed`.
4. For claiming, show the entropy or possession gap concretely; a guessable code or first-user-wins is `confirmed`.
5. Shared provisioning/unlock secrets are `confirmed` and typically fleet-wide critical.
6. Return `confirmed` only with a source/script trace; return `needs_validation` with the exact silicon-state or process fact an owner must confirm.
