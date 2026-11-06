# Wireless and Radio Protocols Hunting

#### When to use this file

Reach for this file when the device has a radio: BLE, Wi-Fi provisioning, 802.15.4/Zigbee/Thread/Matter, LoRaWAN or proprietary sub-GHz, cellular, or NFC. Pair it with `FIRMWARE-MEMORY-SAFETY.md` for the frame parsers, `CRYPTO-KEYS-AND-SECURE-STORAGE.md` for session keys and nonces, and `DEVICE-PROTOCOLS-AND-CLOUD-LINK.md` for what rides on top. The attacker here is adjacent (in radio range), so pre-pairing/pre-auth parsers and pairing decisions dominate. This file reasons from source only; it never transmits, sniffs, or puts a radio into monitor mode.

Split a large radio target by technology (BLE, Wi-Fi, 802.15.4/Thread/Matter, LoRaWAN/sub-GHz, cellular/NFC) and by phase (pre-pairing parsing, pairing/key exchange, post-pairing).

## Core discipline (include in every agent prompt for this domain)

```
- The attacker is in radio range by default. Enumerate every handler reachable before pairing/authentication and treat all its fields as hostile.
- Judge pairing by the method actually negotiated (Just Works, legacy, fixed passkey) and whether MITM protection is required for the data it guards.
- Frame counters and nonces prevent replay only if they are monotonic across reboots and wide enough; check storage and width.
- A key shared across the fleet (default link key, shared AppKey) makes one extraction fleet-wide.
- Never transmit, sniff, or enter monitor/injection mode. On-air behavior that is not source-visible is needs_validation with a bench plan.
```

## BLE attack classes (subagent_type: `general`)

**Weak pairing method for the data it protects**
The device uses Just Works where MITM protection is needed, legacy pairing instead of LE Secure Connections, or a fixed/known passkey, so a nearby attacker pairs or MITMs. Check the `bt_security`/IO-capability configuration and the required security level for sensitive characteristics. A weak method guarding real control is `confirmed`; whether the paired data matters is the severity driver.

**GATT characteristics without required permissions/encryption**
Sensitive GATT characteristics are readable/writable without the encryption or authentication permission, so an unpaired peer reads or writes them. Grep the GATT table (`BT_GATT_CHARACTERISTIC`, `BT_GATT_PERM_*`) and check each sensitive handle requires encryption/authentication. A sensitive handle without the permission is `confirmed`.

**Pre-pairing writes to sensitive handles**
A write handler for a control/config characteristic executes before pairing completes, letting an unauthenticated peer act. Trace which write callbacks run pre-encryption. A dangerous pre-pairing write is `confirmed` (see `ATTACK-CLASSES.md#Unauthenticated pre-pairing and pre-auth parsers`).

**Custom L2CAP/ATT/SMP parsing bugs**
A vendor or custom BLE stack parses L2CAP/ATT/SMP PDUs, ATT MTU, or long-write/prepare-write buffers with the usual length/offset bugs, reachable pre-pairing. Apply memory-safety discipline to these parsers. A reachable parser overflow is `confirmed`.

**Bonding storage and privacy**
Bonding keys are stored insecurely or not cleared on reset, or the device uses a static (non-resolvable) address enabling tracking. Insecure bond storage is `confirmed` (key exposure); static-address tracking is a low-severity privacy finding unless the product claims privacy.

## Wi-Fi provisioning attack classes (subagent_type: `general`)

**Open SoftAP or cleartext credential transfer**
SoftAP provisioning uses an open network, or Wi-Fi/cloud credentials are sent in cleartext during onboarding, so an adjacent attacker captures them. Check the provisioning AP security and the credential channel. Cleartext credential transfer is `confirmed`.

**BLE/SoftAP provisioning security level**
ESP-IDF `protocomm`/`wifi_provisioning` runs at security 0 or 1 (weak or PoP-only) where security 2 (SRP6a) is needed, letting an adjacent attacker provision or capture. Check the configured `protocomm` security version and PoP handling. An inadequate level is `confirmed`.

**Captive-portal and provisioning handler injection**
The provisioning HTTP/DNS handler has injection or parsing bugs reachable during onboarding. Apply injection/memory-safety discipline. A reachable injection is `confirmed`.

## 802.15.4, Zigbee, Thread, and Matter attack classes (subagent_type: `general`)

**Default or shared network keys**
The device uses the Zigbee default Trust Center link key (`ZigBeeAlliance09`) or a shared network key, so an adjacent attacker joins or decrypts. Grep for the default key and key-distribution code. A default/shared key is `confirmed`.

**Install-code and commissioning handling**
Install codes are weak, reused, or logged, or Matter PASE passcode handling is weak and the attestation verification is skipped (a "skip attestation" debug flag in production). Check commissioning code and any attestation-bypass flags. A skipped attestation or weak passcode in production is `confirmed`.

**Frame-counter handling and replay**
802.15.4/Thread frame counters reset on reboot, are too narrow, or are not enforced, allowing replay of commands. Check counter storage, width, and enforcement. A replayable command is `confirmed`.

## LoRaWAN, sub-GHz, and proprietary attack classes (subagent_type: `general`)

**Frame-counter reset and ABP replay**
LoRaWAN `FCnt` is 16-bit where 32-bit is needed, or ABP devices reset counters on reboot, enabling replay; join nonces repeat. Check `FCnt` width, counter persistence, and join-nonce generation. A replayable uplink/downlink or reused join nonce is `confirmed`.

**Shared vs per-device AppKey**
The LoRaWAN AppKey (or proprietary session key) is shared across devices rather than per-device, so one extraction compromises the fleet. Check key provisioning. A shared AppKey is `confirmed` (fleet-wide).

**Rolling-code and proprietary remote weaknesses**
A proprietary remote/sub-GHz protocol uses a weak rolling code, fixed code, or no authentication, allowing replay or forgery. Review the code-generation and validation logic. A forgeable/replayable control is `confirmed`; on-air confirmation is `needs_validation`.

## Cellular and NFC attack classes (subagent_type: `general`)

**AT-command injection into the modem**
Data from SMS, the network, or an application reaches a modem AT-command builder without sanitization, injecting commands (dial, SMS, data-context changes). Grep AT-command construction for untrusted interpolation. A reachable AT injection is `confirmed`.

**NFC NDEF parsing bugs**
The NFC/NDEF parser trusts record lengths/types from a tag or peer, with the usual memory-safety bugs, reachable by tapping a crafted tag. Apply memory-safety discipline. A reachable parser bug is `confirmed`, proximity vector recorded.

## Universal moves (apply across the above)

- List every radio handler reachable before pairing/authentication and treat it as the primary adjacent-attacker surface.
- For each session, check key provenance (per-device vs shared), nonce/frame-counter width and persistence across reboot, and replay enforcement.
- Judge pairing/commissioning by the method actually negotiated and whether it provides the MITM protection the guarded data needs.
- Apply memory-safety discipline to every frame/PDU/NDEF parser; these are adjacent-attacker-reachable and high value.
- Never transmit or sniff; keep on-air reachability and timing as `needs_validation` with a bounded bench plan.

## Validation rules (apply before reporting ANY finding here)

1. Name the adjacent attacker and the exact radio invariant: pre-pairing reachability, pairing strength, permission on a handle, counter/nonce enforcement, or key scope.
2. Mark `attack_vector` as `adjacent_wireless` (or `physical_noninvasive` for NFC tap) and record whether MITM protection was required.
3. Reproduce parser bugs in a host build of the stack; on-air reachability, timing, and pairing behavior that are not source-visible are `needs_validation` with a bench plan.
4. Fleet-shared keys (default link key, shared AppKey) are `confirmed` and typically critical; per-device scope lowers severity.
5. A privacy-only issue (static address tracking) is low unless the product claims privacy.
6. Return `confirmed` only with a source trace and bounded evidence; return `needs_validation` with the exact on-air or pairing fact an owner must observe on the bench.
