# Fieldbus, Automotive, and ICS Hunting

#### When to use this file

Reach for this file when the device speaks an automotive, industrial, or building bus: UDS/CAN and ISO-TP, SecOC, AUTOSAR crypto, Modbus, PROFINET, EtherNet/IP/CIP, BACnet, DNP3, OPC UA, or a proprietary serial protocol in medical/industrial gear. Pair it with `FIRMWARE-MEMORY-SAFETY.md` for the frame/reassembly parsers, `CRYPTO-KEYS-AND-SECURE-STORAGE.md` for SecurityAccess and SecOC keys, and `SAFETY-AND-AVAILABILITY.md` for actuator and safety effects. The attacker here is usually on the bus (local bus vector). This file reasons from source; it never puts a frame on a real bus.

Split a large target by domain: automotive diagnostics (UDS/ISO-TP/SecOC/gateway), industrial (Modbus/PROFINET/CIP/BACnet/DNP3/OPC UA), and proprietary/medical.

## Core discipline (include in every agent prompt for this domain)

```
- A protocol that is unauthenticated by design is context, not a finding, unless the product claims a control over it. Findings come from parser bugs, bypassed product controls, and missing gating of dangerous functions.
- The attacker is on the bus; name the local-bus vector and whether a diagnostic session or security level is required to reach the function.
- Reassembly (ISO-TP, segmented industrial PDUs) is a prime memory-safety surface: trust the received length, not the declared one.
- Dangerous services (write memory, flash, routine control, actuator writes) must be gated by session and security level; verify the gate, not just its existence.
- Never transmit on a real bus. On-bus behavior and timing not in source are needs_validation with a bench plan.
```

## Automotive attack classes (subagent_type: `general`)

**UDS SecurityAccess (0x27) seed/key weakness**
The SecurityAccess seed is static or predictable, the seed-to-key algorithm is weak or fleet-shared, or there is no delay/attempt limiting, so an attacker computes the key and unlocks diagnostics. Grep for service `0x27`, `RequestSeed`/`SendKey`, the key algorithm, and attempt counters. A static seed, weak/shared algorithm, or missing lockout is `confirmed`.

**Dangerous services reachable without session/security**
RoutineControl (0x31), WriteDataByIdentifier (0x2E), RequestDownload/TransferData (0x34/0x36), or ECUReset (0x11) are reachable without the required diagnostic session or security level. Check the session/security precondition on each service handler. A dangerous service reachable unauthenticated is `confirmed`; actuator effects may be `safety_relevant`.

**ISO-TP reassembly length handling**
The ISO-TP (ISO 15765-2) reassembler trusts the declared total length or a flow-control frame, overflowing the reassembly buffer or mishandling consecutive-frame indices. Apply memory-safety discipline to the reassembler. A reachable overflow is `confirmed`.

**Gateway CAN ID allowlists and routing**
A CAN gateway forwards or acts on frames without an ID allowlist, or diagnostic frames cross from a low-trust bus to a high-trust one. Check the gateway's routing/filter tables. A missing filter that lets an attacker-reachable bus reach a safety-critical ECU is `confirmed`.

**SecOC freshness and MAC truncation; AUTOSAR crypto config**
SecOC uses a truncated MAC that is too short, a freshness value that is predictable or not enforced, or an AUTOSAR CSM/crypto-stack configuration with weak keys/algorithms, allowing forgery or replay of authenticated messages. Check SecOC MAC length, freshness handling, and the crypto config. A forgeable/replayable SecOC message is `confirmed`.

**Diagnostic session timeout handling**
A security-unlocked diagnostic session does not time out or persists across resets, widening the window for privileged operations. Check session-timeout logic. A session that does not expire as required is `confirmed`.

## Industrial attack classes (subagent_type: `general`)

**Function-code handler bounds (Modbus and friends)**
Modbus/TCP or RTU, or another fieldbus, handles a function code with register addresses/counts from the wire without bounding them against the actual register map, causing out-of-bounds reads/writes. Check each function-code handler's address/count validation. A reachable out-of-bounds is `confirmed`; the unauthenticated nature of Modbus itself is context unless a control is claimed.

**Write-to-coil/register paths affecting actuators**
A write function (write coil/register, CIP set-attribute) drives an actuator or changes a setpoint without the authorization the product claims, or with no bounds on the value. Trace the write to the actuator/setpoint. An unauthorized or unbounded actuator write is `confirmed` and may be `safety_relevant`.

**Protocol parser bounds (PROFINET/CIP/BACnet/DNP3)**
PROFINET, EtherNet/IP/CIP, BACnet, or DNP3 PDU parsers trust lengths/counts/offsets from the wire. Apply memory-safety discipline to each parser. A reachable parser overflow is `confirmed`.

**OPC UA security policy and PLC program upload**
OPC UA accepts security policy `None` (unauthenticated/unencrypted) where the product requires security, or the PLC runtime accepts a program/logic upload without authentication, letting an attacker change control logic. Check the allowed security policies and the program-upload auth. A `None`-allowed endpoint where a control is claimed, or an unauthenticated program upload, is `confirmed`.

## Proprietary and medical attack classes (subagent_type: `general`)

**Proprietary serial protocol parsing and command allowlists**
A proprietary serial/medical protocol parses untrusted frames with the usual bugs, or exposes dangerous commands without an allowlist/authorization. Apply memory-safety and gating discipline. A reachable parser bug or ungated dangerous command is `confirmed`, with safety impact noted where an actuator is involved.

## Universal moves (apply across the above)

- First decide whether the product claims a control over the protocol. If the protocol is unauthenticated by design and no control is claimed, that is context; hunt parser bugs, bypassed claimed controls, and ungated dangerous functions instead.
- For each dangerous service/function, verify the session/security/authorization gate on the handler path, including sibling and legacy handlers.
- Apply memory-safety discipline to every reassembler and PDU parser; the declared length is attacker-controlled.
- Trace actuator and setpoint writes to their physical effect and mark `safety_relevant` where source shows the actuator path.
- Never transmit on a real bus; keep on-bus reachability and timing as `needs_validation` with a bench plan on isolated hardware the owner controls.

## Validation rules (apply before reporting ANY finding here)

1. Name the local-bus attacker and the exact invariant: a parser bound, a bypassed claimed control, or a missing session/security gate on a dangerous function.
2. State explicitly whether the protocol's lack of authentication is in scope (a claimed product control) or context (by-design openness).
3. Reproduce parser and reassembly bugs in a host fixture; on-bus timing and reachability not in source are `needs_validation` with an isolated-bench plan.
4. For SecurityAccess/SecOC, show the seed/key/MAC/freshness weakness in source; fleet-shared algorithms are `confirmed` and severe.
5. Mark actuator and setpoint effects `safety_relevant` only when source shows the actuator path; otherwise `needs_validation`.
6. Return `confirmed` only with a source trace and bounded evidence; return `needs_validation` with the exact on-bus or configuration fact an owner must confirm on isolated hardware.
