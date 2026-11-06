# Device Protocols and Cloud Link Hunting

#### When to use this file

Reach for this file when the device talks to a cloud backend, a companion app, or another device over application protocols: MQTT, CoAP, LwM2M, HTTP(S) clients, and the JSON/CBOR/protobuf payloads they carry; device shadow/twin; and local LAN control APIs. Pair it with `CRYPTO-KEYS-AND-SECURE-STORAGE.md` for TLS/DTLS verification and device identity, `FIRMWARE-UPDATE-AND-OTA.md` for update triggers, and `WIRELESS-AND-RADIO-PROTOCOLS.md` for the transport beneath. This file owns the device-side protocol client, the trust it places in the cloud and the app, and replay.

Split a large target into protocol clients/parsers, device-cloud identity, companion-app link, and time/replay.

## Core discipline (include in every agent prompt for this domain)

```
- A topic, URI, or command that executes device actions is an input surface; trace it to the handler and check authorization and bounds.
- Payload parsers (cJSON, tinycbor, nanopb) run on attacker or cloud-controlled bytes; apply memory-safety discipline.
- The cloud and the companion app are not automatically trusted. Cloud-pushed desired state and app commands must be validated on the device.
- Without a real-time clock, certificate validity and token expiry checks may be skipped; check how time is obtained and trusted.
- Validate parsers and logic in host fixtures; reaching a specific broker/cloud/app state not in source is needs_validation.
```

## On-device protocol-client attack classes (subagent_type: `general`)

**Topic/URI command handlers executing actions**
An MQTT topic, CoAP URI, or HTTP route handler maps a message to a device action (reboot, config change, actuator, update) without authenticating the sender or authorizing the action. Trace each subscribed topic/route to its handler and check the gate. An action reachable from an unauthenticated or wrong-tenant message is `confirmed`; actuator effects may be `safety_relevant`.

**JSON/CBOR/protobuf parsing bounds**
cJSON, tinycbor, nanopb, or a custom decoder parses untrusted payloads with the usual length/nesting/type bugs (deep nesting, unbounded arrays, type confusion). Apply memory-safety discipline and check decode limits. A reachable overflow, over-deep recursion, or type confusion is `confirmed`; see `SAFETY-AND-AVAILABILITY.md` for exhaustion.

**DTLS/TLS client verification**
The protocol client disables or weakens certificate/PSK verification (no CA check, no hostname/identity check, `VERIFY_NONE`), so a network attacker MITMs the cloud link. Grep for the TLS/DTLS setup and verification mode (cross-reference `CRYPTO-KEYS-AND-SECURE-STORAGE.md`). Disabled verification on the cloud link is `confirmed`.

**CoAP block-wise and LwM2M object handlers**
CoAP block-wise transfer reassembly mishandles block numbers/sizes (overflow or inconsistent assembly), or LwM2M object write/execute handlers accept writes to sensitive objects (an Execute on the firmware-update object, a write to a security object) without authorization. Check the reassembler bounds and object-write/execute authorization. A reachable overflow or an unauthorized sensitive-object operation is `confirmed`.

## Device-cloud identity attack classes (subagent_type: `general`)

**Per-device vs shared credentials**
The device authenticates to the cloud with a credential shared across the fleet rather than a per-device identity, so extracting it from one device impersonates many. Check how the device credential/cert is provisioned and whether it is unique. A shared cloud credential is `confirmed` (fleet-wide).

**Device shadow/twin trust**
The device applies cloud-pushed desired state (shadow/twin) without validating ranges, authorization, or consistency, so a compromised or mis-scoped cloud command drives the device into an unsafe or unauthorized state. Trace desired-state application to its effect. Unvalidated application of desired state is `confirmed`; safety effects may be `safety_relevant`.

**Command channel and tenant mixing**
A cloud command channel does not bind commands to this device/tenant, or a cloud backend included in the repo mixes tenants so one tenant's command reaches another's device. Check command-to-device binding and tenant scoping in any in-repo backend. A cross-tenant command path is `confirmed`.

## Companion-app link attack classes (subagent_type: `general`)

**LAN API trusting the local network**
A local HTTP/UDP discovery or control API trusts any device on the LAN, so another LAN host (or a malicious app) controls the device without authentication. Check the local API's authentication. An unauthenticated LAN control API for dangerous actions is `confirmed`.

**App-supplied credentials and local message authentication**
The device trusts credentials or a "verified" flag supplied by the companion app, or local control messages between app and device have no message authentication, allowing replay or forgery by a LAN attacker. Check whether local control is authenticated and integrity-protected. Missing message authentication for control is `confirmed`.

**Replay of local control messages**
Local control messages have no nonce/counter, so a captured message replays. Check for anti-replay on the local channel. A replayable control is `confirmed`; on-wire capture confirmation may be `needs_validation`.

## Time and replay attack classes (subagent_type: `general`)

**No RTC so certificate/token time checks are skipped**
The device lacks a trusted time source and therefore skips certificate validity or token expiry checks, accepting expired or not-yet-valid credentials. Check how time is obtained and whether validity is enforced. Skipped time validation is `confirmed` (or `needs_validation` if the enforcement is conditional on an unseen RTC).

**NTP/time-source trust and replay windows**
The device trusts unauthenticated NTP or a cloud time value for security decisions, or has a wide replay window for signed messages. Check the time source and replay-window size. A security decision driven by spoofable time, or an over-wide replay window, is `confirmed`; spoofing confirmation may be `needs_validation`.

## Universal moves (apply across the above)

- Enumerate every subscribed topic, URI, route, and local API, and for each record who can send it, whether it is authenticated, and what action it reaches.
- Apply memory-safety discipline to every payload decoder (JSON/CBOR/protobuf, CoAP reassembly) running on cloud or peer data.
- Check that the device independently validates cloud desired-state and app-supplied data rather than trusting the sender.
- Verify TLS/DTLS verification and per-device identity; a shared credential or disabled verification is high-impact.
- Where broker/cloud/app behavior or a real clock is not source-visible, stop at `needs_validation` with the exact owner-observed fact.

## Validation rules (apply before reporting ANY finding here)

1. Name the attacker (network, cloud tenant, LAN host, companion app) and the exact invariant: authentication, authorization, payload bound, identity scope, or replay.
2. Reproduce parser bugs in a host fixture; reaching a specific broker/cloud/app state not in source is `needs_validation`.
3. For identity, show per-device vs shared scope; a shared credential is `confirmed` and typically critical.
4. For shadow/twin and app-supplied data, prove the device applies it without validation; mark `safety_relevant` only when source shows the actuator path.
5. Treat disabled TLS/DTLS verification on a security-relevant channel as `confirmed`.
6. Return `confirmed` only with a source trace and bounded evidence; return `needs_validation` with the exact broker, cloud, app, or time fact an owner must observe.
