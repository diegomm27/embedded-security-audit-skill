# Safety and Availability Hunting

#### When to use this file

Reach for this file when untrusted input can exhaust a device's limited resources, brick it, trap it in a reset loop, wear out its flash, or push a safety function into an unsafe state: small-heap allocation from the network, watchdog handling, flash-wear paths, actuator and interlock error handling, and control loops driven by spoofable sensors. Pair it with `FIRMWARE-MEMORY-SAFETY.md` (the parsers that allocate), `RTOS-AND-KERNEL.md` (stack/network limits), and `FIELDBUS-AUTOMOTIVE-AND-ICS.md`/`DEVICE-PROTOCOLS-AND-CLOUD-LINK.md` (the actuators). Never stress a live or shared device; reason from source and bounded host analysis.

Split a large target into resource exhaustion, persistent DoS/bricking, fail-open error handling, and safety-function separation.

## Core discipline (include in every agent prompt for this domain)

```
- Require an input-to-cost or input-to-unsafe-state path with a missing bound, not just "no rate limit". Self-limiting work in the device's own idle time is not a finding.
- Distinguish a transient effect (a watchdog reboot) from a persistent one (a brick, a flash wear-out, a stuck actuator). Persistence and safety raise severity sharply.
- A watchdog that is disabled, fed from the idle loop, or fed from an ISR regardless of task health does not protect against a hung task.
- Mark safety_relevant only when source shows the actuator/interlock path; otherwise the physical-world claim is needs_validation.
- Never stress a live or shared device. Use asymptotic analysis, small host fixtures, and strict local limits; actuator/timing facts are needs_validation with a bench plan.
```

## Resource-exhaustion attack classes (subagent_type: `general`)

**Unbounded allocation from network input on a small heap**
A handler allocates based on an attacker-supplied size/count on a device with a few KB of heap, so one request exhausts memory and fails subsequent (possibly safety-relevant) work. Grep for allocations sized from the wire (`pvPortMalloc(len)`, `malloc(count*size)`) without an aggregate cap. A reachable exhaustion from one or few inputs is `confirmed`; recovery behavior matters for severity.

**Connection/session/table exhaustion**
Connection, session, subscription, or pending-request tables fill without per-peer limits or cleanup on disconnect/timeout, blocking legitimate peers. Check table sizing and cleanup on every disconnect/timeout/error path. A reachable exhaustion is `confirmed`.

**Buffer and queue accumulation without cleanup**
Reassembly buffers, out-of-order segments, or queued jobs accumulate without per-item and aggregate limits or without cleanup on partial parse/cancel. Check limits and cleanup. Reachable accumulation is `confirmed`.

## Watchdog and reset attack classes (subagent_type: `general`)

**Watchdog disabled or fed regardless of health**
The watchdog is disabled in the shipped build, fed unconditionally in the idle loop or a timer ISR, or fed by a task that runs even when the real work is hung, so a hung critical task never triggers a reset. Check watchdog init and every feed site against task-health. A watchdog that cannot catch a hung critical path is `confirmed` (availability/safety context).

**Brownout/reset loop causing a wear-out brick**
Attacker-triggered or input-triggered resets, combined with a flash write on every boot, wear out flash and permanently brick the device, or a reset loop prevents operation. Check for writes on every boot and reset triggers reachable by input. A reachable persistent brick is `confirmed` and high-severity.

**Flash wear from attacker-triggered writes**
Settings or counters are written to flash on every request/event, so an attacker ages the flash to failure. Grep for flash/NVS writes inside request handlers and per-event paths. A reachable per-request write that wears flash is `confirmed`.

## Persistent-DoS and fail-open attack classes (subagent_type: `general`)

**Persistent DoS (brick) vs transient reboot**
Classify each availability issue: a watchdog reboot that recovers is transient; a corrupted-config, exhausted-flash, or bad-state-persisted condition that survives reboot is a brick. State which, because persistence changes severity from medium to high. A reachable persistent brick is `confirmed` high.

**Error handlers that fail open**
An error, timeout, or fault handler leaves an actuator energized, skips a safety interlock, or continues in an inconsistent state instead of entering a safe state. Trace error/fault paths of actuator and interlock code to the physical state they leave. A fail-open path that leaves an unsafe physical state is `confirmed` and `safety_relevant` when the actuator path is source-visible; otherwise `needs_validation`.

**Fail-safe state not defined or not reached**
The system has no defined safe state for a fault, or a fault path does not reliably reach it. Check that faults drive actuators to a defined safe state. A missing/unreachable fail-safe is `confirmed` safety context (mark `safety_relevant` when the actuator path is shown).

## Safety-function and sensor attack classes (subagent_type: `general`)

**Safety function not separated from comms code**
Safety-critical logic shares a task, memory region, or failure domain with network/comms code, so a comms fault or exhaustion disables the safety function (IEC 61508/ISO 26262 is the backdrop, not a compliance checklist). Check separation of the safety function from untrusted-input handling. A shared failure domain that lets comms disable safety is `confirmed` safety context.

**Control loops consuming spoofable sensor values**
A control loop or safety decision uses a sensor value a local/physical attacker can spoof (see `HARDWARE-INTERFACES-AND-DEBUG.md`), driving an unsafe actuator state. Trace the sensor to the actuator decision. Reliance on a spoofable sensor for a safety control is `confirmed`/`safety_relevant` when the actuator path is source-visible; the spoofing step records the physical vector and may be `needs_validation`.

## Universal moves (apply across the above)

- Build an input-to-cost/-to-unsafe-state table: earliest accepted size/count, work or state change it drives, persistence, shared resource, the missing limit, and recovery behavior.
- Separate transient from persistent effects explicitly; persistence and safety are the severity multipliers here.
- Check every watchdog feed site against whether the critical task is actually alive, not just whether some code runs.
- Trace actuator and interlock error paths to the physical state they leave; mark `safety_relevant` only with a source-visible actuator path.
- Validate only with asymptotic analysis and small host fixtures under strict limits; never stress a live or shared device, and keep actuator/timing facts `needs_validation`.

## Validation rules (apply before reporting ANY finding here)

1. Name the untrusted input, the missing bound or unsafe transition, the shared/persistent effect, and the recovery behavior. A missing limit with no concrete shared or unsafe effect is hardening.
2. Classify the effect as transient (reboot) or persistent (brick/wear/stuck actuator); persistence and safety raise severity.
3. For watchdog findings, show that a hung critical task would not trigger a reset given the actual feed sites.
4. Mark `safety_relevant: true` only when source shows the actuator/interlock path and give an impact reason naming the physical effect; otherwise `needs_validation`.
5. Do not validate with availability impact on a live device; use host analysis and bounded fixtures.
6. Return `confirmed` only with a source trace and bounded reasoning/evidence; return `needs_validation` with the exact actuator, timing, or recovery fact an owner must confirm on the bench.
