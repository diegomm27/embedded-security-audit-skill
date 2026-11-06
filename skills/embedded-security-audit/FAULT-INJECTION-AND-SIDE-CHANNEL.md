# Fault Injection and Side Channel Hunting

#### When to use this file

Reach for this file when a security decision runs on hardware an attacker can physically reach and might glitch or measure: secure-boot and debug-unlock decisions, PIN/password checks, key comparisons, and custom crypto. This is a **source-pattern-only** companion: it finds code shapes that are fragile to fault injection or that leak through timing, without any glitching, power measurement, or EM capture. Pair it with `BOOT-CHAIN-AND-SECURE-BOOT.md` (single boot decisions), `HARDWARE-INTERFACES-AND-DEBUG.md` (debug unlock), and `CRYPTO-KEYS-AND-SECURE-STORAGE.md` (constant-time compares). The findings here are mostly `needs_validation` with a bench plan and are severity-capped unless the effect is a pure logic bug.

Split a large target by decision type: boot/debug single-point decisions, authentication compares, and crypto timing.

## Core discipline (include in every agent prompt for this domain)

```
- Hunt code shapes only. Never generate glitch parameters, never measure power/EM, never run on silicon.
- A single compare-and-branch deciding a security outcome is fragile to a single fault; redundancy and hardened constants are the fix.
- A boolean 0/1 success value is easier to force than a hardened multi-bit constant and a double check.
- Most findings here are needs_validation with a bench plan and are capped per the physical-invasive severity rules; a purely logical bug (for example a timing-free logic flaw) can be confirmed.
- Recommend hardened patterns (MCUboot FIH_*, TF-M fih) as the remediation rather than any offensive recipe.
```

## Single-point-decision attack classes (subagent_type: `general`)

**One compare-and-branch deciding a security outcome**
Boot acceptance, debug unlock, or an authentication result hinges on a single `if (verify() == OK)` with no redundant check or flow-integrity counter, so a single instruction-skip or branch fault bypasses it. Grep for lone security branches around `verify`, `authenticate`, `unlock`, and boot transfer. Flag each as a fault-fragile decision; it is `needs_validation` (glitch) with a bench plan, and the fix is a double check plus a hardened constant.

**Boolean success values instead of hardened constants**
Success is represented as `0`/`1` or `true` rather than a hardened multi-bit magic value (for example a `0x3CA5965A`-style constant checked twice), making a forced value trivial. Grep for `bool`/`0`/`1` returns from verification functions. Flag as fault-fragile; recommend hardened status values.

**Missing double checks and flow-integrity counters**
The code lacks a second verification of the same decision and lacks a flow-integrity counter that proves all critical steps ran, so a skipped step goes undetected. Check whether critical sequences increment and later verify a step counter. Absence is a fault-fragility note with a hardened-pattern fix.

**Status variable initialized to success**
A result variable is initialized to the success value and only set to failure on an error path, so a skipped assignment leaves it "success". Grep for `status = OK; ... if (bad) status = FAIL;`. This is both a fault-fragility and sometimes a plain logic bug; if a normal path can leave it success, that is `confirmed`.

## Control-flow-fragility attack classes (subagent_type: `general`)

**Loops whose early exit skips verification**
A verification loop (comparing bytes, iterating key slots) exits early on the first match/mismatch so a fault to the loop counter or exit condition skips remaining checks. Check loop bounds and exit conditions around verification. Flag as fault-fragile; a constant-count, non-short-circuit loop is the fix.

**Default-allow on unexpected switch values**
A `switch` on a security-relevant value has a `default` that allows/continues rather than rejecting, so an unexpected (possibly fault-induced) value takes the permissive path. Grep for `switch` with a permissive `default` in security code. A reachable permissive default is `confirmed` as a logic bug; the fault angle adds fragility.

## Side-channel-pattern attack classes (subagent_type: `general`)

**Non-constant-time comparison of secrets**
A MAC, PIN, password, or key is compared with `memcmp`/`strcmp` or an early-exit loop, leaking match length through timing. Grep for `memcmp(`/`strcmp(` on secrets (shared with `CRYPTO-KEYS-AND-SECURE-STORAGE.md`). The non-constant-time compare is a `confirmed` logic defect; whether the timing is exploitable on the target is `needs_validation` with a bench plan, severity-capped.

**Secret-dependent branches and table lookups**
Branches or memory indexing depend on secret/key bits (table-based AES on a cached core, a branch on a key byte), leaking through timing/cache. Flag these for cores with caches and recommend constant-time/bitsliced code. Timing exploitability is `needs_validation`.

**Key-dependent timing in custom crypto**
A custom cipher/MAC/KDF has execution time that varies with the key, leaking information. Review the custom construction's control flow. The key-dependent timing shape is the observation; exploitability is `needs_validation`.

**Error paths and messages as oracles**
Distinct error codes, messages, or response timing distinguish failure causes (a padding oracle over serial, different errors for "bad MAC" vs "bad length"), giving an attacker an oracle. Grep for differentiated error returns on secret-dependent paths. A clear oracle is `confirmed` as a logic/information defect; timing-only oracles are `needs_validation`.

## Universal moves (apply across the above)

- Map every security decision (boot, debug, auth, key compare) to its code shape: single vs redundant check, boolean vs hardened constant, early-exit vs constant-time, and whether a flow-integrity counter guards the sequence.
- Separate a pure logic bug (reachable without any fault, for example a permissive `default` or a success-initialized status that a normal path leaves unchanged) from a fault/timing fragility. The former can be `confirmed`; the latter is `needs_validation` and capped.
- Recommend concrete hardened patterns (MCUboot `FIH_*`, TF-M `fih`, double checks, hardened constants, constant-time compares) as the fix; never produce glitch parameters or measurement recipes.
- Record the attack vector as `physical_invasive` for glitching and apply the medium cap unless the effect is a fleet-wide secret, documenting the vector in the conditions.
- Keep all validation to source reading; any on-target confirmation is an owner-run bench task.

## Validation rules (apply before reporting ANY finding here)

1. State whether the issue is a pure logic bug (reachable with no fault) or a fault/timing fragility; only the former is eligible for `confirmed` without a bench step.
2. For fault fragilities and timing side channels, use `needs_validation` with an owner-run, bench-only plan; never include glitch parameters or measurement recipes.
3. Set `attack_vector` to `physical_invasive` for glitch-dependent findings and cap severity at medium unless a fleet-wide secret results; record the vector in `conditions`.
4. Recommend hardened patterns as remediation and point to the relevant library macro where one exists.
5. A non-constant-time secret compare and a padding/error oracle are `confirmed` as logic/information defects; their timing exploitability remains `needs_validation`.
6. Return `confirmed` only for a source-visible logic defect with evidence; otherwise return `needs_validation` with the exact bench observation an owner must perform.
