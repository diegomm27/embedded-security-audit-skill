# TrustZone, TEE, and Isolation Hunting

#### When to use this file

Reach for this file whenever the device enforces an isolation boundary in software: ARMv8-M TrustZone (secure/non-secure worlds and NSC veneers), TF-M and PSA secure services, TrustZone-A with OP-TEE or TF-A, MPU-based RTOS userspace (Zephyr userspace, FreeRTOS-MPU), or a partitioning hypervisor. Pair it with `FIRMWARE-MEMORY-SAFETY.md` for the argument-copy bugs at each boundary and with `CRYPTO-KEYS-AND-SECURE-STORAGE.md` for key isolation. This file owns the cross-privilege entry: who may call across the boundary and whether pointers, lengths, and handles are validated before the trusted side acts.

Split a large target by boundary: NSC veneers, PSA/TF-M services, OP-TEE/TF-A, MPU userspace syscalls, and hypervisor channels.

## Core discipline (include in every agent prompt for this domain)

```
- At every cross-privilege entry, enumerate every pointer and length argument and verify the trusted side validates provenance and range before use, every time.
- The lower-trust caller controls its memory after a check. Guard against double-fetch: copy once into trusted memory, then validate and use that copy.
- Never return a secure pointer, secure-memory contents, or uninitialized trusted stack/registers to the non-secure side.
- Isolation level and region configuration (SAU/IDAU/MPC/PPC, MPU regions, partition isolation level) decide what the boundary actually protects; a check is only as strong as the regions behind it.
- Validate argument-handling logic in source and emulation. Facts that depend on silicon SAU/MPC wiring or fuse state are `needs_validation`.
```

## TrustZone-M (ARMv8-M) attack classes (subagent_type: `general`)

**NSC veneer argument validation**
A non-secure-callable entry (`__attribute__((cmse_nonsecure_entry))`) receives pointers and lengths from the non-secure world and uses them without `cmse_check_address_range`/`cmse_check_pointed_object`, so the secure side reads or writes non-secure-controlled or secure memory on the attacker's behalf. Grep for `cmse_nonsecure_entry` veneers and check each pointer argument is validated with the CMSE intrinsics for the right access (read/write) and length. A missing or wrong check is `confirmed` (non-secure to secure escalation).

**Double-fetch of non-secure memory**
The veneer validates a value in non-secure memory, then reads it again (or reads a length then the data) from the same mutable address, letting the non-secure side change it between fetches. Look for two reads of the same NS pointer, or validate-then-use without copying into secure memory first. A double-fetch that defeats the check is `confirmed`.

**Returning secure data or pointers to the non-secure side**
A veneer returns a pointer into secure memory, copies secure data into an NS buffer without need, or leaks secure state. Check return values and output buffers of every veneer. A secure-pointer or secure-data leak is `confirmed` (information disclosure, possibly enabling more).

**SAU/IDAU/MPC/PPC misconfiguration**
The security attribution (SAU/IDAU) or memory/peripheral protection controllers (MPC/PPC) leave secure RAM, flash, or peripherals reachable from the non-secure world, or mark regions wrongly. Review the attribution setup code and compare it with what must be secure. A source-visible misconfiguration is `confirmed`; one that depends on silicon IDAU wiring not in source is `needs_validation`.

**Register/FPU state leak on world switch**
Secure register or FPU state is not cleared on return to non-secure, leaking secrets, especially with lazy FP stacking or preemptible secure calls (`CONFIG_ARM_NONSECURE_PREEMPTIBLE_SECURE_CALLS`). Check the secure-exit path clears caller-saved and FP registers. A leak is `confirmed`; exploitability may need a bench confirmation.

## TF-M and PSA-service attack classes (subagent_type: `general`)

**Partition isolation level**
TF-M runs at isolation level 1, 2, or 3; a lower level than the product requires leaves secure partitions mutually reachable or reachable from the SPM. Check the configured isolation level against the threat model. An inadequate level is a weakness; concrete cross-partition impact may be `needs_validation`.

**PSA client-call parameter validation**
A secure service reads client input with `psa_read`/`psa_write`/`psa_skip` using lengths or offsets it does not bound against the actual invec/outvec sizes, or trusts a client-supplied length. Check each service's parameter handling against the declared vector sizes. An unbounded read/write of client or secure memory is `confirmed`.

**Handle confusion and key-owner checks**
A service confuses handles across clients, or the crypto service does not verify the calling partition owns the key it operates on, so one client uses another's key or handle. Check handle-to-client binding and key ownership checks in crypto/storage services. A cross-client handle or key use is `confirmed`.

## TrustZone-A, OP-TEE, and TF-A attack classes (subagent_type: `general`)

**TA command parameter-type validation**
An OP-TEE trusted application does not check `TEE_PARAM_TYPES` against what it uses, so a client passes a value where a memref is expected (or vice versa), causing type confusion or unvalidated memory access. Check each TA command entry validates param types before using `params[i].memref`. Missing param-type checks are `confirmed`.

**Shared-memory TOCTOU in a TA**
A TA validates data in client-shared (REE) memory, then uses it, while the normal world can modify it concurrently; the TA must copy into secure memory before validating. Look for validation of `memref.buffer` followed by use without a copy. A TOCTOU is `confirmed`.

**SMC handler argument validation in TF-A/BL31**
A platform SMC handler in BL31 trusts register arguments (addresses, sizes) from the normal world without range-checking against allowed memory, letting EL3 act on attacker-chosen addresses. Review platform SMC dispatch and argument checks. An unchecked address/size in an SMC handler is `confirmed`.

**TA-to-TA isolation and REE-FS rollback**
One TA can reach another's memory or session, or secure storage backed by the REE filesystem is not rollback-protected (RPMB not used), so the normal world rolls back TA state. Check TA isolation configuration and whether RPMB/anti-rollback protects secure storage. Weaknesses here are `confirmed` for the stated boundary; rollback impact may be `needs_validation`.

## MPU-based RTOS isolation attack classes (subagent_type: `general`)

**Zephyr userspace syscall verification**
A kernel syscall handler reaches user-supplied pointers without `K_SYSCALL_MEMORY_READ/WRITE`/`Z_SYSCALL_MEMORY_*` or object checks (`K_SYSCALL_OBJ`), so a user thread drives kernel access to arbitrary memory. Grep for syscall handlers and verify each validates user pointers and kernel-object permissions. A missing verifier is `confirmed`.

**FreeRTOS-MPU privilege raising**
Code uses `portRAISE_PRIVILEGE`/`xPortRaisePrivilege` or places data in privileged regions so that an unprivileged task can reach privileged memory or escalate. Check region definitions and privilege-raising call sites. An unprivileged task that can escalate is `confirmed`.

**Kernel-object permission gaps**
MPU userspace grants a thread access to kernel objects (queues, semaphores, drivers) beyond its need, or a region is writable that should not be. Compare granted object permissions with required ones. A reachable over-grant that crosses the task boundary is `confirmed`.

## Hypervisor and partitioning attack classes (subagent_type: `general`)

**Static-partitioning and shared-channel configuration**
Jailhouse/Xen/ACRN or a static partitioning hypervisor configures overlapping memory, a cell with excess device access, or a shared-memory channel between cells that one side can abuse. Review the cell/partition config and inter-cell channels. A misconfiguration that breaks isolation is `confirmed`; hardware-dependent facts are `needs_validation`.

## Universal moves (apply across the above)

- List every cross-privilege entry and, for each, tabulate its pointer/length/handle arguments, the validation applied, and whether a copy-before-validate prevents double-fetch.
- Check the region/attribution configuration (SAU/IDAU/MPC/PPC, MPU, isolation level) that stands behind each check; a perfect check over a misconfigured region still fails.
- Trace return paths and output buffers for secure-pointer, secure-data, and register/FPU leaks to the lower-trust side.
- Validate argument-handling logic with host/emulator harnesses; keep silicon attribution and fuse facts as `needs_validation` with a bench plan.
- Confirm ownership (key-owner, handle-to-client, TA isolation) wherever the trusted side acts on a resource selected by the caller.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust caller (non-secure world, user thread, REE client, peer cell) and the exact pointer, length, handle, or region check that is missing or wrong.
2. Distinguish a source-visible validation gap (`confirmed`) from a configuration fact that needs silicon confirmation (`needs_validation`, vector recorded).
3. For double-fetch and TOCTOU, show the two reads or the validate-then-mutate window; a single validated copy is not a finding.
4. For leaks, show the secure pointer, data, or register state crossing to the lower-trust side.
5. Treat isolation level and region configuration as the backdrop for severity; an inadequate level with no reachable concrete effect is a weakness, not a confirmed cross-boundary finding.
6. Return `confirmed` only with a source trace and bounded evidence; return `needs_validation` with the exact SAU/MPC/MPU/fuse fact an owner must confirm.
