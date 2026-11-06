# RTOS and Kernel Hunting

#### When to use this file

Reach for this file when the target runs an RTOS (FreeRTOS, Zephyr, ThreadX/Azure RTOS, NuttX, RIOT, Mbed OS, embOS) or an embedded Linux kernel with custom drivers, and untrusted input reaches kernel objects, syscalls, shells, logging, the network stack configuration, a filesystem, or a device driver. Pair it with `TRUSTZONE-TEE-AND-ISOLATION.md` for the privilege boundary of syscalls, `FIRMWARE-MEMORY-SAFETY.md` for the copies themselves, and `EMBEDDED-LINUX-AND-USERSPACE.md` for userspace services. This file owns RTOS-object trust, kernel-driver copies, and the subsystems (shell, logging, networking, filesystem) that attackers reach through the kernel.

Split a large target into RTOS objects/scheduling, shells and logging, network-stack configuration, filesystem/path handling, and Linux kernel drivers.

## Core discipline (include in every agent prompt for this domain)

```
- Treat message-queue sizes, event payload lengths, and driver ioctl sizes as attacker-controlled; validate them against the receiving buffer, not the sender's claim.
- Know the callback context: timer, work-queue, and ISR callbacks run with different locking and reentrancy rules than threads.
- Production builds must not expose a debug shell or raw-memory commands; check the shipped config, not the sample.
- For Linux drivers, every `copy_from_user`/`copy_to_user`, `ioctl`, `mmap`, and sysfs/debugfs write is a user-to-kernel boundary; validate sizes and ranges there.
- Validate in host/emulator/native-sim builds; on-target kernel behavior that is not source-visible is `needs_validation`.
```

## RTOS objects and scheduling attack classes (subagent_type: `general`)

**Message-queue and event payload size trust**
Code reads a length or count from a queued message or event and uses it to copy, index, or allocate without checking against the actual payload or destination buffer. Grep for `xQueueReceive`/`k_msgq_get`/`k_fifo_get` consumers that trust an embedded length, and event payloads parsed by size. An out-of-bounds driven by a queued size is `confirmed` with a host harness.

**Timer and work-queue callback context errors**
A timer or work-queue callback touches state or calls APIs that are unsafe in its context (ISR vs thread), or shares data with a thread without synchronization, producing a race on a security-relevant flag or pointer. Identify callback registration and what each callback touches. A reachable race on a security decision is `confirmed`; a timing-only hypothesis is `needs_validation`.

**Task priority and privilege gaps**
A lower-priority or unprivileged task can block, starve, or reach resources of a higher-trust task, or a task runs more privileged than it needs. Compare task privilege/priority with its function. A cross-task reach or escalation is `confirmed`; priority-inversion availability is covered in `SAFETY-AND-AVAILABILITY.md`.

## Shell, logging, and assert attack classes (subagent_type: `general`)

**Debug shells exposed in production**
The Zephyr shell, FreeRTOS+CLI, or a custom command interpreter is enabled in the release build and reachable over UART/USB/BLE/network, exposing memory, flash, or config commands. Grep for `CONFIG_SHELL`, shell command registrations, and CLI handlers, and check the release config. A production-reachable shell with dangerous commands is `confirmed`.

**Format-string bugs in custom printf/logging**
Untrusted strings reach a `printf`-family function as the format argument, or a custom logger interprets `%` in attacker data, leaking memory or corrupting state on implementations that support `%n`. Grep for `printf(buf)`, `LOG_*(var)` where `var` is attacker-controlled, and custom format parsers. A reachable format-string bug is `confirmed`.

**Assert and fault handlers that leak or continue**
An assert handler prints secrets/addresses over a console, or a fault/error handler continues execution in an inconsistent state instead of halting. Check `assert`, fault handlers, and error hooks for disclosure or fail-open behavior. Disclosure to a reachable console or a fail-open continuation is `confirmed` (or `needs_validation` if the console's production availability is unknown).

## Network-stack configuration attack classes (subagent_type: `general`)

**Stack limits and reassembly configuration**
The IP stack (lwIP, Zephyr net) is configured with weak limits or risky features: small `MEMP_*` pools exhausted by attacker packets, IP fragmentation reassembly (`IP_REASSEMBLY`/`LWIP_IPV4` reassembly) enabled with known overflow risk, or missing per-connection caps. Check the stack config and reassembly code paths. A reachable reassembly overflow is `confirmed`; resource limits feed `SAFETY-AND-AVAILABILITY.md`.

**Raw socket and management-frame handlers**
Handlers for raw frames, ICMP, DHCP, or management packets parse untrusted input in the stack; apply memory-safety discipline and check they run with the right privilege. A parser bug is `confirmed`; reachability depending on the stack build is `needs_validation`.

## Filesystem and path attack classes (subagent_type: `general`)

**Untrusted filename/path handling (FatFS/LittleFS)**
A filename or path from the network, a config file, or an update reaches FatFS/LittleFS open/read/write without normalization, allowing traversal (`..`), overwrite of config/keys, or reads outside an intended directory. Grep for `f_open`/`fs_open` with attacker-derived names. A reachable traversal or arbitrary-path write is `confirmed`.

**Filesystem metadata and image parsing**
Mounting or parsing an attacker-supplied filesystem image (SD card, external flash) trusts metadata sizes/offsets. Apply memory-safety discipline to the FS parser. A parser bug on a mountable image is `confirmed`, with the physical/removable vector recorded if media access is needed.

## Linux kernel-driver attack classes (subagent_type: `general`)

**`copy_from_user`/`copy_to_user` size and direction**
A driver `ioctl` or read/write handler uses a user-supplied size without bounding it, copies the wrong direction, or dereferences a user pointer directly, giving a user-to-kernel overflow or disclosure. Grep for `copy_from_user`, `copy_to_user`, `get_user`, `__user`, and `ioctl` switch handlers; check size bounds and `access_ok`. An unbounded or wrong-direction copy is `confirmed`.

**`mmap` of device memory to userspace**
A driver `mmap` maps more physical/device memory than intended, or maps registers that let userspace reach privileged hardware, bypassing the kernel boundary. Check the `mmap` handler's range and offset validation. An over-broad mapping is `confirmed`.

**sysfs/debugfs write handlers and device-tree-controlled sizes**
A sysfs/debugfs store handler parses untrusted input without bounds, or a buffer size comes from a device-tree property that an attacker-controlled DTB could set. Check store-handler parsing and DT-derived sizes. A reachable overflow or an unbounded DT-controlled size is `confirmed`; DTB reachability may be `needs_validation`.

## Universal moves (apply across the above)

- For each kernel/RTOS entry, record the caller's trust, the arguments it controls (sizes, pointers, names, handles), and the validation applied before the kernel acts.
- Check the shipped configuration for shells, logging verbosity, and network features; a dangerous subsystem compiled out in release is not a finding.
- Apply memory-safety discipline to every kernel-side parser and copy; the kernel boundary raises severity because the effect reaches privileged memory.
- Distinguish a reachable race on a security decision (worth confirming with a schedule) from a timing hypothesis (`needs_validation`).
- Where on-target kernel behavior, a specific driver build, or DTB content is not source-visible, stop at `needs_validation` with the exact fact.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust caller (remote peer, unprivileged task, userspace process) and the exact kernel/RTOS invariant (size, pointer, path, context, privilege) that fails.
2. For driver copies, prove the size/range/direction gap at the `copy_*`/`ioctl`/`mmap` boundary; a bounded copy is not a finding.
3. Confirm shells, logging, and risky stack features from the release configuration, not a sample config.
4. Reproduce parser and copy bugs in host/native-sim/emulator builds; reaching a specific driver, stack, or DTB state not in source is `needs_validation`.
5. Treat callback-context races as `confirmed` only with a deterministic schedule; otherwise `needs_validation`.
6. Return `confirmed` only with a source trace and bounded evidence; return `needs_validation` with the exact on-target kernel, driver, or config fact an owner must confirm.
