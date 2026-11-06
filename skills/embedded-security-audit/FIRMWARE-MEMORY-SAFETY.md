# Firmware Memory Safety Hunting

#### When to use this file

Reach for this file whenever the target is C or C++ firmware that processes untrusted bytes: radio and bus parsers, HAL/BSP code, network buffers, DMA paths, packed protocol structs, and ring buffers on an MCU without an MMU. It is the default companion for any C/C++ embedded target and pairs with `BOOT-CHAIN-AND-SECURE-BOOT.md` for loader parsers, `TRUSTZONE-TEE-AND-ISOLATION.md` for privileged-entry argument validation, and `RTOS-AND-KERNEL.md` for kernel-object and driver copies. Use this file for bounds, integer, lifetime, concurrency, and MMIO memory-integrity defects; use the boot/TEE files for the authority decisions those bugs reach.

Split a large target by parser, allocator/lifetime, ISR/concurrency, peripheral/DMA, and architecture (endianness/alignment) so each hunter owns one memory discipline.

## Core discipline (include in every agent prompt for this domain)

```
- Re-derive every bound and lifetime from the attacker-controlled input and all callers. Validate against the worst accepted length from the wire, never from the struct definition or a typical test vector.
- A crash, HardFault, or sanitizer finding proves a defect only when a realistic untrusted input reaches it. Do not infer code execution or a stronger write from a read, or from a label alone.
- Validate only in a host build or an installed emulator (QEMU/Renode/Unicorn) with sanitizers and bounded fuzzing. Never flash, debug-attach, or run on target silicon.
- Account for the target: 8/16/32-bit integer widths, endianness, alignment faults on Cortex-M0, no guard pages, and a fixed memory map. A bug on a 64-bit host may not exist on the MCU, and vice versa.
- Classify as `confirmed` only after source evidence and a bounded host/emulator check establish the defect and its observable effect. Use `needs_validation` when alignment, endianness, allocator, DMA timing, or on-target reachability is unknown.
```

## Bounds and integer attack classes (subagent_type: `general`)

**Wire length copied into a fixed buffer**
A length, count, or offset taken from a radio frame, bus message, USB transfer, or file reaches a `memcpy`, `memmove`, loop, or array index without a correct bound against the destination capacity. Grep for `memcpy(`, `memmove(`, `strncpy`, and manual copy loops near `->len`, `->length`, `hdr->`, and recompute available headroom after headers, padding, and terminators. Confirm by feeding a host build of the parser an input whose declared length exceeds the buffer; do not escalate the observed read past what the harness shows.

**TLV/LTV nested length underflow**
Type-length-value and length-tag-value parsers subtract a header size or inner length from an outer length without checking that the outer value is large enough, producing a huge unsigned remainder used as the next copy size. Look for `remaining -= field_len`, `len - sizeof(hdr)`, and nested `while (offset < total)` loops where an inner length is trusted. These are high-value because they recur across every TLV field; establish each field's effect independently.

**16-bit length truncation and small-integer loop counters**
On 8/16-bit MCUs (AVR, MSP430, some Cortex-M0 code), a 32-bit wire length assigned to a `uint16_t` or an index compared with a `uint8_t`/`uint16_t` counter truncates or wraps, so a bound that looks correct passes a shortened value. Grep for `uint8_t`/`uint16_t` loop variables, `(uint16_t)len`, and size fields narrower than the value they carry. A wrap that lets the copy or index exceed the buffer is `confirmed`; one whose reachability depends on the target integer width is `needs_validation`.

**Ring-buffer head/tail off-by-one and packed-struct overcast**
Circular buffers for UART/DMA/network data mishandle the full/empty distinction or wrap arithmetic, and a handler casts a received byte stream to a packed `struct` without checking that enough bytes arrived. Check `head`/`tail` updates, `% size` versus `& (size-1)`, and every `(struct foo *)buf` cast against the actual received length. Also check `sizeof(pointer)` used where `sizeof(array)` was intended, a classic on `memset`/`memcpy` of a passed-in buffer.

## Stack and memory-layout attack classes (subagent_type: `general`)

**Stack overflow without a guard page**
Deep parser recursion, a large local array, or a VLA/`alloca` sized from input overflows a small task stack into `.bss`, the heap, or an adjacent task's stack, because MCUs have no guard page by default. Check for recursion in parsers, `char buf[LARGE]` locals, and `alloca`/VLA on input-derived sizes, then see whether an MPU stack guard or runtime check exists (`configCHECK_FOR_STACK_OVERFLOW`, Zephyr `CONFIG_HW_STACK_PROTECTION`, `CONFIG_MPU_STACK_GUARD`). Absence of a guard is context that raises severity, not a finding by itself; the reachable overflow is the finding.

**Executable RAM/flash and a fixed memory map**
When the MPU does not mark RAM execute-never (no XN region) or the map is fully fixed and known, a memory-corruption bug is far easier to exploit. State this in the severity reasoning, but do not report "RAM is executable" or "no ASLR" as a standalone finding without a reachable corruption primitive. Grep MPU region setup for XN/`MPU_RASR` attributes and linker scripts for RWX segments.

**Missing or misconfigured MPU regions**
Task or driver code runs with an MPU region that is broader than intended, leaving peripheral or kernel memory writable from a lower-trust context. Compare the configured regions with the data each task should reach. Confirm a reachable cross-region write in an emulator where possible; a claim that depends on the production MPU configuration not in source is `needs_validation`.

## Heap and lifetime attack classes (subagent_type: `general`)

**Unchecked allocation failure and fragmentation**
`pvPortMalloc`, `malloc`, `k_malloc`, or a pool alloc returns NULL under fragmentation (FreeRTOS `heap_1`–`heap_5` differ) and the caller dereferences it, or a fixed pool is exhausted by attacker-paced requests. Grep for allocations whose return value is used without a NULL check, especially on network/receive paths. A NULL deref reachable from the wire is `confirmed`; fragmentation that needs a specific heap scheme is `needs_validation`.

**Use-after-free of network and driver buffers**
Reference-counted buffers (lwIP `pbuf`, Zephyr `net_buf`) are freed on one path while another path, a retry, or a timer still holds a pointer; or a static buffer is reused across connections. Check every `pbuf_free`/`net_buf_unref` and error/cancel path for a surviving reference or iterator. Reproduce the stale access in a host build with ASan where the stack is portable; otherwise `needs_validation`.

**Double free on error paths**
An error or teardown path frees a buffer that a later cleanup also frees, corrupting the allocator. Diff the success and every error path for balanced alloc/free, especially goto-based cleanup ladders. Confirm with ASan on a host build; keep allocator-specific corruption claims bounded to what is observed.

## Concurrency, interrupt, and MMIO attack classes (subagent_type: `general`)

**ISR/thread shared state without a critical section**
State touched by both an ISR and thread context lacks a critical section or atomic access, so an interrupt mid-update leaves a parser bound, pointer, or flag inconsistent. Identify variables written in ISRs (`__attribute__((interrupt))`, vector-table handlers) and read/written in threads, and check for `taskENTER_CRITICAL`, `irq_lock`, or atomics. Also flag non-reentrant functions (static buffers, `strtok`) called from an ISR. Priority inversion that delays a security check is in scope.

**DMA/CPU TOCTOU and cache coherency**
A DMA engine writes into a buffer that the CPU is simultaneously parsing, or the CPU reads a DMA buffer stale on a Cortex-M7/A with a data cache, so a validated length or pointer changes under the parser (double-fetch of DMA memory). Look for DMA receive buffers parsed before transfer-complete, missing cache maintenance (`SCB_InvalidateDCache_by_Addr`), and `volatile` omissions on hardware-updated memory. These are often `needs_validation` because the race depends on DMA timing; a clear double-fetch of attacker-DMA'd memory is `confirmed`.

**Untrusted peripheral/MMIO values used as indices or lengths**
A value read from a sensor, external device, or MMIO register (over SPI/I2C) is trusted as an array index, length, or state selector without range checking, so a replaced or spoofed peripheral drives out-of-bounds access. Grep for SPI/I2C reads feeding `buf[reg]`, `len = resp[0]`, and DMA descriptor addresses sourced from untrusted memory, plus USB descriptor parsing in a host stack. Confirm the missing range check in source; spoofability of the physical bus is `needs_validation` with a bench note.

## Unaligned access and endianness attack classes (subagent_type: `general`)

**Unaligned access faults on strict-alignment cores**
Casting a byte buffer to a wider type and dereferencing it faults on Cortex-M0/M0+ and some RISC-V cores that disallow unaligned access, turning a parser into a reachable HardFault (denial of service) or, with fault handling that continues, worse. Grep for `(uint32_t *)buf`, `*(uint16_t*)(p+off)`, and packed-to-unpacked copies. A reachable fault from the wire is `confirmed` as availability; classify the effect, do not overstate it.

**Host/target endianness mismatch in protocol parsing**
Code assumes host byte order when parsing a wire format with a fixed endianness, or omits `ntohs`/`sys_be16_to_cpu`/`__builtin_bswap`, so lengths and offsets are interpreted wrong on the target. Compare each multi-byte field's declared wire endianness with how it is read. A misparse that enables an out-of-bounds access on the target byte order is `confirmed`; a benign value difference is not a finding. Also check bitfield layout assumptions, which are implementation-defined across compilers.

## Universal moves (apply across the above)

- Build a table for every parser and copy: accepted wire length, the checked representation, the destination capacity, the integer width used, the execution context (ISR/thread), and the consumer. Most firmware memory bugs are one disagreement in that table.
- Follow the fix and every sibling: a bound added in one radio role, one command handler, or one architecture-specific path does not protect the others.
- Prefer existing unit tests, a minimal function harness compiled for the host, and small malformed fixtures with ASan/UBSan. Record the exact input property that triggers the effect and the architecture/build assumptions.
- Separate a safely rejected malformed input from an actual corruption. A parser that returns an error on a bad length is working; the finding is the path that does not.
- When the decisive fact is alignment, endianness, DMA timing, cache behavior, or the production MPU/stack-guard configuration, stop at `needs_validation` with a precise bench or emulator plan.

## Validation rules (apply before reporting ANY finding here)

1. Establish a realistic untrusted entry (radio, bus, USB, file, sensor) and the exact operation that violates a bounds, integer, lifetime, concurrency, or representation invariant.
2. Classify the observable effect precisely: invalid read, invalid write, stale pointer, NULL deref, HardFault/DoS, or safe rejection. Never claim code execution or a write from a read without harness evidence.
3. Reproduce in the narrowest host or emulator harness with sanitizers; verify the sanitizer instruments the faulting operation and record the target architecture and build flags.
4. For concurrency and DMA, use a deterministic schedule or state that the race is `needs_validation` with the timing assumption named. For MMIO/peripheral trust, prove the missing range check in source and name the physical attacker for the bus.
5. A missing stack canary, absent XN, or fixed map is severity context, not a standalone finding. Report it only attached to a reachable corruption.
6. Return `confirmed` only with the exact input, source trace, and observed effect. Return `needs_validation` for a specific unresolved alignment, endianness, allocator, DMA, or on-target reachability fact with the bounded check that resolves it.
