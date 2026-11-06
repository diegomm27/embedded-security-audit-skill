# Attack Classes

#### Attack classes — choose and split based on Phase 1

Select attack classes relevant to the device type. Not every class applies to every target. The list below is a starting point; add device-specific classes from Phase 1 and split large targets per subsystem (bootloader, radio stack, application, Linux userspace, drivers). Frame work as finding, validating, fixing, and prioritizing vulnerabilities. Keep validation to source review and bounded host/emulator fixtures; never flash, drive a bus, transmit RF, or touch hardware.

Use `confirmed` only when source evidence and bounded local validation establish the full boundary and meaningful result. Use `needs_validation` when a specific hardware, fuse/lock-state, provisioning, radio, or runtime fact is unavailable; state the missing fact and the safe owner-observed bench or local check that resolves it.

> **Firmware memory safety** (any C/C++ MCU or firmware target: parsers, HAL/BSP, network buffers, DMA, packed structs): use [FIRMWARE-MEMORY-SAFETY.md](FIRMWARE-MEMORY-SAFETY.md).
>
> **Boot chain and secure boot** (ROM/BL1/BL2 stages, MCUboot, U-Boot, image verification, anti-rollback, DFU/recovery): use [BOOT-CHAIN-AND-SECURE-BOOT.md](BOOT-CHAIN-AND-SECURE-BOOT.md).
>
> **Firmware update and OTA** (signature/manifest verification on-device, SUIT/Uptane, A/B slots, SMP/mcumgr, delta patches): use [FIRMWARE-UPDATE-AND-OTA.md](FIRMWARE-UPDATE-AND-OTA.md).
>
> **Crypto, keys, and secure storage** (key material, RNG/entropy, primitive misuse, constant-time compares, flash encryption, secure elements): use [CRYPTO-KEYS-AND-SECURE-STORAGE.md](CRYPTO-KEYS-AND-SECURE-STORAGE.md).
>
> **TrustZone, TEE, and isolation** (ARMv8-M NSC veneers, TF-M/PSA, OP-TEE/TF-A, MPU-based RTOS userspace, hypervisors): use [TRUSTZONE-TEE-AND-ISOLATION.md](TRUSTZONE-TEE-AND-ISOLATION.md).
>
> **RTOS and kernel** (RTOS syscalls and objects, shells, logging, network stack config, filesystems, Linux kernel drivers): use [RTOS-AND-KERNEL.md](RTOS-AND-KERNEL.md).
>
> **Embedded Linux and userspace** (CGI/management UI, daemons, rootfs privilege, config import, hardening baseline): use [EMBEDDED-LINUX-AND-USERSPACE.md](EMBEDDED-LINUX-AND-USERSPACE.md).
>
> **Hardware interfaces and debug** (JTAG/SWD lock, UART consoles, test/factory modes, external memories, bus trust): use [HARDWARE-INTERFACES-AND-DEBUG.md](HARDWARE-INTERFACES-AND-DEBUG.md).
>
> **Wireless and radio protocols** (BLE, Wi-Fi provisioning, 802.15.4/Zigbee/Thread/Matter, LoRaWAN/sub-GHz, cellular/NFC): use [WIRELESS-AND-RADIO-PROTOCOLS.md](WIRELESS-AND-RADIO-PROTOCOLS.md).
>
> **Fieldbus, automotive, and ICS** (UDS/CAN, ISO-TP, SecOC, Modbus/PROFINET/CIP/BACnet/DNP3/OPC UA, PLC): use [FIELDBUS-AUTOMOTIVE-AND-ICS.md](FIELDBUS-AUTOMOTIVE-AND-ICS.md).
>
> **Device protocols and cloud link** (MQTT/CoAP/LwM2M/HTTP clients, device shadow/twin, companion-app LAN APIs, replay): use [DEVICE-PROTOCOLS-AND-CLOUD-LINK.md](DEVICE-PROTOCOLS-AND-CLOUD-LINK.md).
>
> **Fault injection and side channel** (source-pattern-only: single-point decisions, non-constant-time compares, secret-dependent branches): use [FAULT-INJECTION-AND-SIDE-CHANNEL.md](FAULT-INJECTION-AND-SIDE-CHANNEL.md).
>
> **Device lifecycle and provisioning** (manufacturing/provisioning, PSA lifecycle, factory reset, claiming, end of life): use [DEVICE-LIFECYCLE-AND-PROVISIONING.md](DEVICE-LIFECYCLE-AND-PROVISIONING.md).
>
> **Safety and availability** (unbounded allocation, watchdog handling, flash wear, bricking, fail-open error paths, actuators): use [SAFETY-AND-AVAILABILITY.md](SAFETY-AND-AVAILABILITY.md).
>
> **Toolchain, SDK, and supply chain** (vendored SDK/HAL versions, binary blobs, unpinned fetches, signing keys in CI, build configs): use [TOOLCHAIN-SDK-AND-SUPPLY-CHAIN.md](TOOLCHAIN-SDK-AND-SUPPLY-CHAIN.md).
>
> **Firmware image only** (no source tree, just a binary image): use [FIRMWARE-IMAGE-ANALYSIS.md](FIRMWARE-IMAGE-ANALYSIS.md).

**Unauthenticated pre-pairing and pre-auth parsers** (subagent_type: `general`)
The highest-value surface is any code that parses attacker-controlled bytes before authentication or pairing completes: BLE ATT/SMP/L2CAP handlers reachable before bonding, Wi-Fi management/EAPOL frames, a DHCP/mDNS/CoAP/MQTT handler that runs before any identity check, a UDS request accepted outside a session, and a USB descriptor parser in the device/host stack. Enumerate which handlers run before the gate, then trace each length, offset, and type field to its sink. A parser bug here is remote or adjacent and usually `confirmed` once a host fixture reproduces the out-of-bounds or logic effect; reachability that depends on an unseen radio/stack config is `needs_validation`.

**Length fields from the wire to `memcpy`** (subagent_type: `general`)
Trace every length, count, and offset that originates off-device (radio frame, bus message, file, USB transfer, sensor response) to every copy, loop bound, index, and allocation. Size the worst case from the wire, not from the struct definition. High-hit shapes: `memcpy(dst, src, hdr->len)` into a fixed buffer, 16-bit lengths truncated on 8/16-bit MCUs, `uint8_t` loop counters, TLV/LTV nested length underflow, and a packed-struct cast over a short packet. Confirm with a host build of the parser plus a boundary fixture; do not strengthen a read into a write or into code execution beyond what the harness shows.

**Secure-boot verification logic** (subagent_type: `general`)
Review the bootloader's decision to accept or reject the next stage: return-value confusion (`0` = success vs `1`), an error path that still boots, a key/hash comparison with a `memcmp` length bug, acceptance of an unprovisioned or all-`0xFF` key slot, algorithm downgrade, and a header/TLV parser that runs before the signature is checked. Compare the verified region against the executed region (header-declared size vs actual load, XIP-after-verify TOCTOU). A logic bug visible in source is `confirmed`; a single-point check whose bypass needs glitching is `needs_validation` and capped per the severity rules.

**Update authenticity and rollback** (subagent_type: `general`)
Verify the device itself authenticates the full image and manifest (not only the server or companion app), that version comparison cannot be downgraded to a signed-but-vulnerable build, and that an anti-rollback counter is enforced and stored in monotonic storage, not rewritable flash. Grep for the signature call and check what it covers, and for A/B confirm/revert logic (`boot_set_confirmed`). TLS-only "authenticity" without image signing is a `confirmed` design defect; a freeze or timestamp-role weakness that depends on server behavior is `needs_validation`.

**Privileged-entry pointer and length validation** (subagent_type: `general`)
For every boundary where a lower-privilege caller invokes higher-privilege code — NSC veneer, SVC/syscall handler, TEE TA command, Linux `ioctl`, driver `copy_from_user` — enumerate each pointer and length argument and verify provenance and range checks (`cmse_check_address_range`, `Z_SYSCALL_MEMORY_*`, `copy_from_user` sizes, `TEE_PARAM_TYPES`). Watch for double-fetch of caller memory and for returning secure pointers to the non-secure side. A missing or wrong check with a host/emulator reproduction is `confirmed`; one that needs a specific MPU/SAU configuration not in source is `needs_validation`.

**Hardcoded and shared credentials** (subagent_type: `general`)
Find keys, certificates, PSKs, passwords, and API tokens committed in source, headers, build output, or provisioning scripts, and determine whether they are per-device or fleet-shared. A fleet-shared symmetric key, a committed signing private key, or a shared cloud credential is `critical`/`high`. Record that the secret exists and where, never its value. A key that is clearly a dev/test placeholder used only by a test target is `informational` unless a release path consumes it.

**Debug, test, and factory backdoors in production builds** (subagent_type: `general`)
Look for functionality that bypasses authentication when a compile flag, magic packet, button combination, UART command, or GPIO strap is present: `#ifdef DEBUG` around an auth check, a hidden vendor USB request, a manufacturing-test command handler, a magic unlock constant. Determine whether the release build actually compiles it in (check the release defconfig/prj_release.conf, not just the default). A backdoor reachable in the release configuration is `confirmed`; one gated behind a flag you cannot prove is set in production is `needs_validation`.

**Management and web interfaces on embedded Linux** (subagent_type: `general`)
For CGI binaries and daemons, trace request parameters into `system()`, `popen()`, `exec*`, and shell scripts for command injection; into file paths for traversal; and check auth bypass via path normalization in the web-server config (lighttpd/uhttpd/boa/goahead/mini_httpd). Grep for `system(`, `popen(`, `/cgi-bin/`, and unauthenticated endpoint allowlists. Command injection reachable without auth is `confirmed` with a host reproduction; a config-dependent auth bypass may be `needs_validation`.

**Crypto misuse** (subagent_type: `general`)
Hunt static IV/nonce, ECB mode, CBC without a MAC, a non-constant-time MAC/PIN compare (`memcmp` on a tag), a weak or time-seeded RNG for security values, nonce reuse in AES-GCM/CCM/ChaCha20-Poly1305 (counter reset on reboot), and disabled certificate verification (`MBEDTLS_SSL_VERIFY_NONE`, `SSL_VERIFY_NONE`). A source-visible primitive misuse is `confirmed`; a timing side channel that depends on cache/core behavior on the target is `needs_validation`.

**Unsafe defaults** (subagent_type: `general`)
Find open Telnet/SSH with default credentials, services bound to `0.0.0.0`, default passwords that are not forced to change, permissive CORS on a device admin API, and an open debug console. These are `confirmed` only when a real control is defeated or an attacker action follows; a hardening gap with no reachable boundary violation is a hardening note, not a finding.

**Watchdog, brownout, and fail-open error handling** (subagent_type: `general`)
Review error and fault paths for fail-open behavior: a verification failure that continues, a watchdog disabled or fed from the idle loop regardless of task health, a brownout/reset handler that re-enables an actuator, and a default-allow branch on an unexpected value. A fail-open path that leaves a safety interlock skipped or an actuator energized is high-impact and may be `safety_relevant`; show the actuator path in source or mark it `needs_validation`.

**Wildcard** (subagent_type: `general`)
You are not given a category. Find vulnerabilities outside the standard classes already assigned, while keeping the same concrete boundary and validation requirements.

- What is the strangest code in the firmware? Vendor glue, errata workarounds, and half-finished features get the least review.
- What happens if you use an interface in a way the companion app never would? The app constrains users; the GATT table, UDS stack, or serial protocol does not.
- Are there hidden or undocumented commands, AT commands, vendor USB requests, or UART menus? Look at command tables and dispatch switches.
- What does the code assume about the environment: that the clock is set, that the external flash is authentic, that a sensor is honest, that DMA finished, that the bootloader already validated this?
- What is in the git history: reverted security fixes, commented-out verification, keys committed then removed?
- Which valid-user actions affect other users, shared safety, availability, or an actuator? Check gating, quotas, and recovery around them.

Pursue anomalies inside your assigned scope until the invariant is settled. If a comment says a check is safe, verify it. If a variable is named `temp`, `hack`, `test`, or `legacy`, read it closely.

**Obvious things** (subagent_type: `general`)
Other agents hunt subtle bugs. This agent checks the basic exposures everyone assumes someone else already checked. Be thorough and literal; grep for each item and report every result.

- Unsafe string/memory functions: `strcpy`, `strcat`, `sprintf`, `gets`, unbounded `scanf`, and `memcpy`/`memmove` with a wire length.
- Command execution sinks: `system(`, `popen(`, `exec`, backticks in shell scripts.
- Non-constant-time compares on secrets: `memcmp(` on MACs, tokens, PINs, or passwords.
- Weak randomness for crypto: `rand()`, `srand(time`, custom LFSRs seeded from a chip ID or constant.
- Debug-gated auth: `#ifdef DEBUG` / `#if 0` around authentication or verification.
- Hardcoded secrets: `"admin"`, default passwords, `-----BEGIN`, API tokens, `0xDEADBEEF`-style magic unlock constants.
- Insecure boot/lock config in production defaults: `RDP_LEVEL_0`, `CONFIG_*_DEBUG=y` in a release defconfig, `BOOT_SIGNATURE_TYPE_NONE`, a missing `MCUBOOT_SIGN_*`, `CONFIG_BOOTLOADER_*_INSECURE`.
- Image/TLV handling: `IMAGE_TLV` parsing before verification, unchecked `load_addr`/entry-point fields.
- Secrets in uninitialized memory: `__attribute__((section(".noinit")))` holding keys, keys not zeroized after use.
- Open services and defaults: Telnet enabled, `0.0.0.0` binds, default credentials, JTAG/SWD left unlocked in a provisioning script.

**Important**: For any finding this agent reports, verify the full code path, not just surface appearance. A `memcpy` is not a finding until an attacker-controlled length reaches it past every bound. A `#ifdef DEBUG` is not a finding until the release build defines it. A hardcoded string is not a secret until a security decision consumes it. Trace the impact and name the attacker vector before reporting.
