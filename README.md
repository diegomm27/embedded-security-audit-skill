# embedded-security-audit

A coding-agent skill that turns your agent into a security auditor for embedded systems: MCU firmware, RTOS applications, bootloaders and secure boot, embedded Linux, TEEs/TrustZone, device drivers, OTA update, provisioning, wireless/fieldbus protocols, and firmware images. It orchestrates isolated agents through reconnaissance, coverage-led hunting, candidate validation, structured output, independent record verification, and target-neutral reporting.

It is a domain port of Cloudflare's MIT-licensed [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill. The six-phase workflow, coverage ledger, adversarial validation, and schema-validated findings are preserved exactly; the domain content is specialized for firmware and embedded devices.

## What it does

The skill runs a structured audit in six phases:

1. **Reconnaissance** -- map the platform (arch/core, MPU/MMU, TrustZone, memory map), software stack, boot chain, input surfaces, trust boundaries, secrets, and deterministic coverage in `architecture.md` and `coverage-ledger.json`.
2. **Coverage-led hunting** -- assign isolated hunters from ledger units, record their checks, and use coverage critics to find gaps.
3. **Candidate validation** -- give every unique candidate to a fresh verifier that tries to disprove it, checking host-vs-target type sizes and endianness.
4. **Structured output** -- write `confirmed`, `needs_validation`, and `rejected` records to `findings.json` and validate them against `report-schema.json`.
5. **Independent record verification** -- fresh agents verify final source claims. Material replacements receive another independent verifier.
6. **Target-neutral reporting** -- derive `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`, including a device threat-model summary and the production-configuration assumptions the audit could not see.

The parent runs `validate-coverage-ledger.cjs` after creating the ledger and after each later update, and `validate-findings.cjs` in Phase 4 and again after every Phase 5 replacement.

The verdicts are distinct: `confirmed` has a complete source trace and a bounded host/emulator result, `needs_validation` has an exact unresolved fact (often a fuse, lock-state, radio, or on-target timing fact) and no severity, and `rejected` records a disproved candidate. Each `confirmed`/`needs_validation` record names its `attack_vector`, and findings may carry optional `target_context` and a `safety_relevant` flag.

Multiple runs against the same repo are additive: prior ledgers and findings target gaps, revalidate changed source, and carry forward current-source evidence without treating stale work as covered.

## Files

| File | Purpose |
|------|---------|
| `README.md` | This overview |
| `NOTICE` | Attribution for the ported Cloudflare portions (MIT) |
| `LICENSE` | Repository license |
| `skills/embedded-security-audit/SKILL.md` | Setup, core principles, embedded terminology, execution safety, severity anchors, workflow overview, and anti-patterns |
| `skills/embedded-security-audit/RECONNAISSANCE.md` | Phase 1 reconnaissance prompts, companion selection, and the coverage ledger |
| `skills/embedded-security-audit/HUNTING.md` | Phase 2 orchestration, embedded hunting methodology, and validation rules |
| `skills/embedded-security-audit/ATTACK-CLASSES.md` | Core, wildcard, and obvious-things attack prompts and the companion router |
| `skills/embedded-security-audit/VALIDATION-AND-REPORTING.md` | Phases 3–6 candidate validation, structured output, record verification, and reporting |
| `skills/embedded-security-audit/FIRMWARE-MEMORY-SAFETY.md` | Bounds, integer, lifetime, concurrency, DMA/MMIO, and endianness classes for C/C++ firmware |
| `skills/embedded-security-audit/BOOT-CHAIN-AND-SECURE-BOOT.md` | Chain-of-trust, signature logic, image parsing, anti-rollback, and recovery/DFU classes |
| `skills/embedded-security-audit/FIRMWARE-UPDATE-AND-OTA.md` | Update authenticity, manifest, rollback/freeze, transfer, and DFU-channel classes |
| `skills/embedded-security-audit/CRYPTO-KEYS-AND-SECURE-STORAGE.md` | Key material, RNG/entropy, primitive misuse, constant-time, and secure-storage classes |
| `skills/embedded-security-audit/TRUSTZONE-TEE-AND-ISOLATION.md` | TrustZone-M/A, TF-M/PSA, OP-TEE/TF-A, MPU userspace, and hypervisor classes |
| `skills/embedded-security-audit/RTOS-AND-KERNEL.md` | RTOS objects, shells/logging, network-stack config, filesystem, and Linux-driver classes |
| `skills/embedded-security-audit/EMBEDDED-LINUX-AND-USERSPACE.md` | CGI/management UI, daemons, rootfs privilege, config import, and hardening-baseline classes |
| `skills/embedded-security-audit/HARDWARE-INTERFACES-AND-DEBUG.md` | JTAG/SWD lock, UART consoles, test/factory modes, external memories, and bus-trust classes |
| `skills/embedded-security-audit/WIRELESS-AND-RADIO-PROTOCOLS.md` | BLE, Wi-Fi provisioning, 802.15.4/Zigbee/Thread/Matter, LoRaWAN/sub-GHz, and cellular/NFC classes |
| `skills/embedded-security-audit/FIELDBUS-AUTOMOTIVE-AND-ICS.md` | UDS/CAN/SecOC, Modbus/PROFINET/CIP/BACnet/DNP3/OPC UA, and proprietary/medical classes |
| `skills/embedded-security-audit/DEVICE-PROTOCOLS-AND-CLOUD-LINK.md` | MQTT/CoAP/LwM2M/HTTP clients, device identity, shadow/twin, companion-app link, and replay classes |
| `skills/embedded-security-audit/FAULT-INJECTION-AND-SIDE-CHANNEL.md` | Source-pattern-only single-point-decision, control-flow-fragility, and timing-oracle classes |
| `skills/embedded-security-audit/DEVICE-LIFECYCLE-AND-PROVISIONING.md` | Provisioning, lifecycle state, factory reset/decommissioning, claiming, and end-of-life classes |
| `skills/embedded-security-audit/SAFETY-AND-AVAILABILITY.md` | Resource exhaustion, watchdog/reset, bricking/flash wear, fail-open, and safety-function classes |
| `skills/embedded-security-audit/TOOLCHAIN-SDK-AND-SUPPLY-CHAIN.md` | Dependency resolution, binary blobs, build configs, and CI/signing classes |
| `skills/embedded-security-audit/FIRMWARE-IMAGE-ANALYSIS.md` | Extraction, triage, static analysis, and emulation for binary-image-only targets |
| `skills/embedded-security-audit/report-schema.json` | JSON schema for all three `findings.json` verdicts, with embedded fields |
| `skills/embedded-security-audit/validate-findings.cjs` | Zero-dependency validator for `findings.json` in Phases 4 and 5 |
| `skills/embedded-security-audit/validate-findings.test.cjs` | Findings-validator tests and producer-compatible fixture checks |
| `skills/embedded-security-audit/validate-coverage-ledger.cjs` | Zero-dependency validator for `coverage-ledger.json` in Phases 1–5 |
| `skills/embedded-security-audit/validate-coverage-ledger.test.cjs` | Coverage-ledger validator tests |

## Installation

Install the skill with the [Skills CLI](https://skills.sh):

```bash
npx skills add https://github.com/diegomm27/embedded-security-audit-skill \
  --skill embedded-security-audit
```

Use `--global` for a user-level installation:

```bash
npx skills add https://github.com/diegomm27/embedded-security-audit-skill \
  --skill embedded-security-audit \
  --global
```

Run `npx skills --help` for agent-selection and non-interactive options.

## Usage

Start your coding agent in (or pointed at) the firmware source you want to audit, then ask it to do a security audit:

```
security audit this firmware
```

```
review the bootloader in ./bl2 for secure boot bypasses
```

```
audit this Zephyr app, output to ~/audits/x
```

```
analyze firmware.bin
```

The skill activates automatically when the request matches its trigger (embedded security audit, firmware review, audit the bootloader, analyze a firmware image, etc.). A direct firmware audit or device pen-test request uses full audit mode. Security questions and focused firmware work use guidance mode unless you request report artifacts. In full audit mode, an unspecified output directory defaults to `~/embedded-security-audit/<repo-name>/run-<N>`. The workflow writes inside the target repository only when you explicitly select a directory that version control ignores. When the input is a binary image rather than source, the skill uses its firmware-image analysis mode.

## Requirements

- A coding agent with a model that supports tool use and parallel sub-agents.
- Node.js ≥ 18 for the zero-dependency findings and coverage-ledger validators.
- An OS-enforced sandbox for any target-controlled builds, tests, native/sim targets, emulators, fuzzers, and fixtures. It must disable external networking, use a sanitized allowlisted environment, enforce resource limits, and allow writes only to assigned scratch paths. Without these controls, the workflow keeps the lead as `needs_validation` instead of executing target code.
- Optional local tools, used only inside the sandbox and fully offline: QEMU, Renode, Unicorn; the project's own native/sim targets (Zephyr `native_sim`, the FreeRTOS POSIX port, the ESP-IDF linux target); libFuzzer/AFL++ for host parser fuzzing; and binwalk/unblob/Ghidra for firmware-image analysis.

## Embedded hardware and RF safety

This is a defensive, source-first skill. In both guidance and full audit mode it never touches hardware or the air:

- No flashing, erasing, resetting, power-cycling, or debug-attaching (JTAG/SWD/UART); no opening `/dev/tty*`, USB, CAN, or GPIO/SPI/I2C character devices.
- No RF transmission (BLE, Wi-Fi, Zigbee, Thread, LoRa, sub-GHz, NFC, cellular), no monitor/injection mode, and no SDRs.
- No traffic onto a real bus (CAN, LIN, Modbus, PROFINET, EtherCAT, BACnet) or to any device, gateway, cloud, or OTA endpoint.
- Execution is limited to host-compiled tests, the project's own native/sim targets, and offline emulators with no network and no host-device passthrough.
- Anything that needs real silicon (fuse state, RDP/APPROTECT level, glitch behavior, on-target timing, RF) is reported as `needs_validation` with an owner-run, bench-only plan. The skill never produces glitch parameters, key-extraction scripts, or persistence implants.

## Design principles

- **Only confirm established boundary failures.** Keep a source-grounded blocked lead as `needs_validation` with its exact unresolved fact (often a fuse, lock-state, radio, or on-target timing fact).
- **Adversarial validation.** The agent that checks a finding is never the agent that found it.
- **Severity requires impact.** Likelihood x impact against embedded anchors, not deviation from a checklist; physical-invasive-only findings cap at medium unless they yield a fleet-wide secret, and safety impact is recorded only with a source-visible actuator path.
- **Host is not target.** A crash in a host build proves a defect only if the same code, with the same type sizes, alignment, and endianness, ships to the device.
- **Respect source visibility.** Never assume production lock state from a development config.
- **Multiple runs improve coverage.** Prior ledgers and findings target gaps instead of re-reporting the same ground.

## Attribution

This skill is a domain port of Cloudflare's [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill, Copyright (c) Cloudflare, Inc., MIT License, described in [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness). The six-phase workflow, coverage ledger, adversarial validation discipline, report schema, and validators are adapted from that project; see [NOTICE](NOTICE) for details. The embedded domain content is original to this project.

## License

MIT -- see [LICENSE](LICENSE).
