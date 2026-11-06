# Toolchain, SDK, and Supply Chain Hunting

#### When to use this file

Reach for this file when the firmware build pulls in vendor SDKs/HALs, binary blobs, package-manager or layer dependencies, and CI that signs or publishes images: west/ESP-IDF component manager/PlatformIO/Yocto/Buildroot, radio/Wi-Fi firmware blobs, MCUboot/imgtool signing in CI, and dev-vs-release build configs. Pair it with `FIRMWARE-UPDATE-AND-OTA.md` (the signing keys and published artifacts) and `BOOT-CHAIN-AND-SECURE-BOOT.md` (what the keys protect). This domain covers the trust handoff from source and dependency to the image a device runs.

Split a large target into dependency resolution, binary blobs, build configuration, and CI/signing.

## Core discipline (include in every agent prompt for this domain)

```
- A known-vulnerable or mutable dependency is not a finding by itself. Show who can influence resolution, which build consumes it, and what execution or signing boundary follows.
- State a dependency's version from the lockfile/manifest; never invent a CVE number. Describe the risk generically or cite a well-known real example.
- CI configuration is authorization code: which event triggered it, whose code runs, which secrets exist, and what it may sign or publish.
- A dev signing key or dev build config used for a release is the defect; prove it from the shipped pipeline, not the sample.
- Validate in-repo config flow; hosted-runner, registry, and signing-service facts not in the repo are needs_validation.
```

## Dependency-resolution attack classes (subagent_type: `general`)

**Unpinned or mutable dependency fetches**
west manifests, ESP-IDF component-manager dependencies, PlatformIO `lib_deps`, or Yocto/Buildroot recipes fetch branches, floating tags, or unpinned revisions, so the built firmware changes without source review. Grep manifests/recipes for unpinned revisions, `main`/`master` refs, and missing hashes. An unpinned fetch that reaches the firmware is `confirmed` as a supply-chain exposure; name a lower-trust writer where one exists.

**Namespace/source confusion**
Component or package resolution can select an unintended registry, mirror, or namespace (a public package shadowing a private one), pulling attacker-controllable code. Check source priority and namespace configuration. A reachable confusion is `confirmed`.

**Known-vulnerable vendored components**
A vendored SDK/HAL or library is pinned to a version with publicly known issues (state the version and describe the risk; do not invent a CVE). Check lockfiles/manifests for the pinned version and whether a reachable path uses the affected component. A reachable use of a known-vulnerable version is `confirmed`/`needs_validation` depending on reachability; cite a real example (for example a known-old lwIP/mbedTLS) rather than a fabricated identifier.

## Binary-blob attack classes (subagent_type: `general`)

**Blobs with no provenance**
Wi-Fi/BLE/radio firmware blobs, DSP images, or precompiled libraries ship with no source, hash, or provenance, so their integrity and contents are unverifiable. Inventory binary blobs in the tree and their provenance. A security-relevant blob with no integrity/provenance is a `confirmed` exposure; exploitability of its contents is `needs_validation`.

**Blob update and loading trust**
A blob is loaded or updated at runtime without an integrity check, so a replaced blob runs. Check blob loading/update paths for verification. An unverified blob load is `confirmed`.

## Build-configuration attack classes (subagent_type: `general`)

**Dev config used for release**
A development `prj.conf`/defconfig (debug on, secure boot off, shell enabled, verbose logging) is used to build release images, or there is no separate hardened release config. Compare `prj.conf` vs `prj_release.conf`/defconfig variants and the CI build command's config. A release built from a dev config is `confirmed` (and explains many other findings' reachability).

**Missing hardening flags (context)**
Compiler/linker hardening is absent: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE`, `-Wformat-security`, or an intentional `--no-warn-rwx-segments` masking RWX segments. Record these as context and remediation, not standalone findings; attach them to a reachable corruption to raise its impact. State explicitly that they are not findings alone.

**SBOM and reproducibility gaps**
No SBOM is generated and builds are not reproducible, so a compromised input is hard to detect. Record as a process weakness and remediation; it is not a finding by itself.

## CI and signing attack classes (subagent_type: `general`)

**Signing keys in the repo or CI**
Firmware/image signing keys live in the repository or CI, or the MCUboot default dev key (`root-rsa-2048.pem`) is used to sign release images, so anyone with repo/CI access signs firmware. Grep for key files, `imgtool sign` commands with repo keys, and CI secrets used for signing. A committed or dev signing key used for release is `confirmed` (critical, fleet-wide).

**Unsigned or wrongly-authorized publication**
CI publishes firmware artifacts unsigned, from an untrusted event (a fork PR, an unprotected branch), or without binding the artifact identity through promotion. Compare trigger events, checkout refs, and what the job may publish. An unsigned or wrongly-authorized release path is `confirmed`.

**Secrets reachable from untrusted CI events**
A workflow triggered by a pull request, issue comment, or fork runs contributor-controlled code with access to signing secrets or deployment tokens. Compare trigger type, checkout ref, and secret exposure. A reachable secret from an untrusted event is `confirmed`.

## Universal moves (apply across the above)

- Walk backward from the released/signed image to every dependency, blob, generated input, key, and CI decision; mark each mutable or untrusted handoff.
- State dependency versions from lockfiles/manifests and describe risk generically or with a real well-known example; never invent a CVE identifier.
- Compare dev and release build configurations and identify which one CI actually uses for shipped images.
- Treat hardening flags, SBOM, and reproducibility as context; report them attached to a reachable boundary or as remediation, not as standalone findings.
- Where hosted-runner, registry, or signing-service behavior is not in the repo, stop at `needs_validation` with the exact fact.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust actor (dependency author, CI contributor, repo-access holder) and the consuming build/sign/publish step and its result (code inclusion, signed malicious image, secret disclosure).
2. Prove the handoff: an unpinned/confused dependency or a dev/committed key must reach the shipped image or signing step.
3. Cite dependency versions from the repo and describe risk without fabricating CVE numbers; cite a real example when useful.
4. Keep hardening flags, SBOM, and reproducibility as context/remediation, not standalone findings.
5. Hosted-runner, registry, branch-protection, and signing-service facts not in the repo are `needs_validation`.
6. Return `confirmed` only with an in-repo handoff and bounded evidence; return `needs_validation` with the exact hosted/pipeline fact an owner must observe.
