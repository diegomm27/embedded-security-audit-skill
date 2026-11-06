# Embedded Linux and Userspace Hunting

#### When to use this file

Reach for this file when the device runs embedded Linux (Yocto, Buildroot, OpenWrt) with a management UI, network daemons, a writable rootfs, or config import/restore: routers, gateways, cameras, NAS, industrial gateways. Pair it with `RTOS-AND-KERNEL.md` for kernel drivers, `DEVICE-PROTOCOLS-AND-CLOUD-LINK.md` for device-to-cloud links, and `TOOLCHAIN-SDK-AND-SUPPLY-CHAIN.md` for the Yocto/Buildroot layers and package versions. This file owns userspace: CGI and management interfaces, daemons, rootfs privilege, and config import, plus the hardening baseline as severity context.

Split a large target into web/management UI, services/daemons, rootfs/privilege, update/config import, and hardening baseline.

## Core discipline (include in every agent prompt for this domain)

```
- Trace request parameters into shells: system(), popen(), exec*, and shell scripts are command-injection sinks; check field names, headers, and filenames, not just values.
- Authentication on an endpoint is not authorization; check path normalization and server config for routes that skip the auth handler.
- "Everything runs as root" raises impact but is not a finding alone; attach it to a reachable code-exec or write.
- A hardening gap (no seccomp, devmem enabled) is severity context, not a standalone finding.
- Validate command injection and traversal in a host fixture or container; reaching a specific deployed route/config is `needs_validation`.
```

## Web and management UI attack classes (subagent_type: `general`)

**Command injection in CGI and handlers**
CGI binaries (C, Lua, shell) or a management daemon pass request parameters into `system()`, `popen()`, `exec*`, or a shell script without sanitization, giving command execution. Grep for `system(`, `popen(`, `exec`, and backticks in `/www`, `/cgi-bin`, and daemon source, and trace each argument to its request field. Injection reachable without auth is `confirmed` (critical); authenticated injection is high.

**Authentication bypass via path normalization**
The web server (lighttpd, uhttpd, boa, goahead, mini_httpd) or the app matches an auth rule on a path that normalization or encoding evades (`//cgi-bin`, `/./`, `%2e`, trailing dots), reaching a protected handler unauthenticated. Compare the auth-check path matching with how the handler is finally dispatched. A reachable bypass is `confirmed`.

**CSRF on device admin pages**
State-changing admin actions (change password, enable Telnet, update firmware) lack CSRF protection, so a malicious page in the user's browser drives them. Check for CSRF tokens/`SameSite` on state-changing endpoints. A reachable CSRF on a dangerous action is `confirmed`; impact scales with the action.

**Unauthenticated endpoints**
Some `/cgi-bin/*` or API routes are missing from the auth allowlist/denylist, exposing status, config, or actions without login. Enumerate route registrations and the auth config and diff them. A dangerous unauthenticated endpoint is `confirmed`.

## Services and daemons attack classes (subagent_type: `general`)

**Default/weak remote-access services**
Telnet, SSH/dropbear, or a vendor service ships enabled with default or no credentials, or with a backdoor account. Grep init scripts and configs for `telnetd`, `dropbear`, default users, and `/etc/passwd`/`/etc/shadow` entries. An enabled service with default/no auth is `confirmed`.

**Discovery and management protocols**
UPnP/SSDP, mDNS, TR-069/CWMP, or a vendor management daemon exposes actions or injection surfaces, or binds a management interface to the WAN. Check what each daemon exposes and on which interface. A dangerous action or injection reachable from an untrusted network is `confirmed`.

**Debug daemons left running**
`gdbserver`, `adbd`, a diagnostic port, or an MQTT broker bound on `0.0.0.0` is present in the production image, giving remote control or code execution. Grep init and the image for these. A reachable debug daemon is `confirmed`.

## Rootfs and privilege attack classes (subagent_type: `general`)

**Everything runs as root and setuid sprawl**
All services run as root, or setuid binaries (including a setuid BusyBox) grant broad privilege, so any code-exec is immediately root. Check service users and `find`-style setuid inventory in the image recipe. This raises severity of other findings; a setuid-BusyBox reachable by a lower-privilege user is `confirmed` as privilege escalation.

**World-writable paths in PATH and init**
A world-writable directory appears in a privileged process's PATH, or init scripts source files from a writable partition, so a lower-privilege actor plants a binary or script that runs as root. Grep init scripts for `. /tmp/...`, `source`, and writable-dir PATH entries. A reachable write-then-execute is `confirmed`.

**Default hashes and credentials in the image**
`/etc/shadow` ships with a known/default root hash, or credentials are embedded in configs. Check the image's shadow and config files. A crackable or known default hash is `confirmed` (see `CRYPTO-KEYS-AND-SECURE-STORAGE.md` for key material).

**Overlay/persistence and read-only assumptions**
An overlayfs or writable partition persists attacker-planted files across reboot, or code assumes a read-only rootfs that is actually writable. Check mount setup and whether attacker-writable paths survive reboot. Reachable persistence is `confirmed`.

## Update and config-import attack classes (subagent_type: `general`)

**Unsigned, shell-parsed config import**
Config backup/restore files are unencrypted and unsigned and are parsed by the shell (`. /tmp/config`, `eval`), so a crafted config executes commands or injects settings. Grep restore handlers for shell sourcing and `eval` of config data. A config-import code-exec is `confirmed`.

**Archive extraction path traversal**
Firmware or config upload extracts a tar/zip without checking entry paths, allowing overwrite of system files (zip slip) or symlink escape. Check extraction code for path validation and symlink handling. A reachable traversal on upload is `confirmed`.

## Hardening-baseline attack classes (subagent_type: `general`)

**Kernel and sandbox hardening as context**
`CONFIG_DEVMEM`/`/dev/mem` without `CONFIG_STRICT_DEVMEM`, unsigned kernel modules, absent seccomp/AppArmor, or disabled ASLR weaken containment. Record these as severity context and remediation, not as standalone findings. State clearly that they are not findings alone; attach them to a reachable boundary violation to raise its impact.

## Universal moves (apply across the above)

- Enumerate every externally reachable endpoint and daemon, its interface (LAN/WAN), its auth requirement, and whether request data reaches a shell, a path, or a privileged action.
- Compare the auth-matching path with the final dispatch path; normalization and encoding differences are where bypasses live.
- Inventory privilege: service users, setuid binaries, writable paths in privileged PATH/init, and whether findings land as root.
- Apply command-injection and traversal checks to config import and archive extraction, which are frequently overlooked.
- Keep hardening gaps as context; validate code-exec and traversal in a host fixture or container and mark deployment-specific reachability `needs_validation`.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust actor (remote/LAN/WAN client, local user) and the exact sink: shell command, file path, privileged action, or persisted file.
2. For command injection, trace the request field to the `system`/`popen`/`exec`/shell sink and reproduce in a host/container fixture; a quoted or validated argument is not a finding.
3. For auth bypass, show the path/encoding that evades the auth handler and reaches the protected dispatch.
4. Treat "runs as root", setuid sprawl, and kernel-hardening gaps as severity context; report them only attached to a reachable violation (a reachable setuid-escalation path is itself a finding).
5. Reproduce traversal and config-import issues with bounded fixtures; deployment-specific routes/configs are `needs_validation`.
6. Return `confirmed` only with a source trace and bounded local evidence; return `needs_validation` with the exact deployed route, config, or image fact an owner must confirm.
