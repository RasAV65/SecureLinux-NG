# CHANGELOG

## [16.0.0] - 2026-03-14

### Added
- framework skeleton in `securelinux-ng.sh`
- config examples in `examples/`
- basic `syntax` and `smoke` tests
- expanded `docs/architecture.md`
- strict initial `docs/fstec-mapping.md`
- first real hardening module `2.1.2`: disable SSH root login via `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf`
- `--check` and `--apply` coverage for SSH root login enforcement
- `sshd -t` validation after apply
- `2.2.1`: restrict `su` via `pam_wheel.so use_uid group=wheel`
- group `wheel` creation during apply if absent
- managed block insertion into `/etc/pam.d/su`
- `2.3.1`: check/apply owner, group and mode for `/etc/passwd`, `/etc/group`, `/etc/shadow`
- `2.2.2`: add managed sudo policy drop-in `/etc/sudoers.d/60-securelinux-ng-policy` with `visudo` validation
- `2.3.3`: add initial cron ownership/perms module for standard cron targets
- `2.3.5`: add initial systemd unit/drop-in ownership/perms module for `/etc/systemd/system`
- add basic restore flow for managed SSH/PAM/sudo files and created group `wheel`
- add `--manifest FILE` support for restore
- extend restore to `2.3.1`, `2.3.3`, `2.3.5` using metadata snapshots
- fix `record_manifest_backup` call in systemd permissions module
- switch metadata restore snapshots to machine-readable `MODE/UID/GID` format with fallback for legacy snapshots
- add writable fallback `STATE_DIR` for non-root `check/report/restore` runs
- add `fstec_items` and `fstec_summary` to generated report output
- extend smoke test with `--restore --manifest` path
- add smoke assertions for FSTEC summary in stdout
- `2.3.2`: add runtime executable/library permissions scan with policy-gated detect-only apply

### Fixed
- fix unset shell variable in `2.3.2` dry-run summary output
- dry-run summary output without reading a non-existent report file
- smoke test now uses a local writable state directory

