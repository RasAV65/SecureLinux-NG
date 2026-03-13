## [16.0.0] - 2026-03-14

### Added
- framework skeleton in `securelinux-ng.sh`
- config examples in `examples/`
- basic `syntax` and `smoke` tests
- expanded `docs/architecture.md`
- strict initial `docs/fstec-mapping.md`

### Fixed
- dry-run summary output without reading a non-existent report file
- smoke test now uses a local writable state directory

# CHANGELOG

## 16.0.0
- создан отдельный репозиторий SecureLinux-NG
- создан новый каркас проекта
- добавлена базовая структура документации
- справочные материалы вынесены в `research/`

### Added
- first real hardening module `2.1.2`: disable SSH root login via `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf`
- `--check` and `--apply` coverage for SSH root login enforcement
- `sshd -t` validation after apply\n- `2.2.1`: restrict `su` via `pam_wheel.so use_uid group=wheel`
- group `wheel` creation during apply if absent
- managed block insertion into `/etc/pam.d/su`
