# Restore model — SecureLinux-NG

## Текущий этап

На текущем этапе `--restore` работает для:
- managed SSH drop-in `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf`
- managed sudoers drop-in `/etc/sudoers.d/60-securelinux-ng-policy`
- PAM-файла `/etc/pam.d/su`
- группы `wheel`, если она была создана самим SecureLinux-NG
- metadata restore для:
  - `/etc/passwd`, `/etc/group`, `/etc/shadow`
  - стандартных cron targets
  - targets в `/etc/systemd/system`

## Источник manifest

`--restore` использует:
1. `--manifest FILE`, если путь указан явно
2. иначе — последний `manifest-*.json` в `STATE_DIR`

## Что хранится в manifest

Для restore используются:
- `backups` в виде объектов:
  - `original`
  - `backup`
- `created_files`
- `created_groups`

## Metadata restore

Для модулей `2.3.1`, `2.3.3`, `2.3.5` используется упрощённая модель:
- при apply сохраняется машиночитаемый snapshot:
  - `MODE=`
  - `UID=`
  - `GID=`
- при restore значения читаются из snapshot;
- затем выполняются `chown uid:gid` и `chmod mode`.

## Ограничения

Restore по metadata всё ещё упрощённый, но он уже не зависит от локализованного текстового вывода `stat`.
Для совместимости сохранён fallback на старый snapshot-формат, если он встретится в старых manifest/backup.
