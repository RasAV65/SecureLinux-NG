# Restore model — SecureLinux-NG

## Текущий этап

На текущем этапе `--restore` работает только для управляемых файлов и группы, для которых SecureLinux-NG уже ведёт достаточно данных в manifest.

Поддерживается:
- SSH drop-in `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf`
- PAM-файл `/etc/pam.d/su`
- sudoers drop-in `/etc/sudoers.d/60-securelinux-ng-policy`
- удаление группы `wheel`, если она была создана самим SecureLinux-NG

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

## Что пока не откатывается автоматически

Для модулей:
- `2.3.1`
- `2.3.3`
- `2.3.5`

сейчас сохраняются только metadata snapshots (`stat`-снимки), но нет полноценного автоматического восстановления прежнего owner/group/mode.

Это ограничение текущего этапа и оно должно явно отражаться в report.
