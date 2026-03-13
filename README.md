# SecureLinux-NG

**Версия:** 16.0.0

## Назначение

SecureLinux-NG — новый проект безопасной настройки Linux-хостов с полной ориентацией на требования и рекомендации ФСТЭК, с управляемым применением изменений, проверкой покрытия требований и контролируемым откатом.

## Статус

Проект находится в разработке как отдельная линия, независимая от SecureLinux 15.x.

## Цели проекта

- полное и прозрачное покрытие требований ФСТЭК;
- жёсткая трассировка: каждый блок кода должен быть привязан к пункту стандарта;
- предсказуемое применение изменений;
- режимы проверки, применения и отката;
- минимизация скрытых побочных эффектов;
- отдельный контроль совместимости изменений.

## Структура проекта

- `securelinux-ng.sh` — основной скрипт
- `docs/architecture.md` — архитектура проекта
- `docs/fstec-mapping.md` — карта соответствия требованиям ФСТЭК
- `docs/compatibility.md` — совместимость и ограничения
- `docs/restore-model.md` — модель отката
- `examples/` — примеры конфигурации
- `tests/` — базовые тесты
- `research/` — справочные и сравнительные материалы

## Базовые принципы

1. Все изменения должны быть обратимыми.
2. Все изменения должны быть проверяемыми.
3. Все меры должны иметь явную привязку к документам.
4. Совместимость должна проверяться до применения изменений.
5. Любые допущения должны быть документированы отдельно.

## Текущая версия

`16.0.0`


## Что уже реализовано

### Framework
- CLI framework
- config loading
- preflight skeleton
- manifest skeleton
- report skeleton
- dry-run skeleton
- basic restore flow for managed files/groups
- syntax/smoke tests

### Первые hardening-модули
- `2.1.2` — отключение входа `root` по SSH через drop-in:
  - файл: `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf`
  - параметр: `PermitRootLogin no`
  - поддержка: `--check`, `--apply`, `--apply --dry-run`

- `2.2.1` — ограничение `su` через `pam_wheel.so use_uid` и группу `wheel`:
  - файл: `/etc/pam.d/su`
  - правило: `auth required pam_wheel.so use_uid group=wheel`
  - создаётся группа: `wheel` (если отсутствует)
  - поддержка: `--check`, `--apply`, `--apply --dry-run`

- `2.2.2` — базовая sudo policy model через managed drop-in:
  - файл: `/etc/sudoers.d/60-securelinux-ng-policy`
  - правило: `%wheel ALL=(ALL:ALL) ALL`
  - проверка: `visudo -cf`
  - поддержка: `--check`, `--apply`, `--apply --dry-run`

- `2.3.1` — контроль владельца/группы/прав для критичных файлов:
  - `/etc/passwd` → `root:root`, `0644`
  - `/etc/group` → `root:root`, `0644`
  - `/etc/shadow` → `root:shadow`, `0640`
  - поддержка: `--check`, `--apply`, `--apply --dry-run`

- `2.3.2` — контроль прав для исполняемых файлов запущенных процессов и соответствующих библиотек:
  - сканируются пути из `/proc/*/exe` и `/proc/*/maps`
  - проверяется отсутствие `group/other write` на самом файле
  - проверяется отсутствие `group/other write` у родительских директорий
  - текущий статус: `check` + policy-gated detect-only в `apply`

- `2.3.4` — контроль прав для файлов/команд, встречающихся в `sudoers`:
  - сканируются `/etc/sudoers` и `/etc/sudoers.d/*`
  - извлекаются абсолютные пути команд
  - проверяется отсутствие `group/other write` на самом файле
  - проверяется отсутствие `group/other write` у родительских директорий
  - текущий статус: `check` + policy-gated detect-only в `apply`

- `2.3.3` — контроль владельца/группы/прав для cron-целей:
  - `/etc/crontab` → `root:root`, `0600`
  - `/etc/cron.d` → `root:root`, `0700`
  - `/etc/cron.hourly` → `root:root`, `0700`
  - `/etc/cron.daily` → `root:root`, `0700`
  - `/etc/cron.weekly` → `root:root`, `0700`
  - `/etc/cron.monthly` → `root:root`, `0700`
  - поддержка: `--check`, `--apply`, `--apply --dry-run`

- `2.3.5` — контроль владельца/группы/прав для systemd unit/drop-in targets в `/etc/systemd/system`:
  - каталог `/etc/systemd/system` и `*.d` → `root:root`, `0755`
  - unit-файлы `*.service`, `*.socket`, `*.timer`, `*.mount`, `*.path`, `*.target`, `*.slice` → `root:root`, `0644`
  - drop-in `*.conf` → `root:root`, `0644`
  - поддержка: `--check`, `--apply`, `--apply --dry-run`

- `2.4.1`, `2.4.2`, `2.4.8` — базовый sysctl-модуль защиты ядра:
  - `kernel.dmesg_restrict = 1`
  - `kernel.kptr_restrict = 2`
  - `net.core.bpf_jit_harden = 2`
  - managed drop-in: `/etc/sysctl.d/60-securelinux-ng-kernel.conf`
  - поддержка: `--check`, `--apply`, `--apply --dry-run`, `--restore`

## Restore

Сейчас `--restore` умеет:
- брать manifest из `--manifest FILE` или автоматически выбирать последний `manifest-*.json` из `STATE_DIR`;
- восстанавливать managed SSH drop-in;
- восстанавливать managed sudoers drop-in;
- восстанавливать `/etc/pam.d/su` из backup;
- удалять группу `wheel`, если она была создана самим SecureLinux-NG.

Текущий статус metadata-restore:
- для модулей `2.3.1`, `2.3.3`, `2.3.5` восстановление выполняется по машиночитаемому metadata-snapshot;
- восстанавливаются прежние `uid:gid` и `mode`, если snapshot найден и успешно разобран;
- для совместимости сохранён fallback на старый текстовый формат snapshot.

### Поведение STATE_DIR

- для `apply` каталог состояния должен быть доступен на запись;
- для `check`, `report`, `restore` при недоступности `STATE_DIR` используется fallback:
  - `./.securelinux-ng-state`
- fallback сопровождается warning-сообщением в report/stdout.

### Покрытие ФСТЭК в report

В `report-*.json` и stdout summary сейчас дополнительно отражаются:
- `fstec_items`
- `fstec_summary`
- количество реализованных пунктов
- количество `partial` / `done`
- тип restore-модели для каждого реализованного пункта
