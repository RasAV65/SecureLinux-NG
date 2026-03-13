# Архитектура SecureLinux-NG

## Назначение

SecureLinux-NG — framework для безопасной настройки Linux-хостов с опорой на требования и рекомендации ФСТЭК, с обязательной проверкой совместимости до применения изменений, фиксацией действий в manifest/report и контролируемым откатом там, где это возможно.

## Границы версии 16.0.0

Версия 16.0.0 на текущем этапе является framework-линией.
Её задача — не реализовать весь hardening сразу, а создать базовую архитектуру, на которую дальше будут навешиваться проверяемые hardening-модули.

На текущем этапе в основе должны быть:
- CLI framework;
- загрузка внешнего config;
- preflight / compatibility skeleton;
- manifest skeleton;
- report skeleton;
- dry-run framework;
- базовые smoke/syntax tests.

## Основные режимы

Поддерживаемые режимы:
- `--help`
- `--version`
- `--check`
- `--apply`
- `--restore`
- `--report`

Поддерживаемые опции framework-уровня:
- `--dry-run`
- `--profile=baseline|strict|paranoid`
- `--config <file>`

## Модель профилей

Проект использует три профиля:
- `baseline`
- `strict`
- `paranoid`

Назначение профилей:
- `baseline` — минимально необходимый и максимально совместимый уровень;
- `strict` — усиленный уровень с большим количеством ограничений;
- `paranoid` — максимально жёсткий профиль, допускающий дополнительные compatibility-ограничения.

На framework-этапе профили уже должны разбираться CLI и отражаться в report/manifest, даже если hardening-модули ещё не реализованы.

## Модель конфигурации

Приоритет источников конфигурации:
1. defaults внутри скрипта;
2. внешний config file;
3. CLI overrides.

Минимально поддерживаемые ключи config:
- `PROFILE`
- `STATE_DIR`
- `REPORT_FILE`
- `MANIFEST_FILE`

Требования к config:
- формат `KEY=VALUE`;
- пустые строки и комментарии допустимы;
- неизвестные ключи не должны ломать выполнение, но должны отражаться как warning.

## Preflight / compatibility model

Перед применением hardening-мер должен выполняться preflight-анализ среды.

Минимум, что должен определять preflight:
- семейство ОС;
- версия ОС;
- container / non-container;
- desktop / server-like environment;
- Docker;
- Podman;
- Kubernetes node.

Результат preflight должен раскладываться минимум на 4 категории:
- `safe`
- `risky`
- `skipped`
- `requires_confirmed_policy`

Принцип:
- framework не должен молча применять потенциально опасные меры;
- сомнительные меры сначала маркируются, затем либо разрешаются политикой, либо пропускаются.

## Manifest model

Manifest должен быть машинно-читаемым и пригодным для restore/report.

Минимальные поля manifest:
- `version`
- `profile`
- `mode`
- `timestamp`
- `backups`
- `created_files`
- `created_groups`
- `modified_files`
- `systemd_units`
- `sysctl_configs`
- `grub_backups`
- `apply_report`
- `warnings`
- `irreversible_changes`

На этапе framework manifest может быть частично пустым, но его структура уже должна быть стабильной.

## Restore model

Restore в SecureLinux-NG должен опираться не на догадки, а на manifest.

Restore-модель должна предполагать:
- восстановление изменённых файлов из backup;
- удаление созданных файлов;
- удаление созданных групп;
- удаление созданных systemd unit/drop-in;
- удаление созданных sysctl drop-in;
- отдельную маркировку действий, которые автоматически неоткатны.

Если откат невозможен, это должно быть явно отражено в manifest/report.

## Report model

После `--check`, `--apply`, `--restore` и `--report` должен существовать единый формат итогового report.

Минимальные разделы report:
- версия;
- профиль;
- режим;
- сведения о среде;
- `safe`;
- `risky`;
- `skipped`;
- `requires_confirmed_policy`;
- `warnings`;
- `errors`.

На этапе dry-run report может не писаться на диск, но summary должен печататься в stdout.

## Dry-run model

`--dry-run` допустим только вместе с `--apply`.

В dry-run framework обязан:
- ничего не менять в системе;
- показывать, что было бы создано;
- показывать, что было бы изменено;
- показывать, какие артефакты manifest/report были бы созданы;
- печатать итоговую summary без требования реального наличия report-файла.

## Разделение framework и hardening

Критическое правило версии 16.0.0:
- framework и hardening не смешивать.

Порядок разработки:
1. framework;
2. preflight policy gates;
3. config/report/manifest stabilization;
4. hardening modules;
5. coverage checks;
6. restore verification.

## Будущие группы hardening-модулей

После стабилизации framework модули рекомендуется вводить по группам:
1. identity / auth / PAM / SSH;
2. file permissions / ownership;
3. kernel / sysctl / boot hardening;
4. audit / verification / coverage.

## Трассировка требований

Каждый будущий hardening-блок должен иметь:
- ссылку на пункт ФСТЭК;
- статус покрытия;
- проверку результата;
- отражение в `docs/fstec-mapping.md`.

Ничего не считать реализованным окончательно, пока нет:
- кода;
- проверки;
- отражения в mapping.

## Документационный принцип

Для SecureLinux-NG порядок должен быть таким:
1. сначала фиксируется архитектура;
2. затем меняется код;
3. затем добавляются тесты;
4. затем обновляются README / CHANGELOG / mapping.

## Report coverage model

Итоговый `report` должен включать не только среду и warnings/errors, но и отдельный блок покрытия ФСТЭК:
- `fstec_items`
- `fstec_summary`

Это позволяет видеть текущий фактический объём реализованных модулей без чтения `docs/fstec-mapping.md`.
