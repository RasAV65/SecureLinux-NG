# Карта соответствия ФСТЭК — SecureLinux-NG

## Правила статусов

Допустимые статусы:
- `not started`
- `partial`
- `done`
- `not applicable`

Правило проекта:
- ничего не считать реализованным по ФСТЭК, пока нет:
  - кода;
  - проверки результата;
  - отражения в report / mapping.

## Важное разграничение

Текущая версия `16.0.0` находится на этапе framework.
Наличие CLI, config loading, preflight, manifest, report, dry-run и tests **не считается** реализацией требований ФСТЭК само по себе.
Это только подготовительная база для дальнейших модулей hardening.

## Framework prerequisites (не засчитываются как реализация пунктов ФСТЭК)

| Компонент | Статус | Код/блок | Комментарий |
|---|---|---|---|
| CLI framework | done | `securelinux-ng.sh` | Есть режимы `--check`, `--apply`, `--restore`, `--report`, `--dry-run`, `--profile`, `--config` |
| Config loading | done | `load_config()` | Есть базовая загрузка внешнего config |
| Preflight skeleton | done | `run_preflight()` | Есть начальное определение среды и policy-gates |
| Manifest skeleton | done | `manifest_init()` | Есть JSON-структура manifest |
| Report skeleton | done | `write_report()` / `print_report_stdout()` | Есть JSON report и stdout summary |
| Dry-run framework | done | `--apply --dry-run` | Есть dry-run без изменения системы |
| Syntax / smoke tests | done | `tests/syntax.sh`, `tests/smoke.sh` | Есть минимальная проверка framework |

## 2.1. Настройка авторизации

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.1.1. Не допускать пустые пароли / обеспечить пароль или блокировку по паролю | not started | — | — | В `NG` ещё нет модуля проверки/исправления пустых паролей и состояния `/etc/shadow` |
| 2.1.2. Отключить вход root по SSH (`PermitRootLogin no`) | partial | `check_ssh_root_login_module()` / `apply_ssh_root_login_module()` | `--check`, `--apply`, `sshd -t`, наличие `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf` | Реализован первый SSH-модуль через drop-in; добавлен базовый restore managed file |

## 2.2. Ограничение механизмов получения привилегий

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.2.1. Ограничить `su` через `pam_wheel.so use_uid` и группу `wheel` | partial | `check_pam_wheel_module()` / `apply_pam_wheel_module()` | `--check`, `--apply`, наличие группы `wheel`, активное правило в `/etc/pam.d/su` | Реализован первый PAM / `su`-модуль; добавлен базовый restore `/etc/pam.d/su` и группы `wheel` |
| 2.2.2. Ограничить пользователей/команды в `sudoers` | partial | `check_sudo_policy_module()` / `apply_sudo_policy_module()` | `--check`, `--apply`, `visudo -cf`, наличие `/etc/sudoers.d/60-securelinux-ng-policy` | Реализована базовая sudo policy model для `%wheel`; добавлен базовый restore managed sudoers drop-in |

## 2.3. Настройка прав доступа к объектам файловой системы

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.3.1. Корректные права для `/etc/passwd`, `/etc/group`, `/etc/shadow` | partial | `check_fs_critical_files_module()` / `apply_fs_critical_files_module()` | `--check`, `--apply`, `stat`, проверка mode/owner/group | Реализован первый FS-permissions-модуль; добавлен metadata restore по stat-snapshot |
| 2.3.2. Корректные права для исполняемых файлов и библиотек запущенных процессов | partial | `check_runtime_paths_module()` / `apply_runtime_paths_module()` | `--check`, сканирование `/proc/*/exe` и `/proc/*/maps`, проверка `go-w` на файлах и родительских директориях | Реализован detect-only модуль; автоматический chmod для runtime paths пока policy-gated |
| 2.3.3. Корректные права для файлов/команд из cron | partial | `check_cron_targets_module()` / `apply_cron_targets_module()` | `--check`, `--apply`, `stat`, проверка mode/owner/group | Реализован начальный cron ownership/perms-модуль для стандартных cron targets; добавлен metadata restore по stat-snapshot |
| 2.3.4. Корректные права/владельцы для файлов, выполняемых через sudo | partial | `check_sudo_command_paths_module()` / `apply_sudo_command_paths_module()` | `--check`, анализ `/etc/sudoers` и `/etc/sudoers.d/*`, проверка `go-w` на файлах и родительских директориях | Реализован detect-only модуль; автоматический chmod для sudo command paths пока policy-gated |
| 2.3.5. Корректные права для стартовых скриптов и `.service` | partial | `check_systemd_unit_targets_module()` / `apply_systemd_unit_targets_module()` | `--check`, `--apply`, `stat`, проверка mode/owner/group | Реализован начальный systemd ownership/perms-модуль для targets в `/etc/systemd/system`; добавлен metadata restore по stat-snapshot |

## 2.4. Настройка механизмов защиты ядра Linux

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.4.1. Ограничить доступ к журналу ядра (`kernel.dmesg_restrict=1`) | partial | `sysctl_kernel_check_module()` / `apply_sysctl_kernel_module()` | `--check`, `--apply`, `sysctl -n kernel.dmesg_restrict`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.4.2. Скрыть ядерные адреса (`kernel.kptr_restrict=2`) | partial | `sysctl_kernel_check_module()` / `apply_sysctl_kernel_module()` | `--check`, `--apply`, `sysctl -n kernel.kptr_restrict`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.4.3. `init_on_alloc=1` | not started | — | — | Требует отдельного GRUB/boot-params модуля |
| 2.4.4. `slab_nomerge` | not started | — | — | Требует отдельного GRUB/boot-params модуля |
| 2.4.5. `iommu=force iommu.strict=1 iommu.passthrough=0` | not started | — | — | Требует отдельного GRUB/boot-params модуля |
| 2.4.6. `randomize_kstack_offset=1` | not started | — | — | Требует отдельного GRUB/boot-params модуля |
| 2.4.7. `mitigations=auto,nosmt` | not started | — | — | Требует отдельного GRUB/boot-params модуля |
| 2.4.8. Защита eBPF JIT (`net.core.bpf_jit_harden=2`) | partial | `sysctl_kernel_check_module()` / `apply_sysctl_kernel_module()` | `--check`, `--apply`, `sysctl -n net.core.bpf_jit_harden`, managed drop-in | Реализован в составе базового sysctl-модуля |

## 2.5. Уменьшение периметра атаки ядра Linux

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.5.* | not started | — | — | Блок attack surface reduction ещё не реализован в `NG` |

## 2.6. Настройка средств защиты пользовательского пространства со стороны ядра Linux

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.6.* | not started | — | — | Блок user-space protections ещё не реализован в `NG` |

## Приоритет разработки модулей для перехода от framework к реальному покрытию

1. `2.1.2` — SSH / `PermitRootLogin no`
2. `2.2.1` — `pam_wheel.so use_uid` + `wheel`
3. `2.2.2` — sudo policy model
4. `2.3.1` — права `/etc/passwd`, `/etc/group`, `/etc/shadow`
5. затем остальные подпункты `2.3.*`
6. затем `2.4.*`, `2.5.*`, `2.6.*`

## Правило обновления карты

Любое изменение в hardening-модулях должно обновлять:
1. `docs/fstec-mapping.md`
2. `README.md` — если меняются режимы/возможности
3. `CHANGELOG.md`
4. tests / проверки
