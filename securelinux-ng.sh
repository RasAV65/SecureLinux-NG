#!/usr/bin/env bash
# securelinux-ng.sh
# Version: 16.0.0
# Project: SecureLinux-NG

SCRIPT_VERSION="16.0.0"

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=""
DRY_RUN=0
PROFILE="baseline"
CONFIG_FILE=""
REPORT_FILE=""
MANIFEST_FILE=""
STATE_DIR="/var/log/securelinux-ng"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"

DISTRO_ID=""
DISTRO_VERSION_ID=""
OS_FAMILY=""
IS_CONTAINER=0
IS_DESKTOP=0
HAS_DOCKER=0
HAS_PODMAN=0
HAS_K8S=0

SSH_ROOT_LOGIN_DROPIN="/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf"
SSH_ROOT_LOGIN_CONTENT=$'# Managed by SecureLinux-NG\nPermitRootLogin no\n'

PAM_SU_FILE="/etc/pam.d/su"
PAM_WHEEL_BLOCK_BEGIN="# BEGIN SecureLinux-NG 2.2.1"
PAM_WHEEL_BLOCK_END="# END SecureLinux-NG 2.2.1"
PAM_WHEEL_LINE="auth required pam_wheel.so use_uid group=wheel"

declare -a WARNINGS=()
declare -a ERRORS=()
declare -a SAFE_ITEMS=()
declare -a RISKY_ITEMS=()
declare -a SKIPPED_ITEMS=()
declare -a POLICY_GATES=()

usage() {
    cat <<'EOF'
Usage:
  ./securelinux-ng.sh --help
  ./securelinux-ng.sh --version
  ./securelinux-ng.sh --check [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --apply [--dry-run] [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --restore [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --report [--profile PROFILE] [--config FILE]

Modes:
  --check           Read-only analysis of current state
  --apply           Framework apply mode (skeleton only)
  --restore         Framework restore mode (skeleton only)
  --report          Print framework report JSON

Options:
  --dry-run         Show what would be done (valid with --apply only)
  --profile NAME    baseline | strict | paranoid
  --config FILE     External config file
  --help            Show help
  --version         Show version
EOF
}

log() {
    printf '[%s] %s
' "$(date '+%F %T %z')" "$*"
}

die() {
    log "[FAIL] $*"
    exit 1
}

add_warning() { WARNINGS+=("$1"); }
add_error() { ERRORS+=("$1"); }
add_safe() { SAFE_ITEMS+=("$1"); }
add_risky() { RISKY_ITEMS+=("$1"); }
add_skipped() { SKIPPED_ITEMS+=("$1"); }
add_policy_gate() { POLICY_GATES+=("$1"); }

record_manifest_warning() {
    local msg="$1"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$msg" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
msg = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
data.setdefault("warnings", []).append(msg)
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
}

record_manifest_modified_file() {
    local path_value="$1"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$path_value" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
value = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("modified_files", [])
if value not in lst:
    lst.append(value)
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
}

record_manifest_backup() {
    local path_value="$1"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$path_value" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
value = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("backups", [])
if value not in lst:
    lst.append(value)
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
}

record_manifest_apply_report() {
    local msg="$1"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$msg" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
msg = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
data.setdefault("apply_report", []).append(msg)
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
}

ssh_root_login_status() {
    if [[ -f "$SSH_ROOT_LOGIN_DROPIN" ]]; then
        if grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+no[[:space:]]*$' "$SSH_ROOT_LOGIN_DROPIN"; then
            echo "configured"
            return 0
        fi
        echo "conflict"
        return 0
    fi
    echo "absent"
}

check_ssh_root_login_module() {
    local status
    status="$(ssh_root_login_status)"

    case "$status" in
        configured)
            add_safe "2.1.2 SSH root login disabled via drop-in: $SSH_ROOT_LOGIN_DROPIN"
            ;;
        absent)
            add_risky "2.1.2 SSH root login is not enforced yet: missing $SSH_ROOT_LOGIN_DROPIN"
            ;;
        conflict)
            add_risky "2.1.2 SSH root login drop-in exists but content is not 'PermitRootLogin no': $SSH_ROOT_LOGIN_DROPIN"
            ;;
        *)
            add_error "2.1.2 SSH root login status detection failed"
            ;;
    esac
}

apply_ssh_root_login_module() {
    local status
    status="$(ssh_root_login_status)"

    case "$status" in
        configured)
            add_safe "2.1.2 SSH root login already disabled: $SSH_ROOT_LOGIN_DROPIN"
            record_manifest_apply_report "2.1.2 already compliant: $SSH_ROOT_LOGIN_DROPIN"
            return 0
            ;;
        absent|conflict)
            ;;
        *)
            add_error "2.1.2 SSH root login status detection failed during apply"
            return 1
            ;;
    esac

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/ssh/sshd_config.d'"
        if [[ -f "$SSH_ROOT_LOGIN_DROPIN" ]]; then
            log "[DRY-RUN] backup '$SSH_ROOT_LOGIN_DROPIN' -> '$STATE_DIR/$(basename "$SSH_ROOT_LOGIN_DROPIN").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] write '$SSH_ROOT_LOGIN_DROPIN' with 'PermitRootLogin no'"
        log "[DRY-RUN] sshd -t"
        add_skipped "2.1.2 dry-run: SSH root login drop-in would be written"
        return 0
    fi

    mkdir -p /etc/ssh/sshd_config.d

    if [[ -f "$SSH_ROOT_LOGIN_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SSH_ROOT_LOGIN_DROPIN").bak-$TIMESTAMP"
        cp -a "$SSH_ROOT_LOGIN_DROPIN" "$backup_path"
        record_manifest_backup "$backup_path"
    fi

    printf '%s' "$SSH_ROOT_LOGIN_CONTENT" > "$SSH_ROOT_LOGIN_DROPIN"

    if sshd -t; then
        record_manifest_modified_file "$SSH_ROOT_LOGIN_DROPIN"
        record_manifest_apply_report "2.1.2 enforced via $SSH_ROOT_LOGIN_DROPIN"
        add_safe "2.1.2 SSH root login disabled via drop-in: $SSH_ROOT_LOGIN_DROPIN"
    else
        add_error "2.1.2 sshd -t failed after writing $SSH_ROOT_LOGIN_DROPIN"
        record_manifest_warning "2.1.2 sshd -t failed after writing $SSH_ROOT_LOGIN_DROPIN"
        return 1
    fi
}


pam_wheel_group_exists() {
    getent group wheel >/dev/null 2>&1
}

pam_wheel_rule_present() {
    [[ -f "$PAM_SU_FILE" ]] || return 1
    grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so([[:space:]]+.*)?[[:space:]]use_uid([[:space:]]+.*)?[[:space:]]group=wheel([[:space:]]+.*)?$' "$PAM_SU_FILE"
}

pam_wheel_managed_block_present() {
    [[ -f "$PAM_SU_FILE" ]] || return 1
    grep -Fq "$PAM_WHEEL_BLOCK_BEGIN" "$PAM_SU_FILE" && grep -Fq "$PAM_WHEEL_BLOCK_END" "$PAM_SU_FILE"
}

check_pam_wheel_module() {
    local group_ok=0
    local rule_ok=0

    pam_wheel_group_exists && group_ok=1 || true
    pam_wheel_rule_present && rule_ok=1 || true

    if (( group_ok == 1 && rule_ok == 1 )); then
        add_safe "2.2.1 su restricted via pam_wheel and group wheel"
        return 0
    fi

    if (( group_ok == 0 )); then
        add_risky "2.2.1 missing group wheel"
    fi
    if (( rule_ok == 0 )); then
        add_risky "2.2.1 missing active pam_wheel rule in $PAM_SU_FILE"
    fi
}

apply_pam_wheel_module() {
    local need_backup=0

    if pam_wheel_group_exists && pam_wheel_rule_present; then
        add_safe "2.2.1 su restriction already configured"
        record_manifest_apply_report "2.2.1 already compliant: wheel + pam_wheel"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        if ! pam_wheel_group_exists; then
            log "[DRY-RUN] groupadd wheel"
        fi
        if [[ -f "$PAM_SU_FILE" ]]; then
            log "[DRY-RUN] backup '$PAM_SU_FILE' -> '$STATE_DIR/$(basename "$PAM_SU_FILE").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] ensure managed pam_wheel block in '$PAM_SU_FILE'"
        add_skipped "2.2.1 dry-run: wheel group and pam_wheel rule would be enforced"
        return 0
    fi

    if ! pam_wheel_group_exists; then
        groupadd wheel
        python3 - "$MANIFEST_FILE" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("created_groups", [])
if "wheel" not in lst:
    lst.append("wheel")
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
        record_manifest_apply_report "2.2.1 created group wheel"
    fi

    [[ -f "$PAM_SU_FILE" ]] || die "Файл не найден: $PAM_SU_FILE"

    if [[ -f "$PAM_SU_FILE" ]]; then
        local backup_path="$STATE_DIR/$(basename "$PAM_SU_FILE").bak-$TIMESTAMP"
        cp -a "$PAM_SU_FILE" "$backup_path"
        record_manifest_backup "$backup_path"
        need_backup=1
    fi

    python3 - "$PAM_SU_FILE" <<'PYJSON'
import sys, pathlib, re
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
begin = "# BEGIN SecureLinux-NG 2.2.1"
end = "# END SecureLinux-NG 2.2.1"
line = "auth required pam_wheel.so use_uid group=wheel"
block = begin + "\n" + line + "\n" + end + "\n"

pattern = re.compile(r'(?ms)^# BEGIN SecureLinux-NG 2\.2\.1\n.*?^# END SecureLinux-NG 2\.2\.1\n?')
if pattern.search(text):
    text = pattern.sub(block, text)
else:
    if not text.endswith("\n"):
        text += "\n"
    text += "\n" + block

path.write_text(text, encoding='utf-8')
PYJSON

    if pam_wheel_rule_present; then
        record_manifest_modified_file "$PAM_SU_FILE"
        record_manifest_apply_report "2.2.1 enforced in $PAM_SU_FILE"
        add_safe "2.2.1 su restricted via pam_wheel and group wheel"
    else
        add_error "2.2.1 pam_wheel rule verification failed after update of $PAM_SU_FILE"
        record_manifest_warning "2.2.1 pam_wheel rule verification failed after update of $PAM_SU_FILE"
        return 1
    fi
}

require_cmds() {
    local missing=()
    local cmd
    for cmd in bash python3 stat uname grep awk date mkdir cat systemctl; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    (( ${#missing[@]} == 0 )) || die "Отсутствуют обязательные команды: ${missing[*]}"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help)
                usage
                exit 0
                ;;
            --version)
                echo "securelinux-ng.sh v${SCRIPT_VERSION}"
                exit 0
                ;;
            --check|--apply|--restore|--report)
                [[ -z "$MODE" ]] || die "Нельзя указывать несколько режимов одновременно"
                MODE="${1#--}"
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --profile)
                shift
                [[ $# -gt 0 ]] || die "После --profile требуется значение"
                PROFILE="$1"
                ;;
            --profile=*)
                PROFILE="${1#*=}"
                ;;
            --config)
                shift
                [[ $# -gt 0 ]] || die "После --config требуется путь к файлу"
                CONFIG_FILE="$1"
                ;;
            --config=*)
                CONFIG_FILE="${1#*=}"
                ;;
            *)
                die "Неизвестный аргумент: $1"
                ;;
        esac
        shift
    done
}

validate_args() {
    [[ -n "$MODE" ]] || die "Нужно указать один режим: --check | --apply | --restore | --report"

    case "$PROFILE" in
        baseline|strict|paranoid) ;;
        *) die "Недопустимый профиль: $PROFILE" ;;
    esac

    if (( DRY_RUN == 1 )) && [[ "$MODE" != "apply" ]]; then
        die "--dry-run допустим только вместе с --apply"
    fi

    if [[ -n "$CONFIG_FILE" ]] && [[ ! -f "$CONFIG_FILE" ]]; then
        die "Файл конфига не найден: $CONFIG_FILE"
    fi
}

load_config() {
    [[ -n "$CONFIG_FILE" ]] || return 0

    python3 - "$CONFIG_FILE" <<'PYCFG'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
for n, line in enumerate(text.splitlines(), 1):
    s = line.strip()
    if not s or s.startswith('#'):
        continue
    if '=' not in s:
        print(f"CONFIG_ERROR:{n}: нет '='")
        raise SystemExit(2)
    k, v = s.split('=', 1)
    k = k.strip()
    if not k or ' ' in k:
        print(f"CONFIG_ERROR:{n}: плохой ключ")
        raise SystemExit(2)
PYCFG

    while IFS='=' read -r k v; do
        [[ -n "${k:-}" ]] || continue
        case "$k" in
            PROFILE)
                [[ "$PROFILE" == "baseline" ]] && PROFILE="$v"
                ;;
            STATE_DIR)
                STATE_DIR="$v"
                ;;
            REPORT_FILE)
                REPORT_FILE="$v"
                ;;
            MANIFEST_FILE)
                MANIFEST_FILE="$v"
                ;;
            *)
                add_warning "Неизвестный ключ в config пропущен: $k"
                ;;
        esac
    done < <(python3 - "$CONFIG_FILE" <<'PYCFG'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
for line in path.read_text(encoding='utf-8').splitlines():
    s = line.strip()
    if not s or s.startswith('#') or '=' not in s:
        continue
    k, v = s.split('=', 1)
    print(f"{k.strip()}={v.strip()}")
PYCFG
)
}

finalize_paths() {
    REPORT_FILE="${REPORT_FILE:-$STATE_DIR/report-${TIMESTAMP}.json}"
    MANIFEST_FILE="${MANIFEST_FILE:-$STATE_DIR/manifest-${TIMESTAMP}.json}"
}

detect_os() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION_ID="${VERSION_ID:-unknown}"
    else
        DISTRO_ID="unknown"
        DISTRO_VERSION_ID="unknown"
    fi

    case "$DISTRO_ID" in
        ubuntu|debian) OS_FAMILY="debian" ;;
        *) OS_FAMILY="unknown" ;;
    esac
}

detect_environment() {
    [[ -f /.dockerenv ]] && IS_CONTAINER=1
    grep -qaE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null && IS_CONTAINER=1 || true

    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]] || [[ -n "${DESKTOP_SESSION:-}" ]]; then
        IS_DESKTOP=1
    elif systemctl is-active display-manager >/dev/null 2>&1; then
        IS_DESKTOP=1
    fi

    command -v docker >/dev/null 2>&1 && HAS_DOCKER=1 || true
    command -v podman >/dev/null 2>&1 && HAS_PODMAN=1 || true
    [[ -d /etc/kubernetes || -f /etc/rancher/k3s/k3s.yaml || -f /var/lib/kubelet/config.yaml ]] && HAS_K8S=1 || true
}

run_preflight() {
    detect_os
    detect_environment

    [[ "$OS_FAMILY" == "debian" ]] && add_safe "Поддерживаемое семейство ОС: $DISTRO_ID $DISTRO_VERSION_ID" || add_risky "Неподдерживаемое/непроверенное семейство ОС: $DISTRO_ID $DISTRO_VERSION_ID"

    (( IS_CONTAINER == 1 )) && add_policy_gate "Обнаружен контейнер: часть hardening-мер должна быть автоматически запрещена"
    (( IS_DESKTOP == 1 )) && add_policy_gate "Обнаружен desktop-mode: часть серверных мер требует отдельной политики"
    (( HAS_DOCKER == 1 )) && add_policy_gate "Обнаружен Docker: сетевые/sysctl-меры нужно маркировать как compatibility-sensitive"
    (( HAS_PODMAN == 1 )) && add_policy_gate "Обнаружен Podman: проверять совместимость namespace/cgroup/sysctl"
    (( HAS_K8S == 1 )) && add_policy_gate "Обнаружен Kubernetes node: kernel/network hardening применять только по политике"

    add_skipped "Hardening-модули пока не реализованы: это только framework-скелет"
}

ensure_state_dir() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '$STATE_DIR'"
        return 0
    fi
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
}

manifest_init() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] создать manifest: $MANIFEST_FILE"
        return 0
    fi

    python3 - "$MANIFEST_FILE" "$SCRIPT_VERSION" "$PROFILE" "$MODE" <<'PYJSON'
import sys, json, datetime, pathlib
path = pathlib.Path(sys.argv[1])
data = {
    "version": sys.argv[2],
    "profile": sys.argv[3],
    "mode": sys.argv[4],
    "timestamp": datetime.datetime.now().isoformat(),
    "backups": [],
    "created_files": [],
    "created_groups": [],
    "modified_files": [],
    "systemd_units": [],
    "sysctl_configs": [],
    "grub_backups": [],
    "apply_report": [],
    "warnings": [],
    "irreversible_changes": []
}
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
}

write_report() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] создать report: $REPORT_FILE"
        return 0
    fi

    python3 - "$REPORT_FILE" "$SCRIPT_VERSION" "$PROFILE" "$MODE" "$DISTRO_ID" "$DISTRO_VERSION_ID" "$OS_FAMILY" "$IS_CONTAINER" "$IS_DESKTOP" "$HAS_DOCKER" "$HAS_PODMAN" "$HAS_K8S" "$(printf '%s
' "${SAFE_ITEMS[@]}")" "$(printf '%s
' "${RISKY_ITEMS[@]}")" "$(printf '%s
' "${SKIPPED_ITEMS[@]}")" "$(printf '%s
' "${POLICY_GATES[@]}")" "$(printf '%s
' "${WARNINGS[@]}")" "$(printf '%s
' "${ERRORS[@]}")" <<'PYJSON'
import sys, json, pathlib, datetime
path = pathlib.Path(sys.argv[1])

def split_lines(s):
    return [x for x in s.splitlines() if x.strip()]

data = {
    "version": sys.argv[2],
    "profile": sys.argv[3],
    "mode": sys.argv[4],
    "timestamp": datetime.datetime.now().isoformat(),
    "environment": {
        "distro_id": sys.argv[5],
        "distro_version_id": sys.argv[6],
        "os_family": sys.argv[7],
        "is_container": sys.argv[8] == "1",
        "is_desktop": sys.argv[9] == "1",
        "has_docker": sys.argv[10] == "1",
        "has_podman": sys.argv[11] == "1",
        "has_kubernetes": sys.argv[12] == "1",
    },
    "safe": split_lines(sys.argv[13]),
    "risky": split_lines(sys.argv[14]),
    "skipped": split_lines(sys.argv[15]),
    "requires_confirmed_policy": split_lines(sys.argv[16]),
    "warnings": split_lines(sys.argv[17]),
    "errors": split_lines(sys.argv[18]),
}
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
PYJSON
}

print_report_stdout() {
    if (( DRY_RUN == 1 )); then
        echo "version: ${SCRIPT_VERSION}"
        echo "profile: ${PROFILE}"
        echo "mode: ${MODE}"
        echo "os: ${DISTRO_ID} ${DISTRO_VERSION_ID} (${OS_FAMILY})"
        echo "container: $([[ ${IS_CONTAINER} -eq 1 ]] && echo true || echo false)"
        echo "desktop: $([[ ${IS_DESKTOP} -eq 1 ]] && echo true || echo false)"
        echo "docker: $([[ ${HAS_DOCKER} -eq 1 ]] && echo true || echo false)"
        echo "podman: $([[ ${HAS_PODMAN} -eq 1 ]] && echo true || echo false)"
        echo "kubernetes: $([[ ${HAS_K8S} -eq 1 ]] && echo true || echo false)"
        echo "safe: ${#SAFE_ITEMS[@]}"
        echo "risky: ${#RISKY_ITEMS[@]}"
        echo "skipped: ${#SKIPPED_ITEMS[@]}"
        echo "requires_confirmed_policy: ${#POLICY_GATES[@]}"
        echo "warnings: ${#WARNINGS[@]}"
        echo "errors: ${#ERRORS[@]}"
        return 0
    fi

    python3 - "$REPORT_FILE" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print(f"[FAIL] report не найден: {path}")
    raise SystemExit(1)
data = json.loads(path.read_text(encoding='utf-8'))
print(f"version: {data['version']}")
print(f"profile: {data['profile']}")
print(f"mode: {data['mode']}")
env = data["environment"]
print(f"os: {env['distro_id']} {env['distro_version_id']} ({env['os_family']})")
print(f"container: {env['is_container']}")
print(f"desktop: {env['is_desktop']}")
print(f"docker: {env['has_docker']}")
print(f"podman: {env['has_podman']}")
print(f"kubernetes: {env['has_kubernetes']}")
for key in ("safe", "risky", "skipped", "requires_confirmed_policy", "warnings", "errors"):
    print(f"{key}: {len(data.get(key, []))}")
PYJSON
}

run_check_mode() {
    log "[i] Режим check"
    run_preflight
    check_ssh_root_login_module
    check_pam_wheel_module
    ensure_state_dir
    write_report
    print_report_stdout
}

run_apply_mode() {
    log "[i] Режим apply"
    run_preflight
    ensure_state_dir
    manifest_init

    apply_ssh_root_login_module
    apply_pam_wheel_module

    write_report
    print_report_stdout
}

run_restore_mode() {
    log "[i] Режим restore"
    run_preflight
    ensure_state_dir
    manifest_init

    add_skipped "Restore framework активирован, но restore-обработчики ещё не подключены"
    add_warning "Автоматический откат пока не выполнялся"

    write_report
    print_report_stdout
}

run_report_mode() {
    log "[i] Режим report"
    run_preflight
    ensure_state_dir
    write_report
    print_report_stdout
}

main() {
    require_cmds
    parse_args "$@"
    validate_args
    load_config
    validate_args
    finalize_paths

    case "$MODE" in
        check) run_check_mode ;;
        apply) run_apply_mode ;;
        restore) run_restore_mode ;;
        report) run_report_mode ;;
        *) die "Внутренняя ошибка: неизвестный режим '$MODE'" ;;
    esac
}

main "$@"
