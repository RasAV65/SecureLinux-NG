#!/usr/bin/env bash
# securelinux-ng.sh
# Version: 16.2.8
# Project: SecureLinux-NG
# https://github.com/rasav65/SecureLinux-NG

SCRIPT_VERSION="16.2.8"

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=""
DRY_RUN=0
PROFILE="baseline"
_PROFILE_SET_BY_CLI=0
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
USER_NAMESPACES_LIMIT=""
_APT_UPDATED=0  # флаг: 1 = apt-get update уже выполнен в этом сеансе
HAS_PODMAN=0
HAS_K8S=0

SSH_ROOT_LOGIN_DROPIN="/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf"
SSH_ROOT_LOGIN_CONTENT=$'# Managed by SecureLinux-NG\nPermitRootLogin no\n'

SSH_HARDENING_DROPIN="/etc/ssh/sshd_config.d/61-securelinux-ng-ssh-hardening.conf"
# baseline: базовые параметры (все профили)
SSH_HARDENING_BASELINE=$'# Managed by SecureLinux-NG — SSH hardening baseline (ФСТЭК 2.1.2)\n'
SSH_HARDENING_BASELINE+=$'X11Forwarding no\n'
SSH_HARDENING_BASELINE+=$'MaxAuthTries 3\n'
SSH_HARDENING_BASELINE+=$'MaxSessions 2\n'
SSH_HARDENING_BASELINE+=$'PermitEmptyPasswords no\n'
SSH_HARDENING_BASELINE+=$'UseDNS no\n'
SSH_HARDENING_BASELINE+=$'GSSAPIAuthentication no\n'
SSH_HARDENING_BASELINE+=$'ClientAliveInterval 300\n'
SSH_HARDENING_BASELINE+=$'ClientAliveCountMax 2\n'
SSH_HARDENING_BASELINE+=$'LoginGraceTime 30\n'
SSH_HARDENING_BASELINE+=$'AllowAgentForwarding no\n'
SSH_HARDENING_BASELINE+=$'AllowTcpForwarding no\n'
SSH_HARDENING_BASELINE+=$'IgnoreRhosts yes\n'
SSH_HARDENING_BASELINE+=$'HostbasedAuthentication no\n'
SSH_HARDENING_BASELINE+=$'LogLevel VERBOSE\n'
# strict+: криптографические алгоритмы (источник: fortress_improved.sh / captainzero93)
SSH_HARDENING_STRICT=$'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n'
SSH_HARDENING_STRICT+=$'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n'
SSH_HARDENING_STRICT+=$'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\n'
SSH_HARDENING_STRICT+=$'Compression no\n'
SSH_HARDENING_STRICT+=$'Banner /etc/issue.net\n'

PAM_SU_FILE="/etc/pam.d/su"
PAM_WHEEL_BLOCK_BEGIN="# BEGIN SecureLinux-NG 2.2.1"
PAM_WHEEL_BLOCK_END="# END SecureLinux-NG 2.2.1"
PAM_WHEEL_LINE="auth required pam_wheel.so use_uid group=wheel"

FAILLOCK_CONF="/etc/security/faillock.conf"
# baseline: pam_faillock не применяется
# strict+: deny=5 unlock_time=900 (5 попыток, блокировка 15 мин)
FAILLOCK_CONF_BASELINE=""
FAILLOCK_CONF_STRICT=$'# Managed by SecureLinux-NG — pam_faillock strict+ (корпоративный стандарт 4.4)\naudit\ndeny = 5\nunlock_time = 900\nfail_interval = 900\neven_deny_root\n'

PWQUALITY_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"
# baseline: minlen=15, minclass=4
# strict+:  minlen=16, minclass=4, maxrepeat=2
PWQUALITY_BASELINE=$'# Managed by SecureLinux-NG — pwquality (ФСТЭК 2.1.x)\nminlen = 15\nminclass = 4\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\nreject_username = 1\nenforce_for_root = 1\nretry = 3\n'
PWQUALITY_STRICT=$'# Managed by SecureLinux-NG — pwquality strict (ФСТЭК 2.1.x)\nminlen = 16\nminclass = 4\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\nmaxrepeat = 2\nreject_username = 1\nenforce_for_root = 1\nretry = 3\n'
# login.defs aging: baseline max=90, strict max=60, paranoid max=45
PASS_MAX_DAYS_BASELINE=90
PASS_MAX_DAYS_STRICT=60
PASS_MAX_DAYS_PARANOID=45
PASS_MIN_DAYS=7
PASS_WARN_AGE=14

AUDITD_RULES_DIR="/etc/audit/rules.d"
AUDITD_BASELINE_RULES="${AUDITD_RULES_DIR}/60-securelinux-ng.rules"
AUDITD_STRICT_RULES="${AUDITD_RULES_DIR}/61-securelinux-ng-extended.rules"

UFW_SSH_PORT="22"  # переопределяется из sshd_config если найден
UFW_EXTRA_RULES=""  # дополнительные правила ufw, формат: "15000/udp:Kaspersky 8080/tcp:Proxy"

SUDO_POLICY_DROPIN="/etc/sudoers.d/60-securelinux-ng-policy"
SUDO_POLICY_CONTENT=$'# Managed by SecureLinux-NG\n%wheel ALL=(ALL:ALL) ALL\nDefaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=5\nDefaults passwd_tries=3\nDefaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'

SYSCTL_KERNEL_DROPIN="/etc/sysctl.d/60-securelinux-ng-kernel.conf"
SYSCTL_KERNEL_CONTENT=$'# Managed by SecureLinux-NG\nkernel.dmesg_restrict = 1\nkernel.kptr_restrict = 2\nnet.core.bpf_jit_harden = 2\n'

SYSCTL_ATTACK_SURFACE_DROPIN="/etc/sysctl.d/61-securelinux-ng-attack-surface.conf"
SYSCTL_ATTACK_SURFACE_CONTENT=$'# Managed by SecureLinux-NG\nkernel.perf_event_paranoid = 3\nkernel.kexec_load_disabled = 1\nkernel.unprivileged_bpf_disabled = 1\nvm.unprivileged_userfaultfd = 0\ndev.tty.ldisc_autoload = 0\nvm.mmap_min_addr = 4096\nkernel.randomize_va_space = 2\nuser.max_user_namespaces = 0\n'

SYSCTL_USERSPACE_PROTECTION_DROPIN="/etc/sysctl.d/99-securelinux-ng-userspace-protection.conf"
SYSCTL_USERSPACE_PROTECTION_CONTENT=$'# Managed by SecureLinux-NG\nfs.protected_symlinks = 1\nfs.protected_hardlinks = 1\nfs.protected_fifos = 2\nfs.protected_regular = 2\nfs.suid_dumpable = 0\n'

SYSCTL_NETWORK_DROPIN="/etc/sysctl.d/62-securelinux-ng-network.conf"
SYSCTL_MODULES_DISABLED_DROPIN="/etc/sysctl.d/63-securelinux-ng-modules-disabled.conf"
COREDUMP_LIMITS_FILE="/etc/security/limits.d/99-securelinux-ng-coredump.conf"
COREDUMP_SYSTEMD_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_SYSTEMD_FILE="/etc/systemd/coredump.conf.d/99-securelinux-ng.conf"
SYSCTL_NETWORK_CONTENT=$'# Managed by SecureLinux-NG\n# Сетевая защита (п.8.1-8.3 Стандарта)\nnet.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\nnet.ipv4.tcp_syn_retries = 3\n'

RESTORE_MANIFEST=""
RESTORE_SOURCE_MANIFEST=""

FS_CRITICAL_FILES=("/etc/passwd" "/etc/group" "/etc/shadow")
CRON_CRITICAL_TARGETS=(
    "/etc/crontab:file:600:root:root"
    "/etc/cron.d:dir:700:root:root"
    "/etc/cron.hourly:dir:700:root:root"
    "/etc/cron.daily:dir:700:root:root"
    "/etc/cron.weekly:dir:700:root:root"
    "/etc/cron.monthly:dir:700:root:root"
)

SYSTEMD_ETC_DIR="/etc/systemd/system"
SYSTEMD_UNIT_SUFFIXES=("service" "socket" "timer" "mount" "path" "target" "slice")

RUNTIME_PATHS_SAMPLE_LIMIT=20
SUDO_COMMANDS_SAMPLE_LIMIT=20

GRUB_KERNEL_REQUIRED_PARAMS=(
    "init_on_alloc=1"
    "slab_nomerge"
    "iommu=force"
    "iommu.strict=1"
    "iommu.passthrough=0"
    "randomize_kstack_offset=1"
    "mitigations=auto,nosmt"
    "vsyscall=none"
    "debugfs=off"
    "tsx=off"
)

HOME_SENSITIVE_FILE_NAMES=(
    ".bash_history"
    ".history"
    ".sh_history"
    ".bash_profile"
    ".bashrc"
    ".profile"
    ".bash_logout"
    ".rhosts"
)

USER_CRON_DIRS=(
    "/var/spool/cron"
    "/var/spool/cron/crontabs"
)

STANDARD_SYSTEM_PATH_CANDIDATES=(
    "/bin"
    "/sbin"
    "/usr/bin"
    "/usr/sbin"
    "/lib"
    "/lib64"
    "/usr/lib"
    "/usr/lib64"
)

declare -a WARNINGS=()
declare -a ERRORS=()
declare -a SAFE_ITEMS=()
declare -a RISKY_ITEMS=()
declare -a SKIPPED_ITEMS=()
declare -a POLICY_GATES=()
FSTEC_TOTAL_ITEMS=60      # всего позиций в реестре (включая not_applicable)
FSTEC_IMPLEMENTED_ITEMS=59 # реализовано (TOTAL минус not_applicable)
FSTEC_DONE_ITEMS=41    # синхронизировать при изменении статусов
FSTEC_PARTIAL_ITEMS=18  # синхронизировать при изменении статусов

usage() {
    cat <<'EOF'
Usage:
  ./securelinux-ng.sh --help
  ./securelinux-ng.sh --version
  ./securelinux-ng.sh --check [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --apply [--dry-run] [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --restore [--manifest FILE] [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --report [--profile PROFILE] [--config FILE]

Modes:
  --check           Read-only analysis of current state
  --apply           Apply configured hardening modules
  --restore         Restore from manifest/backups
  --report          Print framework report JSON

Options:
  --dry-run         Show what would be done (valid with --apply only)
  --profile NAME    baseline | strict | paranoid
  --config FILE     External config file
  --manifest FILE   Manifest to restore from
  --help            Show help
  --version         Show version
EOF
}

log() {
    local msg
    msg="$(printf '[%s] %s' "$(date '+%F %T %z')" "$*")"
    printf '%s
' "$msg"
    if [[ -n "${LOG_FILE:-}" && -d "$(dirname "$LOG_FILE")" ]]; then
        printf '%s
' "$msg" >> "$LOG_FILE"
    fi
}

log_debug() {
    [[ -n "${DEBUG_LOG_FILE:-}" ]] || return 0
    printf '[%s] [DEBUG] %s
' "$(date '+%F %T %z')" "$*" >> "$DEBUG_LOG_FILE"
}

die() {
    log "[FAIL]  $*"
    exit 1
}

add_warning() { WARNINGS+=("$1"); log "[WARN]  $1"; }
add_error() { ERRORS+=("$1"); log "[ERROR] $1"; }
add_safe() { SAFE_ITEMS+=("$1"); log "[OK]    $1"; }
add_risky() { RISKY_ITEMS+=("$1"); log "[RISKY] $1"; }
add_skipped() { SKIPPED_ITEMS+=("$1"); log "[SKIP]  $1"; }
add_policy_gate() { POLICY_GATES+=("$1"); }

# backup_file_checked SRC DST CTX — создаёт backup с проверкой успеха cp
backup_file_checked() {
    local src="$1" dst="$2" ctx="${3:-backup}"
    if ! cp -a "$src" "$dst"; then
        add_warning "$ctx: не удалось создать backup $src -> $dst"
        record_manifest_warning "$ctx: backup failed: $src -> $dst"
        return 1
    fi
    return 0
}

# acquire_run_lock — защита от параллельного запуска apply/restore через flock
acquire_run_lock() {
    local lockfile="$STATE_DIR/securelinux-ng.lock"
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] acquire lock: '$lockfile'"
        return 0
    fi
    exec 9>"$lockfile"
    if ! flock -n 9; then
        die "Другой экземпляр securelinux-ng уже выполняется (lock: $lockfile)"
    fi
}

# profile_allows LEVEL — возвращает 0 (true) если текущий профиль >= LEVEL
# LEVEL: baseline | strict | paranoid
profile_allows() {
    local required="$1"
    case "$required" in
        baseline) return 0 ;;
        strict)
            case "$PROFILE" in
                strict|paranoid) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        paranoid)
            [[ "$PROFILE" == "paranoid" ]] && return 0 || return 1
            ;;
        *) return 1 ;;
    esac
}

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
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
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
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

record_manifest_backup() {
    local original_path="$1"
    local backup_path="$2"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$original_path" "$backup_path" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
original = sys.argv[2]
backup = sys.argv[3]
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("backups", [])
entry = {"original": original, "backup": backup}
if entry not in lst:
    lst.append(entry)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

manifest_has_backup_for() {
    local original_path="$1"
    [[ -n "${MANIFEST_FILE:-}" && -f "${MANIFEST_FILE:-}" ]] || return 1
    python3 - "$MANIFEST_FILE" "$original_path" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for entry in data.get("backups", []):
    if isinstance(entry, dict) and entry.get("original") == sys.argv[2]:
        raise SystemExit(0)
raise SystemExit(1)
PYJSON
}

record_manifest_created_file() {
    local path_value="$1"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$path_value" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
value = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("created_files", [])
if value not in lst:
    lst.append(value)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
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
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

record_manifest_irreversible_change() {
    local msg="$1"
    [[ -n "${MANIFEST_FILE:-}" ]] || return 0
    (( DRY_RUN == 1 )) && return 0
    [[ -f "$MANIFEST_FILE" ]] || return 0
    python3 - "$MANIFEST_FILE" "$msg" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
msg = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
data.setdefault("irreversible_changes", []).append(msg)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

runtime_paths_scan() {
    python3 - <<'PYJSON'
from pathlib import Path
import os

proc_root = Path(os.environ.get("SECURELINUX_NG_RUNTIME_PROC_ROOT", "/proc"))
read_maps = os.environ.get("SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS", "1") not in {"0", "false", "False", "no", "NO"}
seen = set()

if not proc_root.is_dir():
    raise SystemExit(0)

for proc in proc_root.iterdir():
    if not proc.name.isdigit():
        continue

    exe = proc / "exe"
    try:
        if exe.exists() or exe.is_symlink():
            target = os.path.realpath(exe)
            if target.startswith("/") and os.path.isfile(target):
                seen.add(target)
    except Exception:
        pass

    if not read_maps:
        continue

    maps = proc / "maps"
    try:
        for line in maps.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "/" not in line:
                continue
            path = line.rsplit(None, 1)[-1]
            if path.startswith("/") and os.path.isfile(path):
                seen.add(os.path.realpath(path))
    except Exception:
        pass

for item in sorted(seen):
    print(item)
PYJSON
}

check_runtime_paths_module() {
    python3 - <<'PYJSON'
from pathlib import Path
import os, stat

sample_limit = 20
proc_root = Path(os.environ.get("SECURELINUX_NG_RUNTIME_PROC_ROOT", "/proc"))
read_maps = os.environ.get("SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS", "1") not in {"0", "false", "False", "no", "NO"}
paths = []
seen = set()

if proc_root.is_dir():
    for proc in proc_root.iterdir():
        if not proc.name.isdigit():
            continue

        exe = proc / "exe"
        try:
            if exe.exists() or exe.is_symlink():
                target = os.path.realpath(exe)
                if target.startswith("/") and os.path.isfile(target) and target not in seen:
                    seen.add(target)
                    paths.append(target)
        except Exception:
            pass

        if not read_maps:
            continue

        maps = proc / "maps"
        try:
            for line in maps.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "/" not in line:
                    continue
                path = line.rsplit(None, 1)[-1]
                if path.startswith("/") and os.path.isfile(path):
                    path = os.path.realpath(path)
                    if path not in seen:
                        seen.add(path)
                        paths.append(path)
        except Exception:
            pass

ok = 0
risky = 0
samples = []

EXCLUDED_PARENTS = {"/var/log", "/tmp", "/var/tmp", "/run", "/dev/shm"}
for item in sorted(paths):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        if str(cur) in EXCLUDED_PARENTS:
            break
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception:
            reasons.append(f"parent_stat_failed:{cur}")
            break

        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{len(paths)}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

check_sudo_command_paths_module() {
    python3 - "$SUDO_COMMANDS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, re, stat, sys

sample_limit = int(sys.argv[1])
EXCLUDED_PARENTS = {"/var/log", "/tmp", "/var/tmp", "/run", "/dev/shm"}
sudo_files = [Path("/etc/sudoers")]
sudoers_d = Path("/etc/sudoers.d")
if sudoers_d.is_dir():
    sudo_files.extend(sorted(p for p in sudoers_d.iterdir() if p.is_file()))

paths = []
seen = set()
token_re = re.compile(r'(/[A-Za-z0-9_./+-]+)')

for cfg in sudo_files:
    try:
        text = cfg.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for m in token_re.findall(s):
            path = os.path.realpath(m)
            if path.startswith("/") and os.path.exists(path) and path not in seen:
                seen.add(path)
                paths.append(path)

ok = 0
risky = 0
samples = []

for item in sorted(paths):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if os.path.isfile(item) and stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        if str(cur) in EXCLUDED_PARENTS:
            break
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception:
            reasons.append(f"parent_stat_failed:{cur}")
            break

        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{len(paths)}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

apply_runtime_paths_module() {
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.2 runtime scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.2 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_runtime_paths_module)
        add_skipped "2.3.2 dry-run: runtime executable/library permission remediation is policy-gated"
        return 0
    fi
    local item reason
    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.2 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
            continue
        fi
        [[ -f "$item" ]] || continue
        local backup_path="$STATE_DIR/runtime.$(echo "$item" | tr '/' '_').meta-$TIMESTAMP.txt"
        write_metadata_snapshot "$item" "$backup_path"
        record_manifest_backup "$item" "$backup_path"
        chmod go-w "$item" && {
            record_manifest_modified_file "$item"
            record_manifest_apply_report "2.3.2 chmod go-w: $item"
        } || add_warning "2.3.2 chmod go-w failed: $item"
    done < <(check_runtime_paths_module)
    add_safe "2.3.2 runtime executable/library permissions processed"
}

record_sudo_command_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.4 sudo command paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.4 sudo command paths checked: total=$total ok=$ok risky=$risky"
    fi
}

sysctl_kernel_check_module() {
    python3 - <<'PYJSON'
import subprocess

targets = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "net.core.bpf_jit_harden": "2",
}

ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(
            ["sysctl", "-n", key],
            text=True,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue

    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")

print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_kernel_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.4 sysctl kernel protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.4 sysctl kernel protections checked: total=$total ok=$ok risky=$risky"
    fi
}

grub_kernel_params_check_module() {
    local profile_arg="${1:-baseline}"
    python3 - "$profile_arg" <<'PYJSON'
import sys
from pathlib import Path

profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"

required = [
    "init_on_alloc=1",
    "slab_nomerge",
    "iommu=force",
    "iommu.strict=1",
    "iommu.passthrough=0",
    "randomize_kstack_offset=1",
    "mitigations=auto,nosmt",
    "vsyscall=none",
    "debugfs=off",
    "tsx=off",
]

if profile in ("strict", "paranoid"):
    required += ["apparmor=1", "security=apparmor"]

cmdline = Path("/proc/cmdline").read_text(encoding="utf-8", errors="ignore").strip()
tokens = cmdline.split()

ok = 0
risky = 0
for item in required:
    if item in tokens:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{item}\tmissing_in_proc_cmdline (requires_reboot)")

print(f"SUMMARY\t{len(required)}\t{ok}\t{risky}")
PYJSON
}

record_grub_kernel_params_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.4 grub kernel params checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.4 grub kernel params checked: total=$total ok=$ok risky=$risky (параметры вступят в силу после перезагрузки)"
    fi
}

sysctl_attack_surface_check_module() {
    local profile_arg="${1:-baseline}"
    python3 - "$profile_arg" "$USER_NAMESPACES_LIMIT" <<'PYJSON'
import subprocess, sys
profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"
profile_order = {"baseline": 0, "strict": 1, "paranoid": 2}
profile_level = profile_order.get(profile, 0)

targets_all = {
    "kernel.perf_event_paranoid": ("3", "baseline"),  # ФСТЭК 2.5.2 — все профили
    "kernel.kexec_load_disabled": ("1", "baseline"),
    "kernel.unprivileged_bpf_disabled": ("1", "baseline"),  # ФСТЭК 2.5.6 — все профили
    "vm.unprivileged_userfaultfd": ("0", "baseline"),
    "dev.tty.ldisc_autoload": ("0", "baseline"),
    "vm.mmap_min_addr": ("4096", "baseline"),
    "kernel.randomize_va_space": ("2", "baseline"),
    "user.max_user_namespaces": ("0", "baseline"),
}
_ns_limit = sys.argv[2].strip() if len(sys.argv) > 2 else ""
if _ns_limit == "":
    try:
        current_ns = subprocess.check_output(
            ["sysctl", "-n", "user.max_user_namespaces"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        current_ns = ""
    if current_ns in {"0", "10000"}:
        targets_all["user.max_user_namespaces"] = (current_ns, "baseline")
    else:
        targets_all["user.max_user_namespaces"] = ("0", "baseline")
else:
    targets_all["user.max_user_namespaces"] = (_ns_limit, "baseline")
targets = {k: v[0] for k, v in targets_all.items() if profile_order.get(v[1], 0) <= profile_level}

ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(
            ["sysctl", "-n", key],
            text=True,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue

    if key in ("vm.mmap_min_addr", "kernel.unprivileged_bpf_disabled"):
        try:
            if int(value) >= int(expected):
                ok += 1
            else:
                risky += 1
                print(f"RISK\t{key}\texpected>={expected},actual={value}")
        except Exception:
            risky += 1
            print(f"RISK\t{key}\tbad_value:{value}")
        continue

    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")

print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_attack_surface_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.5 sysctl attack-surface protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.5 sysctl attack-surface protections checked: total=$total ok=$ok risky=$risky"
    fi
}

sysctl_userspace_protection_check_module() {
    local profile_arg="${1:-baseline}"
    python3 - "$profile_arg" <<'PYJSON'
import subprocess, sys
profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"
profile_order = {"baseline": 0, "strict": 1, "paranoid": 2}
profile_level = profile_order.get(profile, 0)

import os
targets_all_base = {
    "fs.protected_symlinks": ("1", "baseline"),
    "fs.protected_hardlinks": ("1", "baseline"),
    "fs.protected_fifos": ("2", "baseline"),
    "fs.protected_regular": ("2", "baseline"),
    "fs.suid_dumpable": ("0", "baseline"),
}
if os.path.exists("/proc/sys/kernel/yama/ptrace_scope"):
    targets_all_base["kernel.yama.ptrace_scope"] = ("3", "baseline")  # ФСТЭК 2.6.1
targets = {k: v[0] for k, v in targets_all_base.items() if profile_order.get(v[1], 0) <= profile_level}

ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(
            ["sysctl", "-n", key],
            text=True,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue

    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")

print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_userspace_protection_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.6 sysctl userspace protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.6 sysctl userspace protections checked: total=$total ok=$ok risky=$risky"
    fi
}

home_targets_scan() {
    python3 - <<'PYJSON'
from pathlib import Path
import os
home = Path(os.environ.get("SECURELINUX_NG_HOME_BASE_DIR", "/home"))
if not home.is_dir():
    raise SystemExit(0)
for p in sorted(home.iterdir()):
    if p.is_dir() and not p.is_symlink():
        print(p)
PYJSON
}

check_home_permissions_module() {
    python3 - <<'PYJSON'
from pathlib import Path
import os, stat

sensitive = {
    ".bash_history",
    ".history",
    ".sh_history",
    ".bash_profile",
    ".bashrc",
    ".profile",
    ".bash_logout",
    ".rhosts",
}

home = Path(os.environ.get("SECURELINUX_NG_HOME_BASE_DIR", "/home"))
if not home.is_dir():
    print("SUMMARY\t0\t0\t0")
    raise SystemExit(0)

ok = 0
risky = 0

for d in sorted(home.iterdir()):
    if not d.is_dir() or d.is_symlink():
        continue

    try:
        mode = stat.S_IMODE(os.stat(d).st_mode)
        if mode == 0o700:
            ok += 1
        else:
            risky += 1
            print(f"RISK\t{d}\thome_mode_expected=700,actual={mode:o}")
    except Exception as e:
        risky += 1
        print(f"RISK\t{d}\thome_stat_failed:{e}")

    for name in sensitive:
        f = d / name
        if not f.exists() or not f.is_file():
            continue
        try:
            mode = stat.S_IMODE(os.stat(f).st_mode)
            if mode & 0o077:
                risky += 1
                print(f"RISK\t{f}\tfile_go_perms_present:{mode:o}")
            else:
                ok += 1
        except Exception as e:
            risky += 1
            print(f"RISK\t{f}\tfile_stat_failed:{e}")

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
PYJSON
}

record_home_permissions_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.10/2.3.11 home permissions checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.10/2.3.11 home permissions checked: total=$total ok=$ok risky=$risky"
    fi
}

check_user_cron_permissions_module() {
    python3 - <<'PYJSON'
from pathlib import Path
import os, stat

roots = [Path(p) for p in os.environ.get("SECURELINUX_NG_USER_CRON_DIRS", "/var/spool/cron:/var/spool/cron/crontabs").split(":") if p]
files = []
seen = set()

for root in roots:
    if not root.is_dir():
        continue
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                files.append(Path(rp))

ok = 0
risky = 0
for f in sorted(files):
    try:
        mode = stat.S_IMODE(os.stat(f).st_mode)
        if mode & 0o022:
            risky += 1
            print(f"RISK\t{f}\tcron_user_file_go_w:{mode:o}")
        else:
            ok += 1
    except Exception as e:
        risky += 1
        print(f"RISK\t{f}\tcron_user_file_stat_failed:{e}")

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
PYJSON
}

record_user_cron_permissions_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.7 user cron permissions checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.7 user cron permissions checked: total=$total ok=$ok risky=$risky"
    fi
}

check_cron_command_paths_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, re, stat, sys

EXCLUDED_PARENTS = {"/var/log", "/tmp", "/var/tmp", "/run", "/dev/shm"}

cron_files = []
base = Path("/etc/crontab")
if base.is_file():
    cron_files.append(base)
cron_d = Path("/etc/cron.d")
if cron_d.is_dir():
    cron_files.extend(sorted(p for p in cron_d.iterdir() if p.is_file()))

seen = set()
paths = []
token_re = re.compile(r'(/[A-Za-z0-9_./+:-]+)')

for cfg in cron_files:
    try:
        text = cfg.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for m in token_re.findall(s):
            rp = os.path.realpath(m)
            if rp.startswith("/") and os.path.exists(rp) and rp not in seen:
                seen.add(rp)
                paths.append(rp)

ok = 0
risky = 0
samples = []
sample_limit = int(sys.argv[1])

for item in sorted(paths):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if os.path.isfile(item) and stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        if str(cur) in EXCLUDED_PARENTS:
            break
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception as e:
            reasons.append(f"parent_stat_failed:{cur}:{e}")
            break

        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{len(paths)}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

record_cron_command_paths_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.3 cron command paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.3 cron command paths checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_cron_command_paths_module() {
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.3 cron-command-paths scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.3 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_cron_command_paths_module)
        add_skipped "2.3.3 dry-run: cron command path remediation is policy-gated"
        return 0
    fi
    local item reason
    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.3 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
            continue
        fi
        [[ -f "$item" ]] || continue
        local backup_path="$STATE_DIR/cron_cmd.$(echo "$item" | tr '/' '_').meta-$TIMESTAMP.txt"
        write_metadata_snapshot "$item" "$backup_path"
        record_manifest_backup "$item" "$backup_path"
        chmod go-w "$item" && {
            record_manifest_modified_file "$item"
            record_manifest_apply_report "2.3.3 chmod go-w: $item"
        } || add_warning "2.3.3 chmod go-w failed: $item"
    done < <(check_cron_command_paths_module)
    add_safe "2.3.3 cron command paths permissions processed"
}

check_standard_system_paths_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, stat, subprocess, sys

paths = set(p for p in os.environ.get(
    "SECURELINUX_NG_STANDARD_SYSTEM_PATHS",
    "/bin:/sbin:/usr/bin:/usr/sbin:/lib:/lib64:/usr/lib:/usr/lib64",
).split(":") if p)

if os.environ.get("SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_ENV_PATH", "1") not in {"0", "false", "False", "no", "NO"}:
    for item in os.environ.get("PATH", "").split(":"):
        if item.startswith("/"):
            paths.add(item)

if os.environ.get("SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_KERNEL_MODULES", "1") not in {"0", "false", "False", "no", "NO"}:
    uname_r = subprocess.run(["uname", "-r"], text=True, capture_output=True, check=False).stdout.strip()
    if uname_r:
        paths.add(f"/lib/modules/{uname_r}")

seen = set()
for base in sorted(paths):
    p = Path(base)
    if not p.exists():
        continue
    if p.is_file():
        items = [p]
    else:
        items = [x for x in p.rglob("*") if x.is_file() and not x.is_symlink()]
    for item in items:
        rp = str(item.resolve())
        if rp not in seen:
            seen.add(rp)

ok = 0
risky = 0
sample_limit = int(sys.argv[1])
samples = []

for item in sorted(seen):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception as e:
            reasons.append(f"parent_stat_failed:{cur}:{e}")
            break
        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

record_standard_system_paths_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.8 standard system paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.8 standard system paths checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_standard_system_paths_module() {
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.8 standard-system-paths scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.8 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_standard_system_paths_module)
        add_skipped "2.3.8 dry-run: standard system paths remediation is policy-gated"
        return 0
    fi

    local item reason
    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.8 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
            continue
        fi
        [[ -f "$item" ]] || continue
        local backup_path="$STATE_DIR/syspath.$(echo "$item" | tr '/' '_').meta-$TIMESTAMP.txt"
        write_metadata_snapshot "$item" "$backup_path"
        record_manifest_backup "$item" "$backup_path"
        chmod go-w "$item" && {
            record_manifest_modified_file "$item"
            record_manifest_apply_report "2.3.8 chmod go-w: $item"
        } || add_warning "2.3.8 chmod go-w failed: $item"
    done < <(check_standard_system_paths_module)
    add_safe "2.3.8 standard system paths permissions processed"
}

check_suid_sgid_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, stat, sys

roots = [Path(p) for p in os.environ.get(
    "SECURELINUX_NG_SUID_SGID_PATHS",
    "/bin:/sbin:/usr/bin:/usr/sbin:/lib:/lib64:/usr/lib:/usr/lib64",
).split(":") if p]
seen = set()
files = []

for root in roots:
    if not root.exists():
        continue
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                files.append(Path(rp))

ok = 0
risky = 0
sample_limit = int(sys.argv[1])
samples = []

for f in sorted(files):
    try:
        st = os.stat(f)
    except Exception:
        continue

    mode = stat.S_IMODE(st.st_mode)
    if not (mode & 0o4000 or mode & 0o2000):
        continue

    reasons = []
    if mode & 0o022:
        reasons.append(f"suid_sgid_go_w:{mode:o}")
    if (mode & 0o4000) and st.st_uid != 0:
        reasons.append(f"suid_non_root_owner:{st.st_uid}")

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((str(f), ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

record_suid_sgid_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.9 suid/sgid audit checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.9 suid/sgid audit checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_suid_sgid_module() {
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.9 suid-sgid scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.9 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_suid_sgid_module)
        add_skipped "2.3.9 dry-run: suid/sgid remediation is policy-gated"
        return 0
    fi

    local item reason changed
    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        [[ -f "$item" ]] || continue
        local backup_path="$STATE_DIR/suid.$(echo "$item" | tr '/' '_').meta-$TIMESTAMP.txt"
        write_metadata_snapshot "$item" "$backup_path"
        record_manifest_backup "$item" "$backup_path"
        changed=0
        if [[ "$reason" == *"suid_non_root_owner"* ]]; then
            if chown root "$item"; then
                record_manifest_apply_report "2.3.9 chown root: $item"
                changed=1
            else
                add_warning "2.3.9 chown root failed: $item"
            fi
        fi
        if [[ "$reason" == *"go_w"* ]]; then
            if chmod go-w "$item"; then
                record_manifest_apply_report "2.3.9 chmod go-w: $item"
                changed=1
            else
                add_warning "2.3.9 chmod go-w failed: $item"
            fi
        fi
        if (( changed == 1 )); then
            record_manifest_modified_file "$item"
        fi
    done < <(check_suid_sgid_module)
    add_safe "2.3.9 SUID/SGID audit processed"
}

apply_user_cron_permissions_module() {
    local file backup_path
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.7 user-cron scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.7 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_user_cron_permissions_module)
        add_skipped "2.3.7 dry-run: user cron permissions would be corrected"
        return 0
    fi

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        [[ -f "$file" ]] || continue
        # Проверяем, нужна ли коррекция (go-w)
        local _cron_mode
        _cron_mode="$(stat -c '%a' "$file" 2>/dev/null)" || continue
        if (( (8#$_cron_mode & 8#022) == 0 )); then
            continue  # права уже корректны
        fi
        backup_path="$STATE_DIR/cronuser.$(basename "$file").meta-$TIMESTAMP.txt"
        write_metadata_snapshot "$file" "$backup_path"
        record_manifest_backup "$file" "$backup_path"
        chmod go-w "$file"
        record_manifest_modified_file "$file"
        record_manifest_apply_report "2.3.7 corrected user cron file mode: $file"
    done < <(
        python3 - <<'PYJSON'
from pathlib import Path
import os
seen = set()
for root in [Path(p) for p in os.environ.get("SECURELINUX_NG_USER_CRON_DIRS", "/var/spool/cron:/var/spool/cron/crontabs").split(":") if p]:
    if not root.is_dir():
        continue
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                print(rp)
PYJSON
    )

    add_safe "2.3.7 user cron permissions processed"
}

apply_home_permissions_module() {
    local home_dir file backup_path
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.10/2.3.11 home-perms scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.10/2.3.11 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_home_permissions_module)
        add_skipped "2.3.10/2.3.11 dry-run: home permissions would be corrected"
        return 0
    fi

    while IFS= read -r home_dir; do
        [[ -n "$home_dir" ]] || continue
        if [[ -d "$home_dir" ]]; then
            backup_path="$STATE_DIR/$(basename "$home_dir").home.meta-$TIMESTAMP.txt"
            write_metadata_snapshot "$home_dir" "$backup_path"
            record_manifest_backup "$home_dir" "$backup_path"
            if chmod 700 "$home_dir"; then
                record_manifest_modified_file "$home_dir"
                record_manifest_apply_report "2.3.11 corrected home dir mode: $home_dir"
            else
                add_warning "2.3.11 chmod 700 failed: $home_dir"
            fi
        fi

        for file_name in "${HOME_SENSITIVE_FILE_NAMES[@]}"; do
            file="$home_dir/$file_name"
            [[ -f "$file" ]] || continue
            backup_path="$STATE_DIR/$(basename "$home_dir").$(basename "$file").meta-$TIMESTAMP.txt"
            write_metadata_snapshot "$file" "$backup_path"
            record_manifest_backup "$file" "$backup_path"
            if chmod go-rwx "$file"; then
                record_manifest_modified_file "$file"
                record_manifest_apply_report "2.3.10 corrected sensitive file mode: $file"
            else
                add_warning "2.3.10 chmod go-rwx failed: $file"
            fi
        done
    done < <(home_targets_scan)

    add_safe "2.3.10/2.3.11 home permissions processed"
}

apply_sysctl_userspace_protection_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sysctl.d'"
        if [[ -f "$SYSCTL_USERSPACE_PROTECTION_DROPIN" ]]; then
            log "[DRY-RUN] backup '$SYSCTL_USERSPACE_PROTECTION_DROPIN' -> '$STATE_DIR/$(basename "$SYSCTL_USERSPACE_PROTECTION_DROPIN").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] write '$SYSCTL_USERSPACE_PROTECTION_DROPIN' with 2.6 sysctl protections"
        log "[DRY-RUN] sysctl --system"
        add_skipped "2.6 dry-run: sysctl userspace protections would be enforced"
        return 0
    fi

    # ФСТЭК 2.6.1: ptrace_scope=3 — для всех профилей (strict ограничение снято)

    mkdir -p /etc/sysctl.d

    # yama может отсутствовать в Ubuntu minimal — добавляем ptrace_scope только если доступен
    local _up_content="$SYSCTL_USERSPACE_PROTECTION_CONTENT"
    if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
        _up_content=$'# Managed by SecureLinux-NG\nkernel.yama.ptrace_scope = 3\n'${_up_content#*$'\n'}
    else
        log "[warn] 2.6.1: kernel.yama.ptrace_scope недоступен (yama не загружен) — параметр пропущен"
    fi

    if [[ -f "$SYSCTL_USERSPACE_PROTECTION_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SYSCTL_USERSPACE_PROTECTION_DROPIN").bak-$TIMESTAMP"
        if ! backup_file_checked "$SYSCTL_USERSPACE_PROTECTION_DROPIN" "$backup_path" "2.6 sysctl userspace"; then
            add_skipped "2.6 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SYSCTL_USERSPACE_PROTECTION_DROPIN" "$backup_path"
    fi

    local existed_before=0
    [[ -e "$SYSCTL_USERSPACE_PROTECTION_DROPIN" ]] && existed_before=1 || true

    printf '%s' "$_up_content" > "$SYSCTL_USERSPACE_PROTECTION_DROPIN"

    sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
    (( existed_before == 0 )) && record_manifest_created_file "$SYSCTL_USERSPACE_PROTECTION_DROPIN"
    record_manifest_modified_file "$SYSCTL_USERSPACE_PROTECTION_DROPIN"
    record_manifest_apply_report "2.6 enforced via $SYSCTL_USERSPACE_PROTECTION_DROPIN"
    add_safe "2.6 userspace-protection sysctl enforced via drop-in: $SYSCTL_USERSPACE_PROTECTION_DROPIN"
}

restore_sysctl_userspace_protection_module() {
    restore_file_from_manifest "$SYSCTL_USERSPACE_PROTECTION_DROPIN"
    sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || add_warning "restore: sysctl --system failed after restoring $SYSCTL_USERSPACE_PROTECTION_DROPIN"
}

apply_sysctl_attack_surface_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sysctl.d'"
        if [[ -f "$SYSCTL_ATTACK_SURFACE_DROPIN" ]]; then
            log "[DRY-RUN] backup '$SYSCTL_ATTACK_SURFACE_DROPIN' -> '$STATE_DIR/$(basename "$SYSCTL_ATTACK_SURFACE_DROPIN").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] write '$SYSCTL_ATTACK_SURFACE_DROPIN' with 2.5 sysctl protections"
        log "[DRY-RUN] sysctl --system"
        add_skipped "2.5 dry-run: sysctl attack-surface protections would be enforced"
        return 0
    fi

    mkdir -p /etc/sysctl.d

    if [[ -f "$SYSCTL_ATTACK_SURFACE_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SYSCTL_ATTACK_SURFACE_DROPIN").bak-$TIMESTAMP"
        if ! backup_file_checked "$SYSCTL_ATTACK_SURFACE_DROPIN" "$backup_path" "2.5 sysctl attack surface"; then
            add_skipped "2.5 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SYSCTL_ATTACK_SURFACE_DROPIN" "$backup_path"
    fi

    local existed_before=0
    [[ -e "$SYSCTL_ATTACK_SURFACE_DROPIN" ]] && existed_before=1 || true

    local attack_content="$SYSCTL_ATTACK_SURFACE_CONTENT"
    # ФСТЭК 2.5.2/2.5.6: perf_event_paranoid и unprivileged_bpf — для всех профилей
    # 2.5.5 user.max_user_namespaces: явный конфиг имеет приоритет над интерактивом
    local ns_limit
    if [[ -n "$USER_NAMESPACES_LIMIT" ]]; then
        ns_limit="$USER_NAMESPACES_LIMIT"
        attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"
        attack_content="${attack_content}
user.max_user_namespaces = ${ns_limit}"
        add_safe "2.5.5 user.max_user_namespaces=${ns_limit} (из конфига)"
    else
        log ""
        log "[?]     ФСТЭК 2.5.5: user.max_user_namespaces"
        log "[?]     Планируется ли использование Docker / Podman / Kubernetes на этом сервере?"
        log "[?]       1) Нет  — установить =0 (ФСТЭК требование, максимальная безопасность)"
        log "[?]       2) Да   — установить =10000 (контейнеры будут работать)"
        log "[?]       3) Пропустить — не изменять значение"
        if [[ ! -t 0 ]] && ! test -c /dev/tty 2>/dev/null; then
            add_skipped "2.5.5 user.max_user_namespaces пропущен: неинтерактивный режим (задайте USER_NAMESPACES_LIMIT в конфиге)"
            attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"
        else
        local ns_choice
        while true; do
            read -r -p "    Ваш выбор [1/2/3]: " ns_choice < /dev/tty
            case "$ns_choice" in
                1)
                    ns_limit=0
                    attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"
                    attack_content="${attack_content}
user.max_user_namespaces = 0"
                    add_safe "2.5.5 user.max_user_namespaces=0 (выбрано администратором)"
                    log "[i]     Совет: добавьте USER_NAMESPACES_LIMIT=0 в конфиг для автоматического применения"
                    break
                    ;;
                2)
                    ns_limit=10000
                    attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"
                    attack_content="${attack_content}
user.max_user_namespaces = 10000"
                    add_safe "2.5.5 user.max_user_namespaces=10000 (выбрано администратором — Docker/Podman/K8s совместимость)"
                    add_warning "2.5.5 user.max_user_namespaces=10000 — отклонение от ФСТЭК 2.5.5 (требует =0); зафиксируйте обоснование"
                    log "[i]     Совет: добавьте USER_NAMESPACES_LIMIT=10000 в конфиг для автоматического применения"
                    break
                    ;;
                3)
                    attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"
                    add_skipped "2.5.5 user.max_user_namespaces пропущен по выбору администратора"
                    break
                    ;;
                *)
                    log "[?]     Неверный ввод. Введите 1, 2 или 3."
                    ;;
            esac
        done
        log ""
        fi
    fi
    printf '%s' "$attack_content" > "$SYSCTL_ATTACK_SURFACE_DROPIN"

    local sysctl_attack_ok=0
    if sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        sysctl_attack_ok=1
    fi
    (( existed_before == 0 )) && record_manifest_created_file "$SYSCTL_ATTACK_SURFACE_DROPIN"
    record_manifest_modified_file "$SYSCTL_ATTACK_SURFACE_DROPIN"
    record_manifest_apply_report "2.5 enforced via $SYSCTL_ATTACK_SURFACE_DROPIN"
    if (( sysctl_attack_ok == 1 )); then
        add_safe "2.5 attack-surface sysctl protections enforced via drop-in: $SYSCTL_ATTACK_SURFACE_DROPIN"
    else
        add_error "2.5 attack-surface sysctl drop-in записан, но sysctl --system завершился с ошибкой — проверьте --check после перезагрузки"
        record_manifest_warning "2.5 sysctl --system failed after writing $SYSCTL_ATTACK_SURFACE_DROPIN"
    fi
}

restore_sysctl_attack_surface_module() {
    restore_file_from_manifest "$SYSCTL_ATTACK_SURFACE_DROPIN"
    sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || add_warning "restore: sysctl --system failed after restoring $SYSCTL_ATTACK_SURFACE_DROPIN"
}

check_modules_disabled_module() {
    # Модуль временно отключён — apply выдаёт SKIP, check тоже пропускает
    add_skipped "kernel.modules_disabled: временно отключено — проверка пропущена"
    return 0
}

apply_modules_disabled_module() {
    # ВРЕМЕННО ОТКЛЮЧЕНО: kernel.modules_disabled=1 ломает binfmt_misc и UFW при загрузке
    # Требует предварительной загрузки всех нужных модулей до применения параметра
    add_skipped "kernel.modules_disabled: временно отключено (совместимость с binfmt_misc/UFW при boot)"
    return 0
}

restore_modules_disabled_module() {
    # Если dropin не существует — apply был пропущен, restore не нужен
    if [[ ! -f "$SYSCTL_MODULES_DISABLED_DROPIN" ]]; then
        log "[i]     restore kernel.modules_disabled: dropin не создавался — пропуск"
        return 0
    fi
    restore_file_from_manifest "$SYSCTL_MODULES_DISABLED_DROPIN"
    add_warning "restore kernel.modules_disabled: dropin удалён, но значение kernel.modules_disabled=1 необратимо до перезагрузки"
}

apply_grub_kernel_params_module() {
    local grub_file="/etc/default/grub"
    local grub_backup="${STATE_DIR}/grub_default_backup_${TIMESTAMP}"
    local a b c
    local grub_params=("${GRUB_KERNEL_REQUIRED_PARAMS[@]}")
    if profile_allows strict; then
        grub_params+=("apparmor=1" "security=apparmor")
    fi

    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.4 grub params scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.4 would add missing kernel param '$a'"
                    ;;
            esac
        done < <(grub_kernel_params_check_module "$PROFILE")
        log "[DRY-RUN] 2.4 would backup ${grub_file} -> ${grub_backup}"
        log "[DRY-RUN] 2.4 would add missing params to GRUB_CMDLINE_LINUX_DEFAULT"
        log "[DRY-RUN] 2.4 would run update-grub / grub2-mkconfig"
        add_skipped "2.4 dry-run: GRUB kernel params remediation skipped"
        return 0
    fi



    if [[ ! -f "${grub_file}" ]]; then
        add_warning "2.4 ${grub_file} не найден — пропуск GRUB hardening"
        record_manifest_warning "2.4 ${grub_file} not found"
        add_skipped "2.4 apply skipped: ${grub_file} not found"
        return 0
    fi

    if manifest_has_backup_for "${grub_file}"; then
        log "[i]     2.4 GRUB backup уже существует — пропуск"
    else
        cp "${grub_file}" "${grub_backup}" || {
            add_warning "2.4 не удалось создать backup ${grub_file}"
            record_manifest_warning "2.4 grub backup failed"
            add_skipped "2.4 apply skipped: backup failed"
            return 0
        }
        record_manifest_backup "${grub_file}" "${grub_backup}"
        log "[i]     2.4 backup ${grub_file} -> ${grub_backup}"
    fi

    local grub_output
    grub_output=$(python3 - "${grub_file}" "${grub_params[@]}" <<'PYGRUB'
import sys, re, pathlib
grub_file = pathlib.Path(sys.argv[1])
required = sys.argv[2:]
content = grub_file.read_text(encoding='utf-8')
pattern = re.compile(r"(?m)^(GRUB_CMDLINE_LINUX_DEFAULT=)([\"'])(.*?)([\"'])")
m = pattern.search(content)
if not m:
    print('SKIP: GRUB_CMDLINE_LINUX_DEFAULT not found', flush=True)
    sys.exit(0)
prefix, q1, current, q2 = m.group(1), m.group(2), m.group(3), m.group(4)
params = current.split()
added = []
for req in required:
    key = req.split('=')[0]
    exact = False
    replace_idx = None
    for idx, p in enumerate(params):
        if p == req:
            exact = True
            break
        if p == key or p.startswith(key + '='):
            replace_idx = idx
            break
    if exact:
        continue
    if replace_idx is not None:
        params[replace_idx] = req
        added.append(req)
    else:
        params.append(req)
        added.append(req)
new_line = prefix + q1 + ' '.join(params) + q2
new_content = content[:m.start()] + new_line + content[m.end():]
grub_file.write_text(new_content, encoding='utf-8')
if added:
    print('ADDED: ' + ' '.join(added), flush=True)
else:
    print('OK: all params already present', flush=True)
PYGRUB
)
    [[ -n "$grub_output" ]] && record_manifest_apply_report "2.4 GRUB: $grub_output"

    if command -v update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
            && add_safe "2.4 GRUB kernel params applied, update-grub выполнен" \
            || { add_warning "2.4 update-grub завершился с ошибкой"; record_manifest_warning "2.4 update-grub failed"; }
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 \
            && add_safe "2.4 GRUB kernel params applied, grub2-mkconfig выполнен" \
            || { add_warning "2.4 grub2-mkconfig завершился с ошибкой"; record_manifest_warning "2.4 grub2-mkconfig failed"; }
    else
        add_warning "2.4 update-grub / grub2-mkconfig не найден — ${grub_file} обновлён, загрузчик требует ручного обновления"
        record_manifest_warning "2.4 grub update command not found; manual update-grub required"
        add_safe "2.4 GRUB_CMDLINE_LINUX_DEFAULT обновлён (требуется ручной update-grub)"
    fi

    # п.7.7: chmod 600 grub.cfg
    if profile_allows baseline; then
        local grub_cfg
        for grub_cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
            if [[ -f "$grub_cfg" ]]; then
                chmod 600 "$grub_cfg" && \
                    add_safe "7.7 grub.cfg chmod 600: $grub_cfg" || \
                    add_warning "7.7 grub.cfg chmod 600 не удался: $grub_cfg"
            fi
        done
    fi
}

restore_grub_module() {
    local grub_file="/etc/default/grub"
    local backup
    backup=$(python3 -c "
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
target = sys.argv[2]
if not mf.exists():
    sys.exit(1)
data = json.loads(mf.read_text(encoding='utf-8'))
for b in data.get('backups', []):
    if b.get('original') == target:
        print(b.get('backup', ''))
        sys.exit(0)
sys.exit(1)
" "${RESTORE_SOURCE_MANIFEST}" "${grub_file}" 2>/dev/null || true)
    if [[ -z "${backup}" || ! -f "${backup}" ]]; then
        log "[i]     restore 2.4 GRUB: backup не найден в manifest — пропуск"
        return 0
    fi
    cp "${backup}" "${grub_file}" \
        && log "[i]     restore 2.4 GRUB: ${grub_file} восстановлен из ${backup}" \
        || { log "[WARN]  restore 2.4 GRUB: не удалось восстановить ${grub_file}"; return 1; }
    if command -v update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
            && log "[i]     restore 2.4 GRUB: update-grub выполнен" \
            || log "[WARN]  restore 2.4 GRUB: update-grub завершился с ошибкой"
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 \
            && log "[i]     restore 2.4 GRUB: grub2-mkconfig выполнен" \
            || log "[WARN]  restore 2.4 GRUB: grub2-mkconfig завершился с ошибкой"
    else
        log "[WARN]  restore 2.4 GRUB: update-grub / grub2-mkconfig не найден — требуется ручное обновление"
    fi
}

apply_sysctl_kernel_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sysctl.d'"
        if [[ -f "$SYSCTL_KERNEL_DROPIN" ]]; then
            log "[DRY-RUN] backup '$SYSCTL_KERNEL_DROPIN' -> '$STATE_DIR/$(basename "$SYSCTL_KERNEL_DROPIN").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] write '$SYSCTL_KERNEL_DROPIN' with kernel.dmesg_restrict=1, kernel.kptr_restrict=2, net.core.bpf_jit_harden=2"
        log "[DRY-RUN] sysctl --system"
        add_skipped "2.4 dry-run: sysctl kernel protections would be enforced"
        return 0
    fi

    mkdir -p /etc/sysctl.d

    if [[ -f "$SYSCTL_KERNEL_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SYSCTL_KERNEL_DROPIN").bak-$TIMESTAMP"
        if ! backup_file_checked "$SYSCTL_KERNEL_DROPIN" "$backup_path" "2.4 sysctl kernel"; then
            add_skipped "2.4 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SYSCTL_KERNEL_DROPIN" "$backup_path"
    fi

    local existed_before=0
    [[ -e "$SYSCTL_KERNEL_DROPIN" ]] && existed_before=1 || true

    printf '%s' "$SYSCTL_KERNEL_CONTENT" > "$SYSCTL_KERNEL_DROPIN"

    local sysctl_kernel_ok=0
    if sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        sysctl_kernel_ok=1
    fi
    (( existed_before == 0 )) && record_manifest_created_file "$SYSCTL_KERNEL_DROPIN"
    record_manifest_modified_file "$SYSCTL_KERNEL_DROPIN"
    record_manifest_apply_report "2.4 enforced via $SYSCTL_KERNEL_DROPIN"
    if (( sysctl_kernel_ok == 1 )); then
        add_safe "2.4 kernel sysctl protections enforced via drop-in: $SYSCTL_KERNEL_DROPIN"
    else
        add_error "2.4 kernel sysctl drop-in записан, но sysctl --system завершился с ошибкой — проверьте --check после перезагрузки"
        record_manifest_warning "2.4 sysctl --system failed after writing $SYSCTL_KERNEL_DROPIN"
    fi
}

restore_sysctl_kernel_module() {
    restore_file_from_manifest "$SYSCTL_KERNEL_DROPIN"
    sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || add_warning "restore: sysctl --system failed after restoring $SYSCTL_KERNEL_DROPIN"
}

sysctl_network_check_module() {
    python3 - "${1:-baseline}" <<'PYJSON'
import subprocess, sys
targets = {
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.default.log_martians": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.tcp_syn_retries": "3",
}
profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"
paranoid_targets = {
    "net.ipv4.tcp_timestamps": "0",
}
if profile == "paranoid":
    targets.update(paranoid_targets)
ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(["sysctl", "-n", key], text=True, capture_output=True, check=False)
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue
    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")
print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_network_check_results() {
    local total="$1" ok="$2" risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "8.1-8.3 sysctl network protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "8.1-8.3 sysctl network protections checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_sysctl_network_module() {
    if (( DRY_RUN == 1 )); then
        log "[i]     [DRY-RUN] write '$SYSCTL_NETWORK_DROPIN'"
        add_skipped "8.1-8.3 dry-run: network sysctl protections would be enforced"
        return 0
    fi
    mkdir -p /etc/sysctl.d
    if [[ -f "$SYSCTL_NETWORK_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SYSCTL_NETWORK_DROPIN").bak-$TIMESTAMP"
        if ! backup_file_checked "$SYSCTL_NETWORK_DROPIN" "$backup_path" "8.1-8.3 sysctl network"; then
            add_skipped "8.1-8.3 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SYSCTL_NETWORK_DROPIN" "$backup_path"
    fi
    local existed_before=0
    [[ -e "$SYSCTL_NETWORK_DROPIN" ]] && existed_before=1 || true
    local network_content="$SYSCTL_NETWORK_CONTENT"
    if profile_allows paranoid; then
        network_content+=$'net.ipv4.tcp_timestamps = 0\n'
    fi
    printf '%s' "$network_content" > "$SYSCTL_NETWORK_DROPIN"
    local sysctl_network_ok=0
    if sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        sysctl_network_ok=1
    fi
    (( existed_before == 0 )) && record_manifest_created_file "$SYSCTL_NETWORK_DROPIN"
    record_manifest_modified_file "$SYSCTL_NETWORK_DROPIN"
    record_manifest_apply_report "8.1-8.3 enforced via $SYSCTL_NETWORK_DROPIN"
    if (( sysctl_network_ok == 1 )); then
        add_safe "8.1-8.3 network sysctl protections enforced via drop-in: $SYSCTL_NETWORK_DROPIN"
    else
        add_error "8.1-8.3 network sysctl drop-in записан, но sysctl --system завершился с ошибкой — проверьте --check после перезагрузки"
        record_manifest_warning "8.1-8.3 sysctl --system failed after writing $SYSCTL_NETWORK_DROPIN"
    fi
    # log_martians сбрасывается при поднятии интерфейса — создаём systemd unit
    local sysctl_unit="/etc/systemd/system/securelinux-ng-sysctl.service"
    printf '[Unit]\nDescription=SecureLinux-NG: reapply sysctl after network\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/sbin/sysctl --system\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n' > "$sysctl_unit"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable securelinux-ng-sysctl >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
    record_manifest_created_file "$sysctl_unit"
    add_safe "8.1-8.3 systemd unit создан для применения sysctl после network-online"
}

restore_sysctl_network_module() {
    local sysctl_unit="/etc/systemd/system/securelinux-ng-sysctl.service"
    if restore_has_created_file "$sysctl_unit"; then
        systemctl disable securelinux-ng-sysctl >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
        restore_file_from_manifest "$sysctl_unit"
        systemctl daemon-reload >/dev/null 2>&1 || true
        log "[i]     restore: securelinux-ng-sysctl.service отключён и удалён"
    fi
    restore_file_from_manifest "$SYSCTL_NETWORK_DROPIN"
    if [[ -f "$SYSCTL_NETWORK_DROPIN" ]]; then
        sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || add_warning "restore: sysctl --system failed after restoring $SYSCTL_NETWORK_DROPIN"
    fi
}

apply_sudo_command_paths_module() {
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.4 sudo command scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.4 would review '$a' reason='$b'"
                    ;;
            esac
        done < <(check_sudo_command_paths_module)
        add_skipped "2.3.4 dry-run: sudo command path remediation is policy-gated"
        return 0
    fi

    local item reason
    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.4 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
            continue
        fi
        [[ -f "$item" ]] || continue
        local backup_path="$STATE_DIR/sudo_cmd.$(echo "$item" | tr '/' '_').meta-$TIMESTAMP.txt"
        write_metadata_snapshot "$item" "$backup_path"
        record_manifest_backup "$item" "$backup_path"
        chmod go-w "$item" && chown root:root "$item" && {
            record_manifest_modified_file "$item"
            record_manifest_apply_report "2.3.4 chmod go-w + chown root: $item"
        } || add_warning "2.3.4 chmod go-w / chown root failed: $item"
    done < <(check_sudo_command_paths_module)
    add_safe "2.3.4 sudo command paths permissions processed"
}

resolve_restore_manifest() {
    if [[ -n "$RESTORE_MANIFEST" ]]; then
        [[ -f "$RESTORE_MANIFEST" ]] || die "Manifest для restore не найден: $RESTORE_MANIFEST"
        RESTORE_SOURCE_MANIFEST="$RESTORE_MANIFEST"
        return 0
    fi

    [[ -d "$STATE_DIR" ]] || die "STATE_DIR не найден: $STATE_DIR"

    RESTORE_SOURCE_MANIFEST="$(
        python3 - "$STATE_DIR" <<'PYJSON'
import sys, pathlib
base = pathlib.Path(sys.argv[1])
items = sorted(base.glob("manifest-*.json"))
if items:
    print(items[-1])
elif (base / "manifest.json").exists():
    print(base / "manifest.json")
else:
    print("")
PYJSON
)"
    [[ -n "$RESTORE_SOURCE_MANIFEST" ]] || die "Не найден manifest для restore в $STATE_DIR"
    [[ -f "$RESTORE_SOURCE_MANIFEST" ]] || die "Manifest для restore не найден: $RESTORE_SOURCE_MANIFEST"
}

restore_lookup_backup() {
    local original_path="$1"
    python3 - "$RESTORE_SOURCE_MANIFEST" "$original_path" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
original = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
for entry in data.get("backups", []):
    if isinstance(entry, dict) and entry.get("original") == original:
        print(entry.get("backup", ""))
        raise SystemExit(0)
print("")
PYJSON
}

restore_has_created_file() {
    local target="$1"
    python3 - "$RESTORE_SOURCE_MANIFEST" "$target" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
target = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
raise SystemExit(0 if target in data.get("created_files", []) else 1)
PYJSON
}

restore_has_created_group() {
    local target="$1"
    python3 - "$RESTORE_SOURCE_MANIFEST" "$target" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
target = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
raise SystemExit(0 if target in data.get("created_groups", []) else 1)
PYJSON
}

restore_file_from_manifest() {
    local target="$1"
    local backup
    backup="$(restore_lookup_backup "$target")"

    if [[ -n "$backup" && -f "$backup" ]]; then
        cp -a "$backup" "$target"
        add_safe "restore: restored $target from backup $backup"
        return 0
    fi

    if restore_has_created_file "$target"; then
        if [[ -e "$target" ]]; then
            rm -f "$target"
            add_safe "restore: removed created file $target"
        else
            add_safe "restore: created file already absent $target"
        fi
        return 0
    fi

    add_warning "restore: no backup mapping for $target"
    return 0
}

restore_ssh_root_login_module() {
    restore_file_from_manifest "$SSH_ROOT_LOGIN_DROPIN"
}

check_ssh_hardening_module() {
    if [[ ! -f "$SSH_HARDENING_DROPIN" ]]; then
        add_risky "2.1.2 SSH hardening drop-in отсутствует: $SSH_HARDENING_DROPIN"
        return 0
    fi
    local missing=() wrong=()
    # Проверяем наличие И значения ключевых параметров
    local -A expected_values=(
        [X11Forwarding]="no" [MaxAuthTries]="3" [MaxSessions]="2"
        [PermitEmptyPasswords]="no" [UseDNS]="no" [GSSAPIAuthentication]="no"
        [ClientAliveInterval]="300" [ClientAliveCountMax]="2" [LoginGraceTime]="30"
        [AllowAgentForwarding]="no" [AllowTcpForwarding]="no"
        [IgnoreRhosts]="yes" [HostbasedAuthentication]="no" [LogLevel]="VERBOSE"
    )
    local param val actual
    for param in "${!expected_values[@]}"; do
        val="${expected_values[$param]}"
        actual="$(awk "/^${param}[[:space:]]/{print \$2; exit}" "$SSH_HARDENING_DROPIN" 2>/dev/null)"
        if [[ -z "$actual" ]]; then
            missing+=("$param")
        elif [[ "$actual" != "$val" ]]; then
            wrong+=("${param}=${actual}(ожидалось=${val})")
        fi
    done
    if profile_allows strict; then
        for param in KexAlgorithms Ciphers MACs Compression Banner; do
            grep -q "^${param}" "$SSH_HARDENING_DROPIN" || missing+=("$param")
        done
    fi
    if [[ ${#missing[@]} -eq 0 && ${#wrong[@]} -eq 0 ]]; then
        add_safe "2.1.2 SSH hardening drop-in присутствует и корректен: $SSH_HARDENING_DROPIN"
    else
        local details=""
        [[ ${#missing[@]} -gt 0 ]] && details="отсутствуют: ${missing[*]}"
        [[ ${#wrong[@]} -gt 0 ]] && details="${details:+$details; }неверные значения: ${wrong[*]}"
        add_risky "2.1.2 SSH hardening drop-in: $details"
    fi
}

apply_ssh_hardening_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] write '$SSH_HARDENING_DROPIN' (profile: ${PROFILE})"
        add_skipped "2.1.2 dry-run: SSH hardening drop-in would be written"
        return 0
    fi

    mkdir -p /etc/ssh/sshd_config.d

    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SSH_HARDENING_DROPIN").bak-$TIMESTAMP"
        if ! backup_file_checked "$SSH_HARDENING_DROPIN" "$backup_path" "2.1.2 SSH hardening"; then
            add_skipped "2.1.2 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SSH_HARDENING_DROPIN" "$backup_path"
    fi

    local existed_before=0
    [[ -e "$SSH_HARDENING_DROPIN" ]] && existed_before=1 || true

    local content="$SSH_HARDENING_BASELINE"
    if profile_allows strict; then
        content+="$SSH_HARDENING_STRICT"
    fi

    printf '%s' "$content" > "$SSH_HARDENING_DROPIN"

    if sshd -t >/dev/null 2>&1; then
        (( existed_before == 0 )) && record_manifest_created_file "$SSH_HARDENING_DROPIN"
        record_manifest_modified_file "$SSH_HARDENING_DROPIN"
        record_manifest_apply_report "2.1.2 SSH hardening enforced via $SSH_HARDENING_DROPIN (profile: ${PROFILE})"
        add_safe "2.1.2 SSH hardening drop-in written: $SSH_HARDENING_DROPIN"
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    else
        add_error "2.1.2 sshd -t failed после записи $SSH_HARDENING_DROPIN — откат"
        record_manifest_warning "2.1.2 sshd -t failed, rolling back"
        if [[ -n "${backup_path:-}" && -f "$backup_path" ]]; then
            cp -a "$backup_path" "$SSH_HARDENING_DROPIN"
        else
            rm -f "$SSH_HARDENING_DROPIN"
        fi
        return 1
    fi
}

restore_ssh_hardening_module() {
    restore_file_from_manifest "$SSH_HARDENING_DROPIN"
}

KERNEL_MODULE_BLACKLIST="/etc/modprobe.d/60-securelinux-ng-blacklist.conf"

FAIL2BAN_JAIL="/etc/fail2ban/jail.local"

ACCOUNT_AUDIT_FILE="/var/log/securelinux-ng/account_audit.txt"

check_account_audit_module() {
    if [[ -f "$ACCOUNT_AUDIT_FILE" ]]; then
        add_safe "account audit: отчёт присутствует: $ACCOUNT_AUDIT_FILE"
    else
        add_risky "account audit: отчёт отсутствует: $ACCOUNT_AUDIT_FILE"
    fi
}

apply_account_audit_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] generate account audit report -> $ACCOUNT_AUDIT_FILE"
        add_skipped "account audit dry-run"
        return 0
    fi

    mkdir -p "$(dirname "$ACCOUNT_AUDIT_FILE")"

    python3 - "$ACCOUNT_AUDIT_FILE" <<'PYAUDIT'
import sys, pathlib, pwd, grp, datetime

out = []
out.append("# SecureLinux-NG — Account Audit")
out.append("# Generated: " + datetime.datetime.now().isoformat())
out.append("")

out.append("## Users (/etc/passwd)")
for e in sorted(pwd.getpwall(), key=lambda x: x.pw_uid):
    out.append(f"  uid={e.pw_uid:5d}  {e.pw_name:20s}  shell={e.pw_shell}  home={e.pw_dir}")

out.append("")
out.append("## Groups (/etc/group)")
for e in sorted(grp.getgrall(), key=lambda x: x.gr_gid):
    members = ", ".join(e.gr_mem) if e.gr_mem else "(none)"
    out.append(f"  gid={e.gr_gid:5d}  {e.gr_name:20s}  members={members}")

out.append("")
out.append("## UID=0 accounts")
for e in pwd.getpwall():
    if e.pw_uid == 0:
        out.append(f"  {e.pw_name}")

out.append("")
out.append("## Accounts with login shell")
nologin = {"/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""}
for e in sorted((e for e in pwd.getpwall() if e.pw_shell not in nologin), key=lambda x: x.pw_uid):
    out.append(f"  uid={e.pw_uid:5d}  {e.pw_name:20s}  shell={e.pw_shell}")

out.append("")
out.append("## sudo/wheel/admin group members")
for gname in ("sudo", "wheel", "admin"):
    try:
        g = grp.getgrnam(gname)
        members = ", ".join(g.gr_mem) if g.gr_mem else "(none)"
        out.append(f"  group={gname}: {members}")
    except KeyError:
        out.append(f"  group={gname}: not found")

pathlib.Path(sys.argv[1]).write_text("\n".join(out) + "\n", encoding="utf-8")
PYAUDIT

    # --- 17.1: активные службы ---
    {
        echo ""
        echo "## Active systemd services (17.1)"
        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print "  " $1}' | sort
    } >> "$ACCOUNT_AUDIT_FILE"

    # --- 17.2: открытые порты ---
    {
        echo ""
        echo "## Open listening ports (17.2)"
        ss -tlnp 2>/dev/null | tail -n +2 | awk '{print "  " $0}'
    } >> "$ACCOUNT_AUDIT_FILE"

    record_manifest_created_file "$ACCOUNT_AUDIT_FILE"
    record_manifest_modified_file "$ACCOUNT_AUDIT_FILE"
    record_manifest_apply_report "account audit: report written to $ACCOUNT_AUDIT_FILE"
    add_safe "account audit: отчёт записан: $ACCOUNT_AUDIT_FILE"
    log "[i]     account audit: просмотр: cat $ACCOUNT_AUDIT_FILE"
}

restore_account_audit_module() {
    if restore_has_created_file "$ACCOUNT_AUDIT_FILE"; then
        restore_file_from_manifest "$ACCOUNT_AUDIT_FILE"
    else
        log "[i]     restore account audit: файл не трекался — пропуск"
    fi
}

check_apparmor_module() {
    if ! command -v apparmor_status >/dev/null 2>&1; then
        add_risky "AppArmor: не установлен"
        return 0
    fi
    if systemctl is-active --quiet apparmor 2>/dev/null; then
        local enforced
        enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        if profile_allows strict; then
            add_safe "AppArmor: активен, enforce профилей: ${enforced:-?}"
        else
            add_skipped "AppArmor уже активен в системе: enforce профилей=${enforced:-?} (для baseline не требуется)"
        fi
    else
        if profile_allows strict; then
            add_risky "AppArmor: не активен"
        else
            add_skipped "AppArmor: не активен (для baseline не требуется)"
        fi
    fi
}

pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

check_memory_requirements() {
    local mem_available_mb
    mem_available_mb=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "0")
    if (( mem_available_mb > 0 && mem_available_mb < 512 )); then
        log "[WARN]  Доступно менее 512MB RAM (${mem_available_mb}MB)."
        log "[WARN]  Установка крупных пакетов (AIDE, cracklib-runtime) может завершиться ошибкой."
        log "[WARN]  Рекомендуется минимум 1GB свободной RAM перед запуском --apply."
        log "[WARN]  Продолжение через 10 секунд... (Ctrl+C для отмены)"
        sleep 10
    elif (( mem_available_mb > 0 && mem_available_mb < 1024 )); then
        log "[WARN]  Доступно менее 1GB RAM (${mem_available_mb}MB) — возможны проблемы при установке пакетов."
    fi
}

wait_for_dpkg_lock() {
    local lock_wait=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1        || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if (( lock_wait == 0 )); then
            log "[i]     apt: ожидание освобождения dpkg lock..."
        fi
        sleep 3
        (( lock_wait += 3 ))
        if (( lock_wait >= 300 )); then
            add_warning "apt: dpkg lock не освободился за 5 минут — продолжаем"
            break
        fi
    done
}

apt_update_once() {
    if (( _APT_UPDATED == 1 )); then return 0; fi
    wait_for_dpkg_lock
    log "[i]     apt-get update..."
    if DEBIAN_FRONTEND=noninteractive apt-get update -q >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        _APT_UPDATED=1
    else
        add_warning "apt-get update завершился с ошибкой — последующие установки пакетов могут не работать"
    fi
}

apply_apparmor_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install apparmor apparmor-utils, enable service"
        add_skipped "AppArmor dry-run"
        return 0
    fi

    if ! profile_allows strict; then
        add_skipped "AppArmor пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi

    log "[i]     AppArmor: установка пакетов..."
    apt_update_once
    local apparmor_was_installed=0
    pkg_installed apparmor && apparmor_was_installed=1
    if (( apparmor_was_installed == 0 )); then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" apparmor apparmor-utils >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
            add_warning "AppArmor: не удалось установить пакеты"
            record_manifest_warning "AppArmor: apt-get install failed"
            return 0
        }
    fi

    systemctl enable --now apparmor >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true

    if (( apparmor_was_installed == 1 )); then
        # Пакет уже был установлен — не трогаем профили, только проверяем статус
        local enforced
        enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "?")
        add_warning "AppArmor: уже установлен, профили не изменены. Для enforce: aa-enforce /etc/apparmor.d/*"
        record_manifest_warning "AppArmor: pre-installed, profiles not modified"
        return 0
    fi

    # Переводим все complain-профили в enforce (только при свежей установке)
    if command -v aa-enforce >/dev/null 2>&1; then
        aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
        record_manifest_apply_report "AppArmor: aa-enforce applied to /etc/apparmor.d/*"
    fi

    local enforced
    enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "?")
    add_safe "AppArmor: включён, enforce профилей: ${enforced:-?}"
    record_manifest_apply_report "AppArmor: enabled and enforce mode set"
    record_manifest_irreversible_change "AppArmor: enforce mode — для отката: aa-complain /etc/apparmor.d/*"
}

restore_apparmor_module() {
    if ! profile_allows strict; then
        log "[i]     restore AppArmor: модуль не применялся для текущего профиля — пропуск"
        return 0
    fi
    log "[i]     restore AppArmor: автоматический откат не реализован"
    add_warning "restore AppArmor: выполните вручную: aa-complain /etc/apparmor.d/* && systemctl disable apparmor"
}

check_aide_module() {
    if ! profile_allows strict; then
        add_skipped "AIDE пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if ! command -v aide >/dev/null 2>&1; then
        add_risky "AIDE: не установлен"
        return 0
    fi
    if [[ -f /var/lib/aide/aide.db ]]; then
        add_safe "AIDE: база данных присутствует: /var/lib/aide/aide.db"
    else
        add_risky "AIDE: база данных отсутствует (требуется aide --init)"
    fi
}

apply_aide_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install aide, aide --init"
        add_skipped "AIDE dry-run: would install and init database"
        return 0
    fi

    if ! profile_allows strict; then
        add_skipped "AIDE пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi

    log "[i]     AIDE: установка пакета..."
    apt_update_once
    pkg_installed aide || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" aide >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "AIDE: не удалось установить пакет"
        record_manifest_warning "AIDE: apt-get install failed"
        return 0
    }

    if [[ -f /var/lib/aide/aide.db ]]; then
        add_safe "AIDE: база данных уже существует, инициализация пропущена"
        return 0
    fi
    log "[i]     AIDE: инициализация базы данных — не прерывайте процесс, может занять 3–10 минут..."
    if aide --config /etc/aide/aide.conf --init >/dev/null 2>&1; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
        record_manifest_apply_report "AIDE: database initialized at /var/lib/aide/aide.db"
        record_manifest_irreversible_change "AIDE: база данных создана — обновлять после изменений: aide --update"
        add_safe "AIDE: база данных инициализирована"
        add_warning "AIDE: запускайте 'aide --check' после перезагрузки для проверки целостности"
    else
        add_warning "AIDE: aide --init завершился с ошибкой — проверьте вручную"
        record_manifest_warning "AIDE: aide --init failed"
    fi
}

restore_aide_module() {
    if ! profile_allows strict; then
        log "[i]     restore AIDE: модуль не применялся для текущего профиля — пропуск"
        return 0
    fi
    # AIDE не имеет backup-файла — при restore только сообщаем
    log "[i]     restore AIDE: база данных не восстанавливается автоматически"
    add_warning "restore AIDE: удалите /var/lib/aide/aide.db вручную если требуется откат"
}

check_fail2ban_module() {
    if ! profile_allows paranoid; then
        add_skipped "fail2ban пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        add_risky "fail2ban: не установлен"
        return 0
    fi
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        add_safe "fail2ban: служба активна"
    else
        add_risky "fail2ban: служба не активна"
    fi
    if [[ -f "$FAIL2BAN_JAIL" ]] && grep -q '^\[sshd\]' "$FAIL2BAN_JAIL" 2>/dev/null; then
        add_safe "fail2ban: SSH jail настроен"
    else
        add_risky "fail2ban: SSH jail не настроен"
    fi
}

apply_fail2ban_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install fail2ban, write ${FAIL2BAN_JAIL}"
        add_skipped "fail2ban dry-run"
        return 0
    fi

    if ! profile_allows paranoid; then
        add_skipped "fail2ban пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    log "[i]     fail2ban: установка пакета..."
    apt_update_once
    pkg_installed fail2ban || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" fail2ban >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "fail2ban: не удалось установить пакет"
        record_manifest_warning "fail2ban: apt-get install failed"
        return 0
    }
    systemctl enable --now fail2ban >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true

    local ssh_port="22"
    local detected
    detected=$(grep -Ei '^\s*Port\s+' /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | head -1)
    [[ -z "$detected" ]] && detected=$(grep -Ei '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [[ -n "$detected" ]] && ssh_port="$detected"

    mkdir -p /etc/fail2ban
    if [[ -f "$FAIL2BAN_JAIL" ]]; then
        local bak="$STATE_DIR/jail.local.bak-$TIMESTAMP"
        if ! backup_file_checked "$FAIL2BAN_JAIL" "$bak" "fail2ban"; then
            add_skipped "fail2ban apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$FAIL2BAN_JAIL" "$bak"
    fi
    local existed=0
    [[ -e "$FAIL2BAN_JAIL" ]] && existed=1 || true

    if (( existed == 1 )); then
        add_warning "fail2ban: $FAIL2BAN_JAIL уже существует — не перезаписан (ФСТЭК требует SSH jail). Проверьте вручную наличие [sshd] секции."
        record_manifest_warning "fail2ban: jail.local pre-exists, not overwritten"
        local enforced_count
        enforced_count=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        if [[ "$enforced_count" == "active" ]]; then
            add_safe "fail2ban: сервис ${enforced_count}"
        else
            add_warning "fail2ban: jail.local сохранён, но сервис ${enforced_count}"
            record_manifest_warning "fail2ban: pre-existing jail.local kept, service=${enforced_count}"
        fi
        record_manifest_apply_report "fail2ban: pre-existing jail.local kept"
        return 0
    fi

    cat > "$FAIL2BAN_JAIL" <<JAILEOF
# Managed by SecureLinux-NG — fail2ban SSH jail
# Не редактируйте jail.conf — он перезаписывается при обновлении пакета.

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ${ssh_port}
filter   = sshd
logpath  = %(sshd_log)s
maxretry = 5
bantime  = 3600
JAILEOF

    (( existed == 0 )) && record_manifest_created_file "$FAIL2BAN_JAIL"
    record_manifest_modified_file "$FAIL2BAN_JAIL"
    record_manifest_apply_report "fail2ban: SSH jail written (port=${ssh_port})"

    if systemctl restart fail2ban >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        add_safe "fail2ban: SSH jail настроен (port=${ssh_port}, maxretry=5, bantime=3600)"
    else
        add_warning "fail2ban: jail.local записан, но restart fail2ban не удался"
        record_manifest_warning "fail2ban: systemctl restart failed after writing jail.local"
    fi
}

restore_fail2ban_module() {
    if ! restore_manifest_has_path "$FAIL2BAN_JAIL"; then
        log "[i]     restore fail2ban: модуль не применялся — пропуск"
        return 0
    fi
    restore_file_from_manifest "$FAIL2BAN_JAIL"
    systemctl restart fail2ban >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
}

check_rkhunter_module() {
    if ! profile_allows paranoid; then
        add_skipped "rkhunter пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if ! command -v rkhunter >/dev/null 2>&1; then
        add_risky "rkhunter: не установлен"
        return 0
    fi
    add_safe "rkhunter: установлен ($(rkhunter --version 2>/dev/null | head -1))"
}

apply_rkhunter_module() {
    if (( DRY_RUN == 1 )); then
        add_skipped "rkhunter dry-run: would install and update database"
        return 0
    fi
    if ! profile_allows paranoid; then
        add_skipped "rkhunter пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    log "[i]     rkhunter: установка пакета..."
    apt_update_once
    pkg_installed rkhunter || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" rkhunter >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "rkhunter: не удалось установить пакет"
        record_manifest_warning "rkhunter: apt-get install failed"
        return 0
    }
    log "[i]     rkhunter: обновление базы данных..."
    local rkhunter_update_ok=1
    rkhunter --update >/dev/null 2>&1 || rkhunter_update_ok=0
    rkhunter --propupd >/dev/null 2>&1 || rkhunter_update_ok=0
    if (( rkhunter_update_ok == 1 )); then
        record_manifest_apply_report "rkhunter: installed and database updated"
        record_manifest_irreversible_change "rkhunter: установлен — удалить вручную: apt-get remove rkhunter"
        add_safe "rkhunter: установлен и база данных обновлена"
    else
        record_manifest_apply_report "rkhunter: installed, but database update failed"
        record_manifest_warning "rkhunter: --update/--propupd failed"
        add_warning "rkhunter: установлен, но обновление базы завершилось с ошибкой"
    fi
}

restore_rkhunter_module() {
    if ! restore_manifest_has_report_text "rkhunter:"; then
        log "[i]     restore rkhunter: модуль не применялся — пропуск"
        return 0
    fi
    log "[i]     restore rkhunter: пакет не удаляется автоматически; при необходимости удалите вручную: apt-get remove rkhunter"
}

check_kernel_modules_module() {
    if [[ -f "$KERNEL_MODULE_BLACKLIST" ]]; then
        add_safe "kernel modules: blacklist присутствует: $KERNEL_MODULE_BLACKLIST"
    else
        add_risky "kernel modules: blacklist отсутствует: $KERNEL_MODULE_BLACKLIST (requires_reboot)"
    fi
}

apply_kernel_modules_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] write $KERNEL_MODULE_BLACKLIST"
        add_skipped "kernel modules dry-run: blacklist would be written"
        return 0
    fi

    if [[ -f "$KERNEL_MODULE_BLACKLIST" ]]; then
        local bak="$STATE_DIR/$(basename "$KERNEL_MODULE_BLACKLIST").bak-$TIMESTAMP"
        if ! backup_file_checked "$KERNEL_MODULE_BLACKLIST" "$bak" "kernel modules"; then
            add_skipped "kernel modules apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$KERNEL_MODULE_BLACKLIST" "$bak"
    fi
    local existed=0
    [[ -e "$KERNEL_MODULE_BLACKLIST" ]] && existed=1 || true

    cat > "$KERNEL_MODULE_BLACKLIST" <<'BLEOF'
# Managed by SecureLinux-NG — kernel module blacklist (ФСТЭК / CIS)
# Редкие/устаревшие файловые системы
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install jffs2 /bin/false
install squashfs /bin/false
# Редкие сетевые протоколы
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8022 /bin/false
install p8023 /bin/false
# Firewire (DMA-атаки)
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
BLEOF

    # usb_storage: блокировка USB-накопителей (п.10.6 / paranoid — корпоративная политика)
    if profile_allows paranoid; then
        printf '\n# USB-носители (paranoid — корпоративная политика)\ninstall usb_storage /bin/false\n' >> "$KERNEL_MODULE_BLACKLIST"
        add_warning "kernel modules: usb_storage заблокирован (paranoid, п.10.6 корпоративная мера). Если USB-накопители нужны — удалите запись вручную из $KERNEL_MODULE_BLACKLIST"
    fi

    (( existed == 0 )) && record_manifest_created_file "$KERNEL_MODULE_BLACKLIST"
    record_manifest_modified_file "$KERNEL_MODULE_BLACKLIST"
    record_manifest_apply_report "kernel modules: blacklist written: $KERNEL_MODULE_BLACKLIST"

    # Выгружаем модули если загружены
    local mod
    for mod in cramfs freevxfs hfs hfsplus udf jffs2 squashfs                 dccp sctp rds tipc; do
        modprobe -r "$mod" 2>/dev/null || true
    done

    add_safe "kernel modules: blacklist применён: $KERNEL_MODULE_BLACKLIST"
    add_warning "kernel modules: полный эффект blacklist — после перезагрузки"
}

restore_kernel_modules_module() {
    restore_file_from_manifest "$KERNEL_MODULE_BLACKLIST"
}

check_mount_hardening_module() {
    if ! profile_allows paranoid; then
        add_skipped "mount hardening пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    local issues=()
    for target in /dev/shm /var/tmp; do
        if mountpoint -q "$target" 2>/dev/null; then
            local opts
            opts=$(findmnt -n -o OPTIONS --target "$target" 2>/dev/null || echo "")
            [[ "$opts" == *"nosuid"* ]] || issues+=("$target: nosuid missing")
            [[ "$opts" == *"nodev"* ]]  || issues+=("$target: nodev missing")
            [[ "$opts" == *"noexec"* ]] || issues+=("$target: noexec missing")
        fi
    done
    if [[ ${#issues[@]} -eq 0 ]]; then
        add_safe "mount hardening: /dev/shm и /var/tmp проверены"
    else
        add_risky "mount hardening: ${issues[*]} (requires_reboot)"
    fi
}

apply_mount_hardening_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] harden /dev/shm and /var/tmp in /etc/fstab"
        add_skipped "mount hardening dry-run"
        return 0
    fi

    if ! profile_allows paranoid; then
        add_skipped "mount hardening пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    local fstab="/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        add_warning "mount hardening: $fstab не найден"
        return 0
    fi

    local bak="$STATE_DIR/fstab.bak-$TIMESTAMP"
    if ! manifest_has_backup_for "$fstab"; then
        cp -a "$fstab" "$bak"
        record_manifest_backup "$fstab" "$bak"
    fi

    python3 - "$fstab" <<'PYEOF'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
lines = [l for l in lines if not (len(l.split()) >= 2 and l.split()[1] in ('/dev/shm', '/var/tmp'))]
lines.append('tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0\n')
lines.append('tmpfs /var/tmp tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0\n')
path.write_text(''.join(lines), encoding='utf-8')
PYEOF

    record_manifest_modified_file "$fstab"
    record_manifest_apply_report "mount hardening: /dev/shm and /var/tmp entries added to fstab"
    record_manifest_irreversible_change "mount hardening: fstab modified — эффект после перезагрузки"

    # Немедленный remount /dev/shm
    if mountpoint -q /dev/shm 2>/dev/null; then
        mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null             && add_safe "mount hardening: /dev/shm remount выполнен"             || add_warning "mount hardening: /dev/shm remount не удался — эффект после перезагрузки"
    fi

    # /var/tmp tmpfs
    mkdir -p /var/tmp
    if mountpoint -q /var/tmp 2>/dev/null; then
        mount -o remount,nosuid,nodev,noexec /var/tmp 2>/dev/null             && add_safe "mount hardening: /var/tmp remount выполнен"             || add_warning "mount hardening: /var/tmp remount не удался — эффект после перезагрузки"
    else
        mount -t tmpfs -o nosuid,nodev,noexec,mode=1777 tmpfs /var/tmp 2>/dev/null             && add_safe "mount hardening: /var/tmp смонтирован как tmpfs"             || add_warning "mount hardening: /var/tmp mount не удался — эффект после перезагрузки"
    fi
}

restore_mount_hardening_module() {
    if ! restore_manifest_has_report_text "mount hardening"; then
        log "[i]     restore mount hardening: модуль не применялся — пропуск"
        return 0
    fi
    restore_file_from_manifest "/etc/fstab"
    add_warning "restore mount hardening: для полного отката требуется перезагрузка"
}

check_tmp_tmpfs_module() {
    if ! profile_allows paranoid; then
        add_skipped "/tmp tmpfs пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if findmnt -n -o FSTYPE --target /tmp 2>/dev/null | grep -qx "tmpfs"; then
        local opts
        opts=$(findmnt -n -o OPTIONS --target /tmp 2>/dev/null || echo "")
        local issues=()
        [[ "$opts" == *"nosuid"* ]] || issues+=("nosuid missing")
        [[ "$opts" == *"nodev"* ]]  || issues+=("nodev missing")
        [[ "$opts" == *"noexec"* ]] || issues+=("noexec missing")
        if [[ ${#issues[@]} -eq 0 ]]; then
            add_safe "/tmp: tmpfs с nosuid,nodev,noexec"
        else
            add_risky "/tmp: tmpfs но без флагов: ${issues[*]}"
        fi
    else
        add_risky "/tmp: не является tmpfs"
    fi
    if grep -qE '^\s*tmpfs\s+/tmp\s+tmpfs' /etc/fstab 2>/dev/null; then
        add_safe "/tmp: запись в /etc/fstab присутствует"
    else
        add_risky "/tmp: запись в /etc/fstab отсутствует (requires_reboot)"
    fi
}

apply_tmp_tmpfs_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] add tmpfs /tmp to /etc/fstab with nosuid,nodev,noexec,mode=1777"
        log "[DRY-RUN] mount -o remount /tmp"
        add_skipped "/tmp dry-run: tmpfs would be configured"
        return 0
    fi

    if ! profile_allows paranoid; then
        add_skipped "/tmp tmpfs пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    local fstab="/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        add_warning "/tmp: $fstab не найден — пропуск"
        return 0
    fi

    # fstab backup: пропускаем если mount_hardening уже сохранил backup в этом сеансе
    if ! python3 -c "import sys,json,pathlib; d=json.loads(pathlib.Path(sys.argv[1]).read_text()); sys.exit(0 if any(e.get('original')=='/etc/fstab' for e in d.get('backups',[]) if isinstance(e,dict)) else 1)" "$MANIFEST_FILE" 2>/dev/null; then
        local bak="$STATE_DIR/fstab.bak-$TIMESTAMP"
        cp -a "$fstab" "$bak"
        record_manifest_backup "$fstab" "$bak"
    fi

    python3 - "$fstab" <<'PYEOF'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
lines = [l for l in lines if not (len(l.split()) >= 2 and l.split()[1] == '/tmp')]
lines.append('tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0\n')
path.write_text(''.join(lines), encoding='utf-8')
PYEOF

    record_manifest_modified_file "$fstab"
    record_manifest_apply_report "/tmp: tmpfs entry added to /etc/fstab"
    record_manifest_irreversible_change "/tmp: fstab modified — эффект после перезагрузки"

    mkdir -p /tmp
    if findmnt -n -o FSTYPE --target /tmp 2>/dev/null | grep -qx "tmpfs"; then
        mount -o remount,nosuid,nodev,noexec,mode=1777 /tmp 2>/dev/null             && add_safe "/tmp: remount с nosuid,nodev,noexec выполнен"             || add_warning "/tmp: remount не удался — эффект после перезагрузки"
    else
        mount /tmp 2>/dev/null             && add_safe "/tmp: смонтирован как tmpfs"             || add_warning "/tmp: mount не удался — эффект после перезагрузки"
    fi
    add_safe "/tmp: tmpfs настроен (nosuid,nodev,noexec,mode=1777)"
}

restore_tmp_tmpfs_module() {
    if ! restore_manifest_has_report_text "/tmp: tmpfs entry added to /etc/fstab"; then
        log "[i]     restore /tmp tmpfs: модуль не применялся — пропуск"
        return 0
    fi
    if ! restore_manifest_has_report_text "mount hardening"; then
        restore_file_from_manifest "/etc/fstab"
    fi
    add_warning "restore /tmp: для полного отката требуется перезагрузка"
}

check_ufw_module() {
    if ! command -v ufw >/dev/null 2>&1; then
        add_risky "firewall: ufw не установлен"
        return 0
    fi
    if ufw status 2>/dev/null | grep -q "^Status: active"; then
        add_safe "firewall: ufw активен"
    else
        add_risky "firewall: ufw установлен но не активен"
    fi
}

apply_ufw_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install ufw, default deny incoming, allow SSH"
        add_skipped "firewall dry-run: ufw would be configured"
        return 0
    fi

    log "[i]     ufw: установка пакета..."
    apt_update_once
    pkg_installed ufw || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" ufw >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "firewall: не удалось установить ufw"
        record_manifest_warning "firewall: apt-get install ufw failed"
        return 0
    }

    # Конфликт с nftables
    local _nft_active=0 _nft_enabled=0
    if systemctl is-active nftables >/dev/null 2>&1; then _nft_active=1; fi
    if systemctl is-enabled nftables >/dev/null 2>&1; then _nft_enabled=1; fi
    if (( _nft_active == 1 )); then
        systemctl stop nftables 2>/dev/null || true
        systemctl mask nftables 2>/dev/null || true
        record_manifest_apply_report "firewall: nftables pre-state: active"
        record_manifest_apply_report "firewall: nftables stopped and masked"
        log "[i]     firewall: nftables остановлен и замаскирован"
    elif (( _nft_enabled == 1 )); then
        systemctl mask nftables 2>/dev/null || true
        record_manifest_apply_report "firewall: nftables pre-state: enabled"
        log "[i]     firewall: nftables замаскирован"
    fi

    # Определяем SSH порт
    local ssh_port="$UFW_SSH_PORT"
    local detected
    detected=$(grep -Ei '^\s*Port\s+' /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | head -1)
    [[ -z "$detected" ]] && detected=$(grep -Ei '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [[ -n "$detected" ]] && ssh_port="$detected"

    # Если ufw уже активен с правилами — не сбрасывать
    local ufw_was_active=0
    ufw status 2>/dev/null | grep -q "^Status: active" && ufw_was_active=1 || true
    if (( ufw_was_active == 1 )); then
        local ufw_preexisting_ok=1
        if ! ufw allow "${ssh_port}/tcp" comment "SSH" >/dev/null 2>&1; then
            ufw_preexisting_ok=0
            add_warning "firewall: ufw уже активен, но не удалось добавить/подтвердить правило SSH ${ssh_port}/tcp"
            record_manifest_warning "firewall: pre-active ufw, failed to apply SSH rule ${ssh_port}/tcp"
        fi
        local _rule _port _comment
        for _rule in $UFW_EXTRA_RULES; do
            _port="${_rule%%:*}"; _comment="${_rule#*:}"
            if ! ufw allow "$_port" comment "$_comment" >/dev/null 2>&1; then
                ufw_preexisting_ok=0
                add_warning "firewall: ufw уже активен, но не удалось добавить дополнительное правило ${_port} (${_comment})"
                record_manifest_warning "firewall: pre-active ufw, failed to apply extra rule ${_port}:${_comment}"
            fi
        done
        systemctl enable ufw >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
        local ufw_default_in
        ufw_default_in=$(ufw status verbose 2>/dev/null | awk '/^Default:/{print $2}')
        if [[ "$ufw_default_in" != "deny" && "$ufw_default_in" != "reject" ]]; then
            add_error "firewall: ufw уже активен, политика по умолчанию incoming=${ufw_default_in:-unknown} — ФСТЭК требует deny. Исправьте вручную: ufw default deny incoming"
            record_manifest_warning "firewall: ufw pre-active, default incoming policy is not deny"
        else
            add_safe "firewall: ufw активен, политика incoming=deny — соответствует ФСТЭК"
            record_manifest_apply_report "firewall: ufw pre-active, default deny confirmed"
        fi
        if (( ufw_preexisting_ok == 1 )); then
            add_warning "firewall: ufw уже активен — существующие правила сохранены. Проверьте: ufw status verbose"
        else
            add_warning "firewall: ufw уже активен — часть обязательных правил не удалось применить автоматически"
        fi
        record_manifest_apply_report "firewall: ufw pre-active, SSH port=${ssh_port}, extra=${UFW_EXTRA_RULES:-none}"
        record_manifest_warning "firewall restore is partial for pre-active ufw state; existing rules are preserved"
        return 0
    fi

    local ufw_apply_ok=1
    ufw --force reset >/dev/null 2>&1 || ufw_apply_ok=0
    ufw default deny incoming >/dev/null 2>&1 || ufw_apply_ok=0
    ufw default allow outgoing >/dev/null 2>&1 || ufw_apply_ok=0
    ufw allow "${ssh_port}/tcp" comment "SSH" >/dev/null 2>&1 || ufw_apply_ok=0
    local _rule _port _comment
    for _rule in $UFW_EXTRA_RULES; do
        _port="${_rule%%:*}"; _comment="${_rule#*:}"
        ufw allow "$_port" comment "$_comment" >/dev/null 2>&1 || ufw_apply_ok=0
    done
    ufw --force enable >/dev/null 2>&1 || ufw_apply_ok=0
    systemctl enable ufw >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || ufw_apply_ok=0

    if (( ufw_apply_ok == 1 )); then
        record_manifest_apply_report "firewall: ufw enabled, SSH port=${ssh_port}, extra=${UFW_EXTRA_RULES:-none}, default deny incoming"
        record_manifest_irreversible_change "firewall: ufw enabled — отключить вручную: ufw disable"
        add_safe "firewall: ufw включён (SSH port=${ssh_port}, extra=${UFW_EXTRA_RULES:-none}, default deny incoming)"
        log "[i]     firewall: для открытия портов: ufw allow PORT/tcp"
    else
        record_manifest_warning "firewall: ufw command sequence failed during initial enable"
        add_warning "firewall: ufw установлен, но применение правил/enable завершилось с ошибкой"
    fi
}

restore_ufw_module() {
    # ufw не имеет backup — restore только отключает если был включён скриптом
    local was_applied nft_pre_state
    was_applied=$(python3 -c "
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
if not mf.exists(): sys.exit(1)
data = json.loads(mf.read_text(encoding='utf-8'))
reports = data.get('apply_report', [])
print('1' if any('ufw enabled' in r for r in reports) else '0')
" "${RESTORE_SOURCE_MANIFEST}" 2>/dev/null || echo "0")
    if [[ "$was_applied" == "1" ]]; then
        ufw --force disable >/dev/null 2>&1             && log "[i]     restore firewall: ufw отключён"             || log "[WARN]  restore firewall: не удалось отключить ufw"
    else
        if restore_manifest_has_report_text "firewall: ufw pre-active"; then
            log "[i]     restore firewall: pre-active ufw не откатывается автоматически"
            add_warning "restore firewall: для заранее активного ufw откат частичный — существующие правила и состояние до apply сохраняются"
        else
            log "[i]     restore firewall: ufw не был включён скриптом — пропуск"
        fi
    fi
    # восстанавливаем nftables если скрипт его маскировал
    nft_pre_state=$(python3 -c "
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
if not mf.exists(): sys.exit(1)
data = json.loads(mf.read_text(encoding='utf-8'))
reports = data.get('apply_report', [])
if any('nftables pre-state: active' in r for r in reports):
    print('active')
elif any('nftables pre-state: enabled' in r for r in reports):
    print('enabled')
else:
    print('none')
" "${RESTORE_SOURCE_MANIFEST}" 2>/dev/null || echo "none")
    if [[ "$nft_pre_state" == "active" ]]; then
        systemctl unmask nftables 2>/dev/null || true
        systemctl enable --now nftables 2>/dev/null || true
        log "[i]     restore firewall: nftables восстановлен (был active)"
    elif [[ "$nft_pre_state" == "enabled" ]]; then
        systemctl unmask nftables 2>/dev/null || true
        systemctl enable nftables 2>/dev/null || true
        log "[i]     restore firewall: nftables восстановлен (был enabled)"
    fi
}

check_auditd_module() {
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        add_risky "auditd: служба не активна"
        return 0
    fi
    add_safe "auditd: служба активна"
    if [[ -f "$AUDITD_BASELINE_RULES" ]]; then
        add_safe "auditd: baseline rules присутствуют: $AUDITD_BASELINE_RULES"
    else
        add_risky "auditd: baseline rules отсутствуют: $AUDITD_BASELINE_RULES"
    fi
    if profile_allows strict && [[ ! -f "$AUDITD_STRICT_RULES" ]]; then
        add_risky "auditd: extended rules отсутствуют: $AUDITD_STRICT_RULES"
    fi
}

apply_auditd_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install auditd, write ${AUDITD_BASELINE_RULES} (profile: ${PROFILE})"
        add_skipped "auditd dry-run: rules would be written"
        return 0
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        add_warning "auditd: apt-get не найден — установка пропущена"
        return 0
    fi
    log "[i]     auditd: установка пакета..."
    apt_update_once
    pkg_installed auditd || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" auditd >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "auditd: не удалось установить пакет"
        record_manifest_warning "auditd: apt-get install failed"
        return 0
    }
    systemctl enable --now auditd >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true

    mkdir -p "$AUDITD_RULES_DIR"

    # backup baseline
    if [[ -f "$AUDITD_BASELINE_RULES" ]]; then
        local bak="$STATE_DIR/$(basename "$AUDITD_BASELINE_RULES").bak-$TIMESTAMP"
        if ! backup_file_checked "$AUDITD_BASELINE_RULES" "$bak" "auditd baseline"; then
            add_skipped "auditd apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$AUDITD_BASELINE_RULES" "$bak"
    fi
    local existed=0
    [[ -e "$AUDITD_BASELINE_RULES" ]] && existed=1 || true

    cat > "$AUDITD_BASELINE_RULES" <<RULES
# Managed by SecureLinux-NG — auditd baseline (ФСТЭК)
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d -p wa -k sshd
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F perm=wa -k change_file_attr
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F perm=wa -k change_file_attr
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k privileged
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -k privileged
-a always,exit -F arch=b64 -S bind -S connect -k network
-a always,exit -F arch=b32 -S bind -S connect -k network
-w /dev/bus/usb -p rwa -k usb_devices
RULES

    (( existed == 0 )) && record_manifest_created_file "$AUDITD_BASELINE_RULES"
    record_manifest_modified_file "$AUDITD_BASELINE_RULES"
    record_manifest_apply_report "auditd baseline rules written"
    add_safe "auditd: baseline rules written: $AUDITD_BASELINE_RULES"

    # strict+: extended rules
    if profile_allows strict; then
        if [[ -f "$AUDITD_STRICT_RULES" ]]; then
            local bak2="$STATE_DIR/$(basename "$AUDITD_STRICT_RULES").bak-$TIMESTAMP"
            if ! backup_file_checked "$AUDITD_STRICT_RULES" "$bak2" "auditd extended"; then
                add_warning "auditd extended: backup failed, skipping extended rules"
            else
                record_manifest_backup "$AUDITD_STRICT_RULES" "$bak2"
            fi
        fi
        local existed2=0
        [[ -e "$AUDITD_STRICT_RULES" ]] && existed2=1 || true

        cat > "$AUDITD_STRICT_RULES" <<RULES
# Managed by SecureLinux-NG — auditd extended (strict+)
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k exec_from_tmp
-a always,exit -F arch=b32 -S execve -F dir=/tmp -k exec_from_tmp
-w /etc/cron.d       -p wa -k cron
-w /etc/cron.daily   -p wa -k cron
-w /etc/cron.hourly  -p wa -k cron
-w /etc/cron.weekly  -p wa -k cron
-w /etc/cron.monthly -p wa -k cron
-w /etc/crontab      -p wa -k cron
-w /var/spool/cron   -p wa -k cron
-w /etc/hosts        -p wa -k network_config
-w /etc/resolv.conf  -p wa -k network_config
-w /etc/netplan      -p wa -k network_config
-w /etc/systemd/system -p wa -k systemd
-w /lib/systemd/system -p wa -k systemd
-a always,exit -F arch=b64 -S finit_module -k modules
-a always,exit -F arch=b32 -S finit_module -k modules
RULES

        (( existed2 == 0 )) && record_manifest_created_file "$AUDITD_STRICT_RULES"
        record_manifest_modified_file "$AUDITD_STRICT_RULES"
        record_manifest_apply_report "auditd extended rules written"
        add_safe "auditd: extended rules written: $AUDITD_STRICT_RULES"
    fi

    if command -v augenrules >/dev/null 2>&1; then
        if ! augenrules --load >/dev/null 2>&1; then
            add_warning "auditd: правила записаны, но augenrules --load завершился с ошибкой"
            record_manifest_warning "auditd: augenrules --load failed"
        fi
    else
        if ! systemctl restart auditd >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
            add_warning "auditd: правила записаны, но restart auditd завершился с ошибкой"
            record_manifest_warning "auditd: systemctl restart failed after rules update"
        fi
    fi
}

restore_auditd_module() {
    restore_file_from_manifest "$AUDITD_BASELINE_RULES"
    # extended rules применяются только на strict+ — пропускаем если не было в manifest
    if python3 - "$RESTORE_SOURCE_MANIFEST" "$AUDITD_STRICT_RULES" <<'PYCHECK'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
target = sys.argv[2]
in_backups = any(isinstance(e, dict) and e.get("original") == target
                 for e in data.get("backups", []))
in_created = target in data.get("created_files", [])
sys.exit(0 if (in_backups or in_created) else 1)
PYCHECK
    then
        restore_file_from_manifest "$AUDITD_STRICT_RULES"
    else
        log "[i]     restore auditd: extended rules не применялись (профиль не strict+) — пропуск"
    fi
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
    else
        systemctl restart auditd >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
    fi
}

check_password_policy_module() {
    local issues=0
    local expected_max expected_min expected_warn
    expected_min="$PASS_MIN_DAYS"
    expected_warn="$PASS_WARN_AGE"

    if profile_allows paranoid; then
        expected_max="$PASS_MAX_DAYS_PARANOID"
    elif profile_allows strict; then
        expected_max="$PASS_MAX_DAYS_STRICT"
    else
        expected_max="$PASS_MAX_DAYS_BASELINE"
    fi

    local expected_minlen=15
    profile_allows strict && expected_minlen=16
    if [[ -f "$PWQUALITY_CONF" ]]; then
        local actual_minlen
        actual_minlen=$(awk -F'=' '/^[[:space:]]*minlen[[:space:]]*=/{gsub(/ /,"",$2); print $2; exit}' "$PWQUALITY_CONF" 2>/dev/null || echo "")
        if [[ "$actual_minlen" == "$expected_minlen" ]]; then
            add_safe "2.1 pwquality: $PWQUALITY_CONF присутствует (minlen=$actual_minlen)"
        else
            add_risky "2.1 pwquality: $PWQUALITY_CONF отсутствует или minlen не задан (ожидалось $expected_minlen, фактически ${actual_minlen:-unset})"
            issues=1
        fi
    else
        add_risky "2.1 pwquality: $PWQUALITY_CONF отсутствует или minlen не задан"
        issues=1
    fi

    if [[ -f "/etc/pam.d/common-password" ]]; then
        if python3 - /etc/pam.d/common-password <<'PYCHECKPW'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()

def active_has(token):
    for i, line in enumerate(lines):
        s = line.strip()
        if s and not s.startswith('#') and token in s:
            return i
    return None

pwq = active_has('pam_pwquality.so')
pwh = active_has('pam_pwhistory.so')
unix = active_has('pam_unix.so')

ok = pwq is not None and pwh is not None and unix is not None and pwq < pwh < unix
raise SystemExit(0 if ok else 1)
PYCHECKPW
        then
            add_safe "4.2-4.3 common-password: pam_pwquality -> pam_pwhistory -> pam_unix"
        else
            add_risky "4.2-4.3 common-password: нарушен порядок pam_pwquality/pam_pwhistory/pam_unix"
            issues=1
        fi
    else
        add_risky "4.2-4.3 common-password: /etc/pam.d/common-password отсутствует"
        issues=1
    fi

    if [[ -f "$LOGIN_DEFS" ]]; then
        local max min warn
        max=$(awk '/^[[:space:]]*PASS_MAX_DAYS[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || echo "")
        min=$(awk '/^[[:space:]]*PASS_MIN_DAYS[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || echo "")
        warn=$(awk '/^[[:space:]]*PASS_WARN_AGE[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || echo "")
        if [[ "$max" == "$expected_max" && "$min" == "$expected_min" && "$warn" == "$expected_warn" ]]; then
            add_safe "2.1 login.defs: PASS_MAX_DAYS=$max PASS_MIN_DAYS=$min PASS_WARN_AGE=$warn"
        else
            add_risky "2.1 login.defs: ожидалось max=$expected_max min=$expected_min warn=$expected_warn, фактически max=${max:-unset} min=${min:-unset} warn=${warn:-unset}"
            issues=1
        fi
    else
        add_risky "2.1 login.defs: $LOGIN_DEFS отсутствует"
        issues=1
    fi

    # aging проверяется всегда, включая dry-run
    local uid_min
        uid_min="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || true)"
        [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

        local account aging_failed=0 checked=0
        while IFS= read -r account; do
            [[ -n "$account" ]] || continue
            checked=1
            python3 - "$account" "$expected_min" "$expected_max" "$expected_warn" <<'PYSHADOWCHK'
import sys
from pathlib import Path

account = sys.argv[1]
expected_min = sys.argv[2]
expected_max = sys.argv[3]
expected_warn = sys.argv[4]

shadow = Path("/etc/shadow")
if not shadow.exists():
    raise SystemExit(20)

try:
    lines = shadow.read_text(encoding="utf-8", errors="ignore").splitlines()
except PermissionError:
    raise SystemExit(30)

for line in lines:
    if not line or ":" not in line:
        continue
    parts = line.split(":")
    if parts[0] != account:
        continue
    if len(parts) < 6:
        raise SystemExit(21)
    actual_min = parts[3].strip()
    actual_max = parts[4].strip()
    actual_warn = parts[5].strip()
    if actual_min != expected_min:
        raise SystemExit(11)
    if actual_max != expected_max:
        raise SystemExit(10)
    if actual_warn != expected_warn:
        raise SystemExit(12)
    raise SystemExit(0)

raise SystemExit(22)
PYSHADOWCHK
            rc=$?
            if (( rc == 30 )); then
                add_warning "4.1 chage: проверка aging неполная без root — нет доступа к /etc/shadow"
                checked=0
                aging_failed=0
                break
            elif (( rc != 0 )); then
                add_risky "4.1 chage: параметры aging не применены к учетной записи $account"
                aging_failed=1
                break
            fi
        done < <(list_password_policy_target_accounts "$uid_min")

        if (( checked == 1 && aging_failed == 0 )); then
            add_safe "4.1 chage: password aging применён к существующим локальным учетным записям"
        elif (( checked == 0 )); then
            add_warning "4.1 chage: проверка aging неполная — локальные учетные записи не проверены"
        else
            issues=1
        fi
    return $issues
}


list_password_policy_target_accounts() {
    local uid_min="${1:-1000}"
    python3 - "$uid_min" <<'PYJSON'
import sys
from pathlib import Path

uid_min = int(sys.argv[1])
skip_shells = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "false", "nologin"}
seen = set()

for line in Path("/etc/passwd").read_text(encoding="utf-8", errors="ignore").splitlines():
    parts = line.split(":")
    if len(parts) < 7:
        continue
    user, _, uid, _, _, _, shell = parts[:7]
    try:
        uid = int(uid)
    except Exception:
        continue
    if user == "root" or (uid >= uid_min and shell not in skip_shells):
        if user not in seen:
            print(user)
            seen.add(user)
PYJSON
}

normalize_common_password_stack() {
    local path="$1"
    local count="$2"
    python3 - "$path" "$count" <<'PYJSON'
import sys
from pathlib import Path

path = Path(sys.argv[1])
count = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()

def active_has(line: str, token: str) -> bool:
    s = line.strip()
    return bool(s) and not s.startswith("#") and token in s

filtered = [line for line in lines if not active_has(line, "pam_pwhistory")]

unix_idx = next((i for i, line in enumerate(filtered) if active_has(line, "pam_unix.so")), None)
if unix_idx is None:
    raise SystemExit("active pam_unix.so line not found in common-password")

pwq_idx = next((i for i, line in enumerate(filtered) if active_has(line, "pam_pwquality.so")), None)
if pwq_idx is None:
    pwq_line = "password    requisite    pam_pwquality.so retry=3"
else:
    # заменяем существующую строку на эталонную — гарантируем нужные аргументы
    filtered.pop(pwq_idx)
    pwq_line = "password    requisite    pam_pwquality.so retry=3"
    if pwq_idx < unix_idx:
        unix_idx -= 1
    # Если pwq_idx > unix_idx, unix_idx не меняется — корректно

# unix_idx теперь всегда указывает на pam_unix.so; вставляем pwquality перед ним
filtered.insert(unix_idx, pwq_line)
pwq_idx = unix_idx
filtered.insert(pwq_idx + 1, f"password    required    pam_pwhistory.so use_authtok remember={count} enforce_for_root")

path.write_text("\n".join(filtered) + "\n", encoding="utf-8")
PYJSON
}

apply_password_policy_existing_accounts() {
    local max_days="$1"
    local uid_min
    uid_min="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || true)"
    [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

    if (( DRY_RUN == 1 )); then
        while IFS= read -r account; do
            [[ -n "$account" ]] || continue
            log "[DRY-RUN] password aging bootstrap check for '$account'"
            log "[DRY-RUN] chage -m $PASS_MIN_DAYS -M $max_days -W $PASS_WARN_AGE '$account'"
        done < <(list_password_policy_target_accounts "$uid_min")
        add_skipped "4.1 dry-run: password aging would be applied to existing local accounts via chage"
        return 0
    fi

    local account changed=0 action
    while IFS= read -r account; do
        [[ -n "$account" ]] || continue

        action="$(python3 - "$account" "$max_days" <<'PYJSON'
import sys
from datetime import datetime, timezone
from pathlib import Path

account = sys.argv[1]
max_days = int(sys.argv[2])
shadow = Path("/etc/shadow")

if not shadow.exists():
    print("apply")
    raise SystemExit(0)

for line in shadow.read_text(encoding="utf-8", errors="ignore").splitlines():
    if not line or ":" not in line:
        continue
    parts = line.split(":")
    if parts[0] != account:
        continue

    lastchg = parts[2].strip() if len(parts) > 2 else ""
    if lastchg in ("", "-1"):
        print("apply")
        raise SystemExit(0)

    try:
        lastchg_i = int(lastchg)
    except Exception:
        print("apply")
        raise SystemExit(0)

    today = int(datetime.now(timezone.utc).timestamp() // 86400)
    if lastchg_i <= 0 or today > (lastchg_i + max_days):
        print("reset_lastday")
    else:
        print("apply")
    raise SystemExit(0)

print("apply")
PYJSON
)"

        if [[ "$action" == "reset_lastday" ]]; then
            if chage -d "$(date -u +%F)" "$account" && chage -m "$PASS_MIN_DAYS" -M "$max_days" -W "$PASS_WARN_AGE" "$account"; then
                record_manifest_apply_report "4.1 chage bootstrap reset lastday to today for expired user=$account max=$max_days min=$PASS_MIN_DAYS warn=$PASS_WARN_AGE"
                add_warning "4.1 chage: для существующей УЗ $account дата последней смены пароля сдвинута на сегодня, чтобы не вызвать немедленную просрочку"
                changed=1
            else
                add_warning "4.1 chage bootstrap failed for user: $account"
            fi
            continue
        fi

        if chage -m "$PASS_MIN_DAYS" -M "$max_days" -W "$PASS_WARN_AGE" "$account"; then
            record_manifest_apply_report "4.1 chage applied: user=$account max=$max_days min=$PASS_MIN_DAYS warn=$PASS_WARN_AGE"
            changed=1
        else
            add_warning "4.1 chage failed for user: $account"
        fi
    done < <(list_password_policy_target_accounts "$uid_min")

    if (( changed == 1 )); then
        add_safe "4.1 password aging applied to existing local accounts via chage"
    else
        add_warning "4.1 no existing local accounts were updated via chage"
    fi
}

apply_password_policy_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] write '$PWQUALITY_CONF' (profile: ${PROFILE})"
        log "[DRY-RUN] update '$LOGIN_DEFS' PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_WARN_AGE"
        add_skipped "2.1 dry-run: password policy would be applied"
        return 0
    fi

    # --- libpam-pwquality ---
    log "[i]     libpam-pwquality: установка пакетов..."
    apt_update_once
    pkg_installed libpam-pwquality || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" libpam-pwquality cracklib-runtime >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_error "pwquality: не удалось установить libpam-pwquality cracklib-runtime — политика паролей ФСТЭК не применена"
        record_manifest_warning "pwquality: apt-get install failed"
        return 1
    }
    if ! pkg_installed libpam-pwquality; then
        add_error "pwquality: libpam-pwquality не установлен после попытки установки — политика паролей ФСТЭК не применена"
        record_manifest_warning "pwquality: libpam-pwquality not installed"
        return 1
    fi

    # --- pwquality.conf ---
    if [[ -f "$PWQUALITY_CONF" ]]; then
        local bak="$STATE_DIR/$(basename "$PWQUALITY_CONF").bak-$TIMESTAMP"
        if ! manifest_has_backup_for "$PWQUALITY_CONF"; then
            cp -a "$PWQUALITY_CONF" "$bak"
            record_manifest_backup "$PWQUALITY_CONF" "$bak"
        fi
    fi
    local existed=0
    [[ -e "$PWQUALITY_CONF" ]] && existed=1 || true
    local pw_content
    if profile_allows strict; then
        pw_content="$PWQUALITY_STRICT"
    else
        pw_content="$PWQUALITY_BASELINE"
    fi
    mkdir -p /etc/security
    # merge: применяем только параметры ФСТЭК, не затрагивая остальные
    python3 - "$PWQUALITY_CONF" "$pw_content" <<'PYMERGE_PW'
import sys, pathlib
conf = pathlib.Path(sys.argv[1])
new_params = {}
for line in sys.argv[2].splitlines():
    line = line.strip()
    if not line or line.startswith("#"): continue
    if "=" in line:
        k, v = line.split("=", 1)
        new_params[k.strip()] = v.strip()
existing = conf.read_text(encoding="utf-8").splitlines() if conf.exists() else []
result = []
for line in existing:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        result.append(line)
        continue
    if "=" in stripped:
        k = stripped.split("=", 1)[0].strip()
        if k in new_params:
            continue
    result.append(line)
for k, v in new_params.items():
    result.append(f"{k} = {v}")
conf.write_text("\n".join(result) + "\n", encoding="utf-8")
PYMERGE_PW
    local merge_rc=$?
    if (( merge_rc != 0 )); then
        add_error "2.1 pwquality.conf merge завершился с ошибкой (rc=$merge_rc) — политика паролей ФСТЭК не применена"
        record_manifest_warning "2.1 pwquality.conf merge failed (rc=$merge_rc)"
        return 1
    else
        (( existed == 0 )) && record_manifest_created_file "$PWQUALITY_CONF"
        record_manifest_modified_file "$PWQUALITY_CONF"
        record_manifest_apply_report "2.1 pwquality.conf merged (profile: ${PROFILE})"
        add_safe "2.1 pwquality настроен: $PWQUALITY_CONF"
    fi

    # --- pam_pwquality + pam_pwhistory + порядок common-password (Стандарт 4.2–4.3) ---
    local pwhistory_file="/etc/pam.d/common-password"
    if [[ -f "$pwhistory_file" ]]; then
        local pw_history_count=5
        profile_allows strict && pw_history_count=10
        profile_allows paranoid && pw_history_count=24

        local bak_ph="$STATE_DIR/common-password.bak-$TIMESTAMP"
        if ! manifest_has_backup_for "$pwhistory_file"; then
            cp -a "$pwhistory_file" "$bak_ph"
            record_manifest_backup "$pwhistory_file" "$bak_ph"
        fi

        if normalize_common_password_stack "$pwhistory_file" "$pw_history_count"; then
            record_manifest_modified_file "$pwhistory_file"
            record_manifest_apply_report "4.2-4.3 common-password normalized: pam_pwquality -> pam_pwhistory -> pam_unix, remember=${pw_history_count}"
            add_safe "4.2-4.3 common-password нормализован: pam_pwquality -> pam_pwhistory -> pam_unix, remember=${pw_history_count}"
        else
            add_warning "4.2-4.3 normalize failed: $pwhistory_file"
        fi
    else
        add_warning "4.2-4.3 common-password: $pwhistory_file не найден — пропуск"
    fi

    # --- login.defs: PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_WARN_AGE ---
    if [[ -f "$LOGIN_DEFS" ]]; then
        local bak2="$STATE_DIR/login.defs.bak-$TIMESTAMP"
        if ! manifest_has_backup_for "$LOGIN_DEFS"; then
            cp -a "$LOGIN_DEFS" "$bak2"
            record_manifest_backup "$LOGIN_DEFS" "$bak2"
        fi
        local max_days
        if profile_allows paranoid; then
            max_days="$PASS_MAX_DAYS_PARANOID"
        elif profile_allows strict; then
            max_days="$PASS_MAX_DAYS_STRICT"
        else
            max_days="$PASS_MAX_DAYS_BASELINE"
        fi
        python3 - "$LOGIN_DEFS" "$max_days" "$PASS_MIN_DAYS" "$PASS_WARN_AGE" <<'PYJSON'
import sys, pathlib

path = pathlib.Path(sys.argv[1])
params = {
    'PASS_MAX_DAYS': sys.argv[2],
    'PASS_MIN_DAYS': sys.argv[3],
    'PASS_WARN_AGE': sys.argv[4],
    'ENCRYPT_METHOD': 'YESCRYPT',
}

lines = path.read_text(encoding='utf-8').splitlines()
filtered = []

for line in lines:
    stripped = line.lstrip()
    drop = False
    for key in params:
        if stripped.startswith(key + ' ') or stripped.startswith(key + '\t'):
            drop = True
            break
        if stripped.startswith('#'):
            body = stripped[1:].lstrip()
            if body.startswith(key + ' ') or body.startswith(key + '\t'):
                drop = True
                break
    if not drop:
        filtered.append(line)

for key, val in params.items():
    filtered.append(f'{key}\t\t{val}')

path.write_text('\n'.join(filtered) + '\n', encoding='utf-8')
PYJSON
        record_manifest_modified_file "$LOGIN_DEFS"
        record_manifest_apply_report "2.1 login.defs updated: PASS_MAX_DAYS=$max_days PASS_MIN_DAYS=$PASS_MIN_DAYS PASS_WARN_AGE=$PASS_WARN_AGE"
        apply_password_policy_existing_accounts "$max_days"
        add_safe "2.1 login.defs: PASS_MAX_DAYS=$max_days PASS_MIN_DAYS=$PASS_MIN_DAYS PASS_WARN_AGE=$PASS_WARN_AGE ENCRYPT_METHOD=YESCRYPT"
    else
        add_warning "2.1 $LOGIN_DEFS не найден — password aging пропущен"
    fi
}

restore_password_policy_module() {
    restore_file_from_manifest "$PWQUALITY_CONF"
    restore_file_from_manifest "$LOGIN_DEFS"
    restore_file_from_manifest "/etc/pam.d/common-password"
}

check_faillock_module() {
    if ! profile_allows strict; then
        add_skipped "2.1 pam_faillock пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if [[ ! -f "$FAILLOCK_CONF" ]]; then
        add_risky "2.1 pam_faillock: $FAILLOCK_CONF отсутствует"
        return 0
    fi
    if grep -Eq '^\s*deny\s*=\s*5\s*$' "$FAILLOCK_CONF" && grep -Eq '^\s*unlock_time\s*=\s*900\s*$' "$FAILLOCK_CONF"; then
        add_safe "2.1 pam_faillock: $FAILLOCK_CONF соответствует strict+ (deny=5 unlock_time=900)"
    else
        add_risky "2.1 pam_faillock: ожидаются deny=5 и unlock_time=900 в $FAILLOCK_CONF"
    fi
}

apply_faillock_module() {
    if ! profile_allows strict; then
        add_skipped "2.1 pam_faillock пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] write '$FAILLOCK_CONF' (profile: ${PROFILE})"
        add_skipped "2.1 dry-run: faillock.conf would be written"
        return 0
    fi

    if [[ ! -f "/lib/security/pam_faillock.so" && ! -f "/lib/x86_64-linux-gnu/security/pam_faillock.so" ]]; then
        add_warning "2.1 pam_faillock.so не найден — пропуск faillock"
        record_manifest_warning "2.1 pam_faillock.so not found"
        add_skipped "2.1 apply skipped: pam_faillock.so missing"
        return 0
    fi

    if [[ -f "$FAILLOCK_CONF" ]]; then
        local backup_path="$STATE_DIR/$(basename "$FAILLOCK_CONF").bak-$TIMESTAMP"
        if ! manifest_has_backup_for "$FAILLOCK_CONF"; then
            if ! backup_file_checked "$FAILLOCK_CONF" "$backup_path" "2.1 faillock"; then
                add_skipped "2.1 apply skipped: faillock backup failed"
                return 0
            fi
            record_manifest_backup "$FAILLOCK_CONF" "$backup_path"
        fi
    fi

    local existed_before=0
    [[ -e "$FAILLOCK_CONF" ]] && existed_before=1 || true

    local content="$FAILLOCK_CONF_STRICT"

    # merge: применяем только параметры ФСТЭК, не затрагивая остальные
    python3 - "$FAILLOCK_CONF" "$content" <<'PYMERGE_FL'
import sys, pathlib
conf = pathlib.Path(sys.argv[1])
new_keyed = {}
new_flags = set()
for entry in sys.argv[2].splitlines():
    entry = entry.strip()
    if not entry or entry.startswith("#"): continue
    if "=" in entry:
        k, v = entry.split("=", 1)
        new_keyed[k.strip()] = v.strip()
    else:
        new_flags.add(entry)
existing = conf.read_text(encoding="utf-8").splitlines() if conf.exists() else []
result = []
for line in existing:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        result.append(line)
        continue
    if "=" in stripped:
        k = stripped.split("=", 1)[0].strip()
        if k in new_keyed:
            continue
    else:
        if stripped in new_flags:
            continue
    result.append(line)
for k, v in new_keyed.items():
    result.append(f"{k} = {v}")
for flag in sorted(new_flags):
    result.append(flag)
conf.write_text("\n".join(result) + "\n", encoding="utf-8")
PYMERGE_FL
    local merge_rc=$?
    if (( merge_rc != 0 )); then
        add_error "2.1 faillock.conf merge завершился с ошибкой (rc=$merge_rc)"
        record_manifest_warning "2.1 faillock.conf merge failed (rc=$merge_rc)"
        return 1
    fi
    (( existed_before == 0 )) && record_manifest_created_file "$FAILLOCK_CONF"
    record_manifest_modified_file "$FAILLOCK_CONF"
    record_manifest_apply_report "2.1 faillock.conf merged (profile: ${PROFILE})"
    add_safe "2.1 pam_faillock настроен: $FAILLOCK_CONF (profile: ${PROFILE})"
}

restore_faillock_module() {
    if ! restore_manifest_has_path "$FAILLOCK_CONF"; then
        log "[i]     restore faillock: модуль не применялся — пропуск"
        return 0
    fi
    restore_file_from_manifest "$FAILLOCK_CONF"
}

restore_pam_wheel_module() {
    restore_file_from_manifest "$PAM_SU_FILE"
    if restore_has_created_group "wheel"; then
        if getent group wheel >/dev/null 2>&1; then
            groupdel wheel && add_safe "restore: removed created group wheel" || add_warning "restore: failed to remove group wheel"
        else
            add_safe "restore: created group wheel already absent"
        fi
    fi
}

restore_sudo_policy_module() {
    restore_file_from_manifest "$SUDO_POLICY_DROPIN"
}

write_metadata_snapshot() {
    local target="$1"
    local snapshot="$2"
    python3 - "$target" "$snapshot" <<'PYJSON'
import sys, pathlib, os, stat
target = pathlib.Path(sys.argv[1])
snapshot = pathlib.Path(sys.argv[2])
st = target.stat()
snapshot.write_text(
    f"TARGET={target}\nMODE={stat.S_IMODE(st.st_mode):o}\nUID={st.st_uid}\nGID={st.st_gid}\n",
    encoding="utf-8"
)
PYJSON
}

restore_read_stat_field() {
    local meta_file="$1"
    local key="$2"
    python3 - "$meta_file" "$key" <<'PYJSON'
import sys, pathlib, re
path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
text = path.read_text(encoding='utf-8', errors='replace')

machine_patterns = {
    "access": r"(?m)^MODE=(\d+)$",
    "uid": r"(?m)^UID=(\d+)$",
    "gid": r"(?m)^GID=(\d+)$",
}
legacy_patterns = {
    "access": r"Access:\s*\((\d+)/",
    "uid": r"Uid:\s*\(\s*(\d+)/",
    "gid": r"Gid:\s*\(\s*(\d+)/",
}

m = re.search(machine_patterns[key], text)
if m:
    print(m.group(1))
    raise SystemExit(0)

m = re.search(legacy_patterns[key], text)
print(m.group(1) if m else "")
PYJSON
}

restore_metadata_from_stat_snapshot() {
    local target="$1"
    local backup
    local mode uid gid

    backup="$(restore_lookup_backup "$target")"
    if [[ -z "$backup" || ! -f "$backup" ]]; then
        log "[i]     restore: нет снапшота прав для $target (файл не изменялся при apply)"
        return 0
    fi

    mode="$(restore_read_stat_field "$backup" access)"
    uid="$(restore_read_stat_field "$backup" uid)"
    gid="$(restore_read_stat_field "$backup" gid)"

    if [[ -z "$mode" || -z "$uid" || -z "$gid" ]]; then
        log "[i]     restore: $backup не является снапшотом прав для $target — пропуск"
        return 0
    fi

    if [[ ! -e "$target" ]]; then
        add_warning "restore: target missing for metadata restore: $target"
        return 0
    fi

    chown "${uid}:${gid}" "$target"
    chmod "$mode" "$target"
    add_safe "restore: restored metadata for $target from snapshot $backup"
}

restore_fs_critical_files_module() {
    local f
    for f in "${FS_CRITICAL_FILES[@]}"; do
        restore_metadata_from_stat_snapshot "$f"
    done
}

restore_cron_targets_module() {
    local spec path
    for spec in "${CRON_CRITICAL_TARGETS[@]}"; do
        path="$(cron_target_path "$spec")"
        restore_metadata_from_stat_snapshot "$path"
    done
}

restore_systemd_unit_targets_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/etc/systemd/system/" in e.get("original", "") and ".meta-" in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

record_runtime_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.2 runtime paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.2 runtime paths checked: total=$total ok=$ok risky=$risky"
    fi
}

fs_expected_mode() {
    case "$1" in
        /etc/passwd|/etc/group) echo "644" ;;
        /etc/shadow) echo "640" ;;
        *) return 1 ;;
    esac
}

fs_expected_group() {
    case "$1" in
        /etc/passwd|/etc/group) echo "root" ;;
        /etc/shadow) echo "shadow" ;;
        *) return 1 ;;
    esac
}

fs_actual_mode() {
    stat -c '%a' "$1"
}

fs_actual_owner_group() {
    stat -c '%U:%G' "$1"
}

check_fs_critical_file_one() {
    local target="$1"
    local exp_mode exp_group actual_mode actual_og
    exp_mode="$(fs_expected_mode "$target")" || { add_error "2.3.1 unknown target: $target"; return 1; }
    exp_group="$(fs_expected_group "$target")" || { add_error "2.3.1 unknown target group: $target"; return 1; }

    if [[ ! -e "$target" ]]; then
        add_error "2.3.1 file not found: $target"
        return 1
    fi

    actual_mode="$(fs_actual_mode "$target")"
    actual_og="$(fs_actual_owner_group "$target")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:${exp_group}" ]]; then
        add_safe "2.3.1 compliant: $target mode=$actual_mode owner/group=$actual_og"
    else
        add_risky "2.3.1 non-compliant: $target expected root:${exp_group} mode=${exp_mode}, actual ${actual_og} mode=${actual_mode}"
    fi
}

check_fs_critical_files_module() {
    local f
    for f in "${FS_CRITICAL_FILES[@]}"; do
        check_fs_critical_file_one "$f"
    done
}

check_empty_passwords_module() {
    python3 - <<'PYJSON'
from pathlib import Path

shadow = Path("/etc/shadow")
if not shadow.exists():
    print("RISK\t/etc/shadow\tmissing")
    print("SUMMARY\t0\t0\t1")
    raise SystemExit(0)

try:
    lines = shadow.read_text(encoding="utf-8", errors="ignore").splitlines()
except PermissionError:
    print("RISK\t/etc/shadow\tpermission_denied")
    print("SUMMARY\t0\t0\t1")
    raise SystemExit(0)
except Exception as e:
    print(f"RISK\t/etc/shadow\tread_failed:{e}")
    print("SUMMARY\t0\t0\t1")
    raise SystemExit(0)

ok = 0
risky = 0
for line in lines:
    if not line or ":" not in line:
        continue
    parts = line.split(":")
    if len(parts) < 2:
        continue
    user, pwd = parts[0], parts[1]
    if pwd == "":
        risky += 1
        print(f"RISK\t{user}\tempty_password_field")
    else:
        ok += 1

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
PYJSON
}

record_empty_passwords_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$total" == "0" && "$risky" != "0" ]]; then
        add_warning "2.1.1 /etc/shadow недоступен для чтения без привилегий; выполнена только ограниченная проверка"
        add_risky "2.1.1 password fields check incomplete: total=$total ok=$ok risky=$risky"
        return 0
    fi
    if [[ "$risky" == "0" ]]; then
        add_safe "2.1.1 password fields checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.1.1 password fields checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_empty_passwords_module() {
    if (( DRY_RUN == 1 )); then
        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.1.1 empty-password scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.1.1 would lock account '$a' reason='$b'"
                    ;;
            esac
        done < <(check_empty_passwords_module)
        add_skipped "2.1.1 dry-run: accounts with empty password field would be locked"
        return 0
    fi

    if (( EUID != 0 )); then
        add_warning "2.1.1 apply skipped: требуется root для работы с /etc/shadow"
        record_manifest_warning "2.1.1 apply skipped: requires root"
        add_skipped "2.1.1 apply skipped: requires root"
        return 0
    fi

    # Сохраняем только список пользователей с пустым паролем — без хэшей
    local empty_users_file="$STATE_DIR/empty-password-users-$TIMESTAMP.txt"
    python3 - "$empty_users_file" <<'PYJSON'
import sys, pathlib
shadow = pathlib.Path("/etc/shadow")
out_file = pathlib.Path(sys.argv[1])
lines = shadow.read_text(encoding="utf-8", errors="ignore").splitlines()
result = []
empty_users = []

for line in lines:
    if ":" not in line:
        result.append(line)
        continue
    parts = line.split(":")
    if len(parts) < 2:
        result.append(line)
        continue
    if parts[1] == "":
        empty_users.append(parts[0])
        parts[1] = "!"
        result.append(":".join(parts))
    else:
        result.append(line)

if empty_users:
    import tempfile, os
    shadow_dir = shadow.parent
    fd, tmp_path = tempfile.mkstemp(dir=str(shadow_dir), prefix=".shadow.tmp.")
    try:
        os.write(fd, ("\n".join(result) + "\n").encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, str(shadow))
    except Exception:
        os.close(fd) if not os.get_inheritable(fd) else None
        os.unlink(tmp_path)
        raise
    out_file.write_text("\n".join(empty_users) + "\n", encoding="utf-8")
    out_file.chmod(0o600)
PYJSON

    if [[ -f "$empty_users_file" ]]; then
        record_manifest_backup "/etc/shadow" "$empty_users_file"
        record_manifest_modified_file "/etc/shadow"
        record_manifest_apply_report "2.1.1 empty password fields locked in /etc/shadow"
        add_safe "2.1.1 empty password fields processed in /etc/shadow"
    else
        record_manifest_apply_report "2.1.1 no empty password fields found in /etc/shadow"
        add_safe "2.1.1 no empty password fields found in /etc/shadow"
    fi
}

apply_fs_critical_file_one() {
    local target="$1"
    local exp_mode exp_group actual_mode actual_og backup_path
    exp_mode="$(fs_expected_mode "$target")" || { add_error "2.3.1 unknown target: $target"; return 1; }
    exp_group="$(fs_expected_group "$target")" || { add_error "2.3.1 unknown target group: $target"; return 1; }

    [[ -e "$target" ]] || { add_error "2.3.1 file not found: $target"; return 1; }

    actual_mode="$(fs_actual_mode "$target")"
    actual_og="$(fs_actual_owner_group "$target")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:${exp_group}" ]]; then
        add_safe "2.3.1 already compliant: $target"
        record_manifest_apply_report "2.3.1 already compliant: $target"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] backup '$target' metadata -> '$STATE_DIR/$(basename "$target").meta-$TIMESTAMP.txt'"
        log "[DRY-RUN] chown root:${exp_group} '$target'"
        log "[DRY-RUN] chmod ${exp_mode} '$target'"
        add_skipped "2.3.1 dry-run: metadata would be corrected for $target"
        return 0
    fi

    backup_path="$STATE_DIR/$(basename "$target").meta-$TIMESTAMP.txt"
    write_metadata_snapshot "$target" "$backup_path"
    record_manifest_backup "$target" "$backup_path"

    chown "root:${exp_group}" "$target"
    chmod "${exp_mode}" "$target"

    actual_mode="$(fs_actual_mode "$target")"
    actual_og="$(fs_actual_owner_group "$target")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:${exp_group}" ]]; then
        record_manifest_modified_file "$target"
        record_manifest_apply_report "2.3.1 corrected metadata for $target"
        if [[ "$target" == "/etc/passwd" || "$target" == "/etc/group" || "$target" == "/etc/shadow" ]]; then
            record_manifest_irreversible_change "2.3.1 metadata changed on $target; previous mode/ownership recorded in backup metadata only"
        fi
        add_safe "2.3.1 corrected: $target mode=$actual_mode owner/group=$actual_og"
    else
        add_error "2.3.1 verification failed after correction: $target"
        record_manifest_warning "2.3.1 verification failed after correction: $target"
        return 1
    fi
}

apply_fs_critical_files_module() {
    local f
    for f in "${FS_CRITICAL_FILES[@]}"; do
        apply_fs_critical_file_one "$f"
    done
}

cron_target_mode() {
    echo "$1" | awk -F: '{print $3}'
}

cron_target_owner() {
    echo "$1" | awk -F: '{print $4}'
}

cron_target_group() {
    echo "$1" | awk -F: '{print $5}'
}

cron_target_path() {
    echo "$1" | awk -F: '{print $1}'
}

cron_target_type() {
    echo "$1" | awk -F: '{print $2}'
}

check_cron_target_one() {
    local spec="$1" path type exp_mode exp_owner exp_group actual_mode actual_og
    path="$(cron_target_path "$spec")"
    type="$(cron_target_type "$spec")"
    exp_mode="$(cron_target_mode "$spec")"
    exp_owner="$(cron_target_owner "$spec")"
    exp_group="$(cron_target_group "$spec")"

    if [[ ! -e "$path" ]]; then
        add_risky "2.3.6 cron target missing: $path"
        return 0
    fi

    if [[ "$type" == "file" && ! -f "$path" ]]; then
        add_risky "2.3.6 cron target type mismatch: expected file, got $path"
        return 0
    fi
    if [[ "$type" == "dir" && ! -d "$path" ]]; then
        add_risky "2.3.6 cron target type mismatch: expected dir, got $path"
        return 0
    fi

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "${exp_owner}:${exp_group}" ]]; then
        add_safe "2.3.6 compliant: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_risky "2.3.6 non-compliant: $path expected ${exp_owner}:${exp_group} mode=${exp_mode}, actual ${actual_og} mode=${actual_mode}"
    fi
}

check_cron_targets_module() {
    local spec
    for spec in "${CRON_CRITICAL_TARGETS[@]}"; do
        check_cron_target_one "$spec"
    done
}

apply_cron_target_one() {
    local spec="$1" path exp_mode exp_owner exp_group actual_mode actual_og backup_path
    path="$(cron_target_path "$spec")"
    exp_mode="$(cron_target_mode "$spec")"
    exp_owner="$(cron_target_owner "$spec")"
    exp_group="$(cron_target_group "$spec")"

    if [[ ! -e "$path" ]]; then
        add_risky "2.3.6 skipped missing cron target: $path"
        return 0
    fi

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "${exp_owner}:${exp_group}" ]]; then
        add_safe "2.3.6 already compliant: $path"
        record_manifest_apply_report "2.3.6 already compliant: $path"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] backup '$path' metadata -> '$STATE_DIR/$(basename "$path").meta-$TIMESTAMP.txt'"
        log "[DRY-RUN] chown ${exp_owner}:${exp_group} '$path'"
        log "[DRY-RUN] chmod ${exp_mode} '$path'"
        add_skipped "2.3.6 dry-run: cron target metadata would be corrected for $path"
        return 0
    fi

    backup_path="$STATE_DIR/$(basename "$path").meta-$TIMESTAMP.txt"
    write_metadata_snapshot "$path" "$backup_path"
    record_manifest_backup "$path" "$backup_path"

    chown "${exp_owner}:${exp_group}" "$path"
    chmod "${exp_mode}" "$path"

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "${exp_owner}:${exp_group}" ]]; then
        record_manifest_modified_file "$path"
        record_manifest_apply_report "2.3.6 corrected metadata for $path"
        record_manifest_irreversible_change "2.3.6 metadata changed on $path; previous mode/ownership recorded in backup metadata only"
        add_safe "2.3.6 corrected: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_error "2.3.6 verification failed after correction: $path"
        record_manifest_warning "2.3.6 verification failed after correction: $path"
        return 1
    fi
}

apply_cron_targets_module() {
    local spec
    for spec in "${CRON_CRITICAL_TARGETS[@]}"; do
        apply_cron_target_one "$spec"
    done
}

systemd_unit_candidates() {
    [[ -d "$SYSTEMD_ETC_DIR" ]] || return 0
    python3 - <<'PYJSON'
from pathlib import Path
base = Path("/etc/systemd/system")
suffixes = {".service", ".socket", ".timer", ".mount", ".path", ".target", ".slice"}
for p in sorted(base.rglob("*")):
    if p.is_dir():
        if p.name.endswith(".d") or p == base:
            print(f"{p}:dir")
        continue
    if p.suffix in suffixes or (p.parent.name.endswith(".d") and p.suffix == ".conf"):
        print(f"{p}:file")
PYJSON
}

check_systemd_unit_one() {
    local path="$1" kind="$2" exp_mode actual_mode actual_og
    if [[ "$kind" == "dir" ]]; then
        exp_mode="755"
    else
        exp_mode="644"
    fi

    if [[ -L "$path" && ! -e "$path" ]]; then
        log_debug "2.3.5 symlink target absent (silent skip): $path"
        return 0
    fi
    if [[ ! -e "$path" ]]; then
        log_debug "2.3.5 systemd target absent (silent skip): $path"
        return 0
    fi

    if [[ -L "$path" ]]; then
        return 0  # symlink managed by package — no output needed
    fi

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:root" ]]; then
        add_safe "2.3.5 compliant: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_risky "2.3.5 non-compliant: $path expected root:root mode=${exp_mode}, actual ${actual_og} mode=${actual_mode}"
    fi
}

check_systemd_unit_targets_module() {
    local item path kind
    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        path="${item%:*}"
        kind="${item##*:}"
        check_systemd_unit_one "$path" "$kind"
    done < <(systemd_unit_candidates)
}

apply_systemd_unit_one() {
    local path="$1" kind="$2" exp_mode actual_mode actual_og backup_path
    if [[ "$kind" == "dir" ]]; then
        exp_mode="755"
    else
        exp_mode="644"
    fi

    [[ -e "$path" ]] || { log_debug "2.3.5 systemd target absent (silent skip): $path"; return 0; }

    if [[ -L "$path" ]]; then
        return 0  # symlink managed by package — no output needed
    fi

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:root" ]]; then
        add_safe "2.3.5 already compliant: $path"
        record_manifest_apply_report "2.3.5 already compliant: $path"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] backup '$path' metadata -> '$STATE_DIR/$(basename "$path").meta-$TIMESTAMP.txt'"
        log "[DRY-RUN] chown root:root '$path'"
        log "[DRY-RUN] chmod ${exp_mode} '$path'"
        add_skipped "2.3.5 dry-run: systemd target metadata would be corrected for $path"
        return 0
    fi

    backup_path="$STATE_DIR/$(basename "$path").meta-$TIMESTAMP.txt"
    write_metadata_snapshot "$path" "$backup_path"
    record_manifest_backup "$path" "$backup_path"

    chown root:root "$path"
    chmod "$exp_mode" "$path"

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:root" ]]; then
        record_manifest_modified_file "$path"
        record_manifest_apply_report "2.3.5 corrected metadata for $path"
        record_manifest_irreversible_change "2.3.5 metadata changed on $path; previous mode/ownership recorded in backup metadata only"
        add_safe "2.3.5 corrected: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_error "2.3.5 verification failed after correction: $path"
        record_manifest_warning "2.3.5 verification failed after correction: $path"
        return 1
    fi
}

apply_systemd_unit_targets_module() {
    local item path kind
    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        path="${item%:*}"
        kind="${item##*:}"
        apply_systemd_unit_one "$path" "$kind"
    done < <(systemd_unit_candidates)
}

sudo_policy_status() {
    if [[ -f "$SUDO_POLICY_DROPIN" ]]; then
        if grep -Eq '^[[:space:]]*%wheel[[:space:]]+ALL=\(ALL:ALL\)[[:space:]]+ALL[[:space:]]*$' "$SUDO_POLICY_DROPIN"; then
            echo "configured"
            return 0
        fi
        echo "conflict"
        return 0
    fi
    echo "absent"
}

check_sudo_policy_module() {
    local status
    status="$(sudo_policy_status)"

    case "$status" in
        configured)
            add_safe "2.2.2 sudo policy enforced via drop-in: $SUDO_POLICY_DROPIN"
            ;;
        absent)
            add_risky "2.2.2 sudo policy is not enforced yet: missing $SUDO_POLICY_DROPIN"
            ;;
        conflict)
            add_risky "2.2.2 sudo policy drop-in exists but content differs from managed policy: $SUDO_POLICY_DROPIN"
            ;;
        *)
            add_error "2.2.2 sudo policy status detection failed"
            ;;
    esac
}

apply_sudo_policy_module() {
    local status
    status="$(sudo_policy_status)"

    case "$status" in
        configured)
            add_safe "2.2.2 sudo policy already configured: $SUDO_POLICY_DROPIN"
            record_manifest_apply_report "2.2.2 already compliant: $SUDO_POLICY_DROPIN"
            return 0
            ;;
        absent|conflict)
            ;;
        *)
            add_error "2.2.2 sudo policy status detection failed during apply"
            return 1
            ;;
    esac

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sudoers.d'"
        if [[ -f "$SUDO_POLICY_DROPIN" ]]; then
            log "[DRY-RUN] backup '$SUDO_POLICY_DROPIN' -> '$STATE_DIR/$(basename "$SUDO_POLICY_DROPIN").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] write '$SUDO_POLICY_DROPIN' with managed sudo policy for %wheel"
        log "[DRY-RUN] chmod 440 '$SUDO_POLICY_DROPIN'"
        log "[DRY-RUN] visudo -cf '$SUDO_POLICY_DROPIN'"
        add_skipped "2.2.2 dry-run: sudo policy drop-in would be written"
        return 0
    fi

    mkdir -p /etc/sudoers.d

    if [[ -f "$SUDO_POLICY_DROPIN" ]]; then
        local backup_path="$STATE_DIR/$(basename "$SUDO_POLICY_DROPIN").bak-$TIMESTAMP"
        if ! backup_file_checked "$SUDO_POLICY_DROPIN" "$backup_path" "2.2.2 sudo policy"; then
            add_skipped "2.2.2 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SUDO_POLICY_DROPIN" "$backup_path"
    fi

    local existed_before=0
    [[ -e "$SUDO_POLICY_DROPIN" ]] && existed_before=1 || true

    printf '%s' "$SUDO_POLICY_CONTENT" > "$SUDO_POLICY_DROPIN"
    chmod 440 "$SUDO_POLICY_DROPIN"

    if visudo -cf "$SUDO_POLICY_DROPIN" >/dev/null 2>&1; then
        (( existed_before == 0 )) && record_manifest_created_file "$SUDO_POLICY_DROPIN"
        record_manifest_modified_file "$SUDO_POLICY_DROPIN"
        record_manifest_apply_report "2.2.2 enforced via $SUDO_POLICY_DROPIN"
        add_safe "2.2.2 sudo policy enforced via drop-in: $SUDO_POLICY_DROPIN"
    else
        add_error "2.2.2 visudo validation failed for $SUDO_POLICY_DROPIN"
        record_manifest_warning "2.2.2 visudo validation failed for $SUDO_POLICY_DROPIN"
        if [[ -n "${backup_path:-}" && -f "$backup_path" ]]; then
            cp -a "$backup_path" "$SUDO_POLICY_DROPIN" || true
            log "[i]     2.2.2 rollback: $SUDO_POLICY_DROPIN восстановлен из backup"
        else
            rm -f "$SUDO_POLICY_DROPIN" || true
            log "[i]     2.2.2 rollback: $SUDO_POLICY_DROPIN удалён"
        fi
        return 1
    fi
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
        if ! backup_file_checked "$SSH_ROOT_LOGIN_DROPIN" "$backup_path" "2.1.2 SSH root login"; then
            add_skipped "2.1.2 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$SSH_ROOT_LOGIN_DROPIN" "$backup_path"
    fi

    local existed_before=0
    [[ -e "$SSH_ROOT_LOGIN_DROPIN" ]] && existed_before=1 || true

    printf '%s' "$SSH_ROOT_LOGIN_CONTENT" > "$SSH_ROOT_LOGIN_DROPIN"

    if sshd -t >/dev/null 2>&1; then
        (( existed_before == 0 )) && record_manifest_created_file "$SSH_ROOT_LOGIN_DROPIN"
        record_manifest_modified_file "$SSH_ROOT_LOGIN_DROPIN"
        record_manifest_apply_report "2.1.2 enforced via $SSH_ROOT_LOGIN_DROPIN"
        if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; then
            add_safe "2.1.2 SSH root login disabled via drop-in: $SSH_ROOT_LOGIN_DROPIN"
        else
            add_warning "2.1.2 SSH root login drop-in записан, но reload ssh/sshd не удался"
            record_manifest_warning "2.1.2 ssh reload failed after writing drop-in"
        fi
    else
        add_error "2.1.2 sshd -t failed after writing $SSH_ROOT_LOGIN_DROPIN"
        record_manifest_warning "2.1.2 sshd -t failed after writing $SSH_ROOT_LOGIN_DROPIN"
        if [[ -n "${backup_path:-}" && -f "$backup_path" ]]; then
            cp -a "$backup_path" "$SSH_ROOT_LOGIN_DROPIN"
            log "[i]     2.1.2 rollback: $SSH_ROOT_LOGIN_DROPIN восстановлен из backup"
        else
            rm -f "$SSH_ROOT_LOGIN_DROPIN"
            log "[i]     2.1.2 rollback: $SSH_ROOT_LOGIN_DROPIN удалён"
        fi
        return 1
    fi
}


pam_wheel_group_exists() {
    getent group wheel >/dev/null 2>&1
}

pam_wheel_rule_present() {
    [[ -f "$PAM_SU_FILE" ]] || return 1
    # Проверяем наличие активной строки с pam_wheel.so, use_uid и group=wheel (любой порядок)
    awk '/^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so/ && /use_uid/ && /group=wheel/ {found=1} END{exit !found}' "$PAM_SU_FILE"
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
        if groupadd wheel; then
            python3 - "$MANIFEST_FILE" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("created_groups", [])
if "wheel" not in lst:
    lst.append("wheel")
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
            record_manifest_apply_report "2.2.1 created group wheel"
        else
            add_error "2.2.1 failed to create group wheel"
            record_manifest_warning "2.2.1 failed to create group wheel"
            return 1
        fi
    fi

    [[ -f "$PAM_SU_FILE" ]] || die "Файл не найден: $PAM_SU_FILE"

    local backup_path="$STATE_DIR/$(basename "$PAM_SU_FILE").bak-$TIMESTAMP"
    if ! manifest_has_backup_for "$PAM_SU_FILE"; then
        if ! backup_file_checked "$PAM_SU_FILE" "$backup_path" "2.2.1 pam_wheel"; then
            add_skipped "2.2.1 apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$PAM_SU_FILE" "$backup_path"
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
    for cmd in bash python3 stat uname grep awk date mkdir cat systemctl visudo sysctl; do
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
                _PROFILE_SET_BY_CLI=1
                ;;
            --profile=*)
                PROFILE="${1#*=}"
                _PROFILE_SET_BY_CLI=1
                ;;
            --config)
                shift
                [[ $# -gt 0 ]] || die "После --config требуется путь к файлу"
                CONFIG_FILE="$1"
                ;;
            --config=*)
                CONFIG_FILE="${1#*=}"
                ;;
            --manifest)
                shift
                [[ $# -gt 0 ]] || die "После --manifest требуется путь к manifest"
                RESTORE_MANIFEST="$1"
                ;;
            --manifest=*)
                RESTORE_MANIFEST="${1#*=}"
                ;;
            *)
                die "Неизвестный аргумент: $1"
                ;;
        esac
        shift
    done
}

validate_args() {
    if [[ -z "$MODE" ]]; then usage; exit 0; fi

    case "$PROFILE" in
        baseline|strict|paranoid) ;;
        *) die "Недопустимый профиль: $PROFILE" ;;
    esac

    if (( DRY_RUN == 1 )) && [[ "$MODE" != "apply" ]]; then
        die "--dry-run допустим только вместе с --apply"
    fi

    if [[ -n "$RESTORE_MANIFEST" && "$MODE" != "restore" ]]; then
        die "--manifest допустим только вместе с --restore"
    fi

    if [[ -n "$CONFIG_FILE" ]] && [[ ! -f "$CONFIG_FILE" ]]; then
        die "Файл конфига не найден: $CONFIG_FILE"
    fi
}

validate_args_post_config() {
    case "$PROFILE" in
        baseline|strict|paranoid) ;;
        *) die "Недопустимый профиль после загрузки конфига: $PROFILE" ;;
    esac
}

validate_execution_context() {
    case "$MODE" in
        apply)
            if (( DRY_RUN == 0 && EUID != 0 )); then
                die "--apply без --dry-run требует root"
            fi
            ;;
        restore)
            if (( EUID != 0 )); then
                die "--restore требует root"
            fi
            ;;
        check|report)
            :
            ;;
        *)
            die "Внутренняя ошибка: неизвестный режим '$MODE' при проверке контекста"
            ;;
    esac
}

load_config() {
    [[ -n "$CONFIG_FILE" ]] || return 0

    local _cfg_rc
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
    _cfg_rc=$?
    if (( _cfg_rc != 0 )); then
        die "Ошибка в config-файле: $CONFIG_FILE — выполнение прервано"
    fi

    while IFS='=' read -r k v; do
        [[ -n "${k:-}" ]] || continue
        case "$k" in
            PROFILE)
                (( _PROFILE_SET_BY_CLI == 0 )) && PROFILE="$v"
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
            RESTORE_MANIFEST)
                RESTORE_MANIFEST="$v"
                ;;
            USER_NAMESPACES_LIMIT)
                USER_NAMESPACES_LIMIT="$v"
                ;;
            UFW_EXTRA_RULES)
                UFW_EXTRA_RULES="$v"
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

restore_manifest_has_path() {
    local target="$1"
    [[ -n "${RESTORE_SOURCE_MANIFEST:-}" && -f "${RESTORE_SOURCE_MANIFEST:-}" ]] || return 1
    python3 - "$RESTORE_SOURCE_MANIFEST" "$target" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
target = sys.argv[2]
data = json.loads(mf.read_text(encoding='utf-8'))
for entry in data.get("backups", []):
    if isinstance(entry, dict) and entry.get("original") == target:
        raise SystemExit(0)
if target in data.get("created_files", []):
    raise SystemExit(0)
raise SystemExit(1)
PYJSON
}

restore_manifest_has_report_text() {
    local needle="$1"
    [[ -n "${RESTORE_SOURCE_MANIFEST:-}" && -f "${RESTORE_SOURCE_MANIFEST:-}" ]] || return 1
    python3 - "$RESTORE_SOURCE_MANIFEST" "$needle" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
needle = sys.argv[2]
data = json.loads(mf.read_text(encoding='utf-8'))
reports = data.get("apply_report", [])
raise SystemExit(0 if any(needle in str(x) for x in reports) else 1)
PYJSON
}

finalize_paths() {
    REPORT_FILE="${REPORT_FILE:-$STATE_DIR/report.json}"
    MANIFEST_FILE="${MANIFEST_FILE:-$STATE_DIR/manifest.json}"
    LOG_FILE="${LOG_FILE:-$STATE_DIR/apply.log}"
    DEBUG_LOG_FILE="${DEBUG_LOG_FILE:-$STATE_DIR/debug.log}"
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

}

ensure_state_dir() {
    local original_state_dir="$STATE_DIR"
    local fallback_state_dir="$SCRIPT_DIR/.securelinux-ng-state"

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '$STATE_DIR'"
        return 0
    fi

    if mkdir -p "$STATE_DIR" 2>/dev/null; then
        chmod 700 "$STATE_DIR" 2>/dev/null || true
        return 0
    fi

    case "$MODE" in
        check|report)
            add_warning "STATE_DIR недоступен: $STATE_DIR; используется fallback: $fallback_state_dir"
            STATE_DIR="$fallback_state_dir"
            mkdir -p "$STATE_DIR" || die "Не удалось создать fallback STATE_DIR: $STATE_DIR"
            chmod 700 "$STATE_DIR" 2>/dev/null || true

            case "$REPORT_FILE" in
                "$original_state_dir"/*) REPORT_FILE="$STATE_DIR/$(basename "$REPORT_FILE")" ;;
            esac
            case "$MANIFEST_FILE" in
                "$original_state_dir"/*) MANIFEST_FILE="$STATE_DIR/$(basename "$MANIFEST_FILE")" ;;
            esac
            ;;
        restore)
            if [[ -n "$RESTORE_MANIFEST" ]]; then
                add_warning "STATE_DIR недоступен: $STATE_DIR; для restore с явным --manifest используется fallback: $fallback_state_dir"
                STATE_DIR="$fallback_state_dir"
                mkdir -p "$STATE_DIR" || die "Не удалось создать fallback STATE_DIR: $STATE_DIR"
                chmod 700 "$STATE_DIR" 2>/dev/null || true

                case "$REPORT_FILE" in
                    "$original_state_dir"/*) REPORT_FILE="$STATE_DIR/$(basename "$REPORT_FILE")" ;;
                esac
                case "$MANIFEST_FILE" in
                    "$original_state_dir"/*) MANIFEST_FILE="$STATE_DIR/$(basename "$MANIFEST_FILE")" ;;
                esac
            else
                die "Не удалось создать STATE_DIR: $STATE_DIR (restore без --manifest не использует fallback)"
            fi
            ;;
        *)
            die "Не удалось создать STATE_DIR: $STATE_DIR"
            ;;
    esac
}

manifest_init() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] создать manifest: $MANIFEST_FILE"
        return 0
    fi

    if [[ -e "$MANIFEST_FILE" ]]; then
        die "Manifest уже существует и будет перезаписан: $MANIFEST_FILE"
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
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

write_check_report_txt() {
    if (( DRY_RUN == 1 )); then return 0; fi
    local txt_file="$STATE_DIR/check.txt"
    {
        printf "SecureLinux-NG v%s — CHECK REPORT\n" "$SCRIPT_VERSION"
        printf "Дата: %s\n" "$(date '+%F %T %z')"
        printf "Профиль: %s\n" "$PROFILE"
        printf "ОС: %s %s\n" "$DISTRO_ID" "$DISTRO_VERSION_ID"
        printf "\n"
        printf "Итого: safe=%s risky=%s warnings=%s errors=%s skipped=%s\n" \
            "${#SAFE_ITEMS[@]}" "${#RISKY_ITEMS[@]}" "${#WARNINGS[@]}" "${#ERRORS[@]}" "${#SKIPPED_ITEMS[@]}"
        printf "\n"
        if [[ ${#RISKY_ITEMS[@]} -gt 0 ]]; then
            printf "=== RISKY ===\n"
            for item in "${RISKY_ITEMS[@]}"; do printf "  [RISKY] %s\n" "$item"; done
            printf "\n"
        fi
        if [[ ${#WARNINGS[@]} -gt 0 ]]; then
            printf "=== WARNINGS ===\n"
            for item in "${WARNINGS[@]}"; do printf "  [WARN]  %s\n" "$item"; done
            printf "\n"
        fi
        if [[ ${#ERRORS[@]} -gt 0 ]]; then
            printf "=== ERRORS ===\n"
            for item in "${ERRORS[@]}"; do printf "  [ERROR] %s\n" "$item"; done
            printf "\n"
        fi
        printf "=== OK ===\n"
        for item in "${SAFE_ITEMS[@]}"; do printf "  [OK]    %s\n" "$item"; done
    } > "$txt_file"
    log "[i]     Отчёт проверки: $txt_file"
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

fstec_items = [
    {"item": "2.1.1", "status": "done", "restore": "managed-file", "module": "empty_password_lock"},
    {"item": "2.1", "status": "partial", "restore": "managed-file", "module": "pam_faillock"},
    {"item": "2.1", "status": "partial", "restore": "managed-file+runtime-state", "module": "password_policy"},
    {"item": "audit", "status": "partial", "restore": "managed-file", "module": "auditd_rules"},
    {"item": "firewall", "status": "partial", "restore": "irreversible", "module": "ufw"},
    {"item": "mount", "status": "partial", "restore": "managed-file", "module": "tmp_tmpfs"},
    {"item": "mount", "status": "partial", "restore": "managed-file", "module": "mount_hardening"},
    {"item": "kernel_modules", "status": "done", "restore": "managed-file", "module": "kernel_module_blacklist"},
    {"item": "fail2ban", "status": "partial", "restore": "managed-file", "module": "fail2ban_ssh_jail"},
    {"item": "aide", "status": "partial", "restore": "irreversible", "module": "aide_init"},
    {"item": "apparmor", "status": "partial", "restore": "irreversible", "module": "apparmor_enforce"},
    {"item": "account_audit", "status": "partial", "restore": "managed-file", "module": "account_audit_report"},
    {"item": "2.1.2", "status": "done", "restore": "managed-file", "module": "ssh_root_login"},
    {"item": "2.1.2", "status": "done", "restore": "managed-file", "module": "ssh_hardening_params"},
    {"item": "2.2.1", "status": "done", "restore": "managed-file+group", "module": "pam_wheel"},
    {"item": "2.2.2", "status": "done", "restore": "managed-file", "module": "sudo_policy"},
    {"item": "2.3.1", "status": "done", "restore": "metadata-snapshot", "module": "fs_critical_files"},
    {"item": "2.3.2", "status": "done", "restore": "metadata-snapshot", "module": "runtime_paths"},
    {"item": "2.3.4", "status": "done", "restore": "metadata-snapshot", "module": "sudo_command_paths"},
    {"item": "2.4.1", "status": "done", "restore": "managed-file", "module": "kernel_dmesg_restrict"},
    {"item": "2.4.2", "status": "done", "restore": "managed-file", "module": "kernel_kptr_restrict"},
    {"item": "2.4.3", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_init_on_alloc"},
    {"item": "2.4.4", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_slab_nomerge"},
    {"item": "2.4.5", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_iommu_hardening"},
    {"item": "2.4.6", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_randomize_kstack_offset"},
    {"item": "2.4.7", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_mitigations"},
    {"item": "2.4.8", "status": "done", "restore": "managed-file", "module": "kernel_bpf_jit_harden"},
    {"item": "2.5.1", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_vsyscall_none"},
    {"item": "2.5.2", "status": "done", "restore": "managed-file", "module": "perf_event_paranoid"},
    {"item": "2.5.3", "status": "done", "restore": "grub-backup", "module": "grub_debugfs_off"},
    {"item": "2.5.4", "status": "done", "restore": "managed-file", "module": "kexec_load_disabled"},
    {"item": "2.5.6", "status": "done", "restore": "managed-file", "module": "unprivileged_bpf_disabled"},
    {"item": "2.5.7", "status": "done", "restore": "managed-file", "module": "unprivileged_userfaultfd"},
    {"item": "2.5.8", "status": "done", "restore": "managed-file", "module": "tty_ldisc_autoload"},
    {"item": "2.5.9", "status": "partial", "restore": "policy-gated-detect-only", "module": "grub_tsx_off"},
    {"item": "2.5.10", "status": "done", "restore": "managed-file", "module": "mmap_min_addr"},
    {"item": "2.5.11", "status": "done", "restore": "managed-file", "module": "randomize_va_space"},
    {"item": "2.6.1", "status": "done", "restore": "managed-file", "module": "yama_ptrace_scope"},
    {"item": "2.6.2", "status": "done", "restore": "managed-file", "module": "protected_symlinks"},
    {"item": "2.6.3", "status": "done", "restore": "managed-file", "module": "protected_hardlinks"},
    {"item": "2.6.4", "status": "done", "restore": "managed-file", "module": "protected_fifos"},
    {"item": "2.6.5", "status": "done", "restore": "managed-file", "module": "protected_regular"},
    {"item": "2.5.5", "status": "done", "restore": "managed-file", "module": "user_namespaces"},
    {"item": "2.6.6", "status": "done", "restore": "managed-file", "module": "suid_dumpable"},
    {"item": "2.3.3", "status": "done", "restore": "metadata-snapshot", "module": "cron_command_paths"},
    {"item": "2.3.5", "status": "done", "restore": "metadata-snapshot", "module": "systemd_targets"},
    {"item": "2.3.6", "status": "done", "restore": "metadata-snapshot", "module": "cron_system_targets"},
    {"item": "2.3.7", "status": "done", "restore": "metadata-snapshot", "module": "user_cron_files"},
    {"item": "2.3.8", "status": "done", "restore": "metadata-snapshot", "module": "standard_system_paths"},
    {"item": "2.3.9", "status": "done", "restore": "metadata-snapshot", "module": "suid_sgid_audit"},
    {"item": "2.3.10", "status": "done", "restore": "metadata-snapshot", "module": "home_sensitive_files"},
    {"item": "2.3.11", "status": "done", "restore": "metadata-snapshot", "module": "home_directories"},
    {"item": "4.3", "status": "done", "restore": "managed-file", "module": "pam_pwhistory"},
    {"item": "17.1", "status": "done", "restore": "managed-file", "module": "account_audit_services"},
    {"item": "17.2", "status": "done", "restore": "managed-file", "module": "account_audit_ports"},
    {"item": "8.4", "status": "done", "restore": "managed-file", "module": "tcp_syncookies"},
    {"item": "8.4", "status": "done", "restore": "managed-file", "module": "icmp_echo_ignore_broadcasts"},
    {"item": "8.4", "status": "done", "restore": "managed-file", "module": "icmp_ignore_bogus_error_responses"},
    {"item": "10.6", "status": "done", "restore": "managed-file", "module": "usb_storage_blacklist"},
    {"item": "15.1", "status": "not_applicable", "restore": "none", "module": "kernel_modules_disabled"},
]

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
    "fstec_items": fstec_items,
    "fstec_summary": {
        "implemented_items": sum(1 for x in fstec_items if x["status"] != "not_applicable"),
        "partial": sum(1 for x in fstec_items if x["status"] == "partial"),
        "done": sum(1 for x in fstec_items if x["status"] == "done"),
        "restore_managed_file": sum(1 for x in fstec_items if x["restore"] == "managed-file"),
        "restore_managed_file_group": sum(1 for x in fstec_items if x["restore"] == "managed-file+group"),
        "restore_metadata_snapshot": sum(1 for x in fstec_items if x["restore"] == "metadata-snapshot"),
        "restore_policy_gated_detect_only": sum(1 for x in fstec_items if x["restore"] == "policy-gated-detect-only"),
    },
}
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
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
        echo "позиций в реестре: ${FSTEC_TOTAL_ITEMS} (40 пунктов ФСТЭК 25.12.2022 + 20 дополнительных мер)"
        echo "реализовано: ${FSTEC_IMPLEMENTED_ITEMS} (не считая временно отключённых)"
        echo "статус done (полная restore): ${FSTEC_DONE_ITEMS} из ${FSTEC_IMPLEMENTED_ITEMS}"
        echo "статус partial (reboot или ручные действия): ${FSTEC_PARTIAL_ITEMS} из ${FSTEC_IMPLEMENTED_ITEMS}"
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
summary = data.get("fstec_summary", {})
if summary:
    total_items = len(data.get("fstec_items", []))
    implemented = summary.get("implemented_items", 0)
    print(f"позиций в реестре: {total_items} (40 пунктов ФСТЭК 25.12.2022 + 20 дополнительных мер)")
    print(f"реализовано: {implemented} (не считая временно отключённых)")
    print(f"статус done (полная restore): {summary.get('done', 0)} из {implemented}")
    print(f"статус partial (reboot или ручные действия): {summary.get('partial', 0)} из {implemented}")
for item in data.get("risky", []):
    print(f"  [RISKY] {item}")
for item in data.get("warnings", []):
    print(f"  [WARN]  {item}")
for item in data.get("errors", []):
    print(f"  [ERROR] {item}")
PYJSON
    log "[i]     Отчёт: $REPORT_FILE"
    if [[ -f "${LOG_FILE:-}" ]]; then
        log "[i]     Лог изменений: $LOG_FILE"
    fi
    if [[ -f "${DEBUG_LOG_FILE:-}" ]]; then
        log "[i]     Технический лог: $DEBUG_LOG_FILE"
    fi
}

run_check_mode() {
    log "[i]     Режим check"
    run_preflight
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_empty_passwords_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.1.1 account: $a reason=$b"
                ;;
        esac
    done < <(check_empty_passwords_module)
    check_ssh_root_login_module
    check_ssh_hardening_module
    check_account_audit_module
    check_rsyslog_module
    check_chrony_module
    check_unattended_upgrades_module
    check_apport_module
    check_coredump_module
    check_apparmor_module
    check_aide_module
    check_fail2ban_module
    check_rkhunter_module
    check_kernel_modules_module
    check_mount_hardening_module
    check_tmp_tmpfs_module
    check_ufw_module
    check_auditd_module
    check_pam_wheel_module
    check_faillock_module
    check_password_policy_module
    check_sudo_policy_module
    check_fs_critical_files_module
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_runtime_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.2 runtime path: $a reason=$b"
                ;;
        esac
    done < <(check_runtime_paths_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sudo_command_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.4 sudo command path: $a reason=$b"
                ;;
        esac
    done < <(check_sudo_command_paths_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_kernel_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.4 sysctl key: $a reason=$b"
                ;;
        esac
    done < <(sysctl_kernel_check_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_grub_kernel_params_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.4 grub kernel param: $a reason=$b"
                ;;
        esac
    done < <(grub_kernel_params_check_module "$PROFILE")
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_attack_surface_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.5 sysctl key: $a reason=$b"
                ;;
            INFO)
                add_skipped "2.5 sysctl key: $a — $b"
                ;;
        esac
    done < <(sysctl_attack_surface_check_module "$PROFILE")
    check_modules_disabled_module
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_userspace_protection_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.6 sysctl key: $a reason=$b"
                ;;
        esac
    done < <(sysctl_userspace_protection_check_module "$PROFILE")
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_network_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "8.1-8.3 sysctl key: $a reason=$b"
                ;;
        esac
    done < <(sysctl_network_check_module "$PROFILE")
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_home_permissions_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.10/2.3.11 target: $a reason=$b"
                ;;
        esac
    done < <(check_home_permissions_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_cron_command_paths_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.3 target: $a reason=$b"
                ;;
        esac
    done < <(check_cron_command_paths_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_user_cron_permissions_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.7 target: $a reason=$b"
                ;;
        esac
    done < <(check_user_cron_permissions_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_standard_system_paths_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.8 target: $a reason=$b"
                ;;
        esac
    done < <(check_standard_system_paths_module)
    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_suid_sgid_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.9 target: $a reason=$b"
                ;;
        esac
    done < <(check_suid_sgid_module)
    check_cron_targets_module
    check_systemd_unit_targets_module
    ensure_state_dir
    write_check_report_txt
    write_report
    print_report_stdout
}


apply_rsyslog_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install rsyslog, enable service"
        add_skipped "rsyslog dry-run: would install and enable"
        return 0
    fi
    log "[i]     rsyslog: установка пакета..."
    apt_update_once
    pkg_installed rsyslog || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" rsyslog >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "rsyslog: не удалось установить пакет"
        record_manifest_warning "rsyslog: apt-get install failed"
        return 0
    }
    if systemctl enable --now rsyslog >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        record_manifest_apply_report "rsyslog: установлен и включён"
        add_safe "rsyslog: служба активна"
    else
        add_warning "rsyslog: пакет установлен, но запуск/enable службы не удался"
        record_manifest_warning "rsyslog: systemctl enable --now failed"
    fi
}

restore_rsyslog_module() {
    log "[i]     restore rsyslog: пакет не удаляется автоматически"
}

check_rsyslog_module() {
    if ! command -v rsyslogd >/dev/null 2>&1; then
        add_risky "rsyslog: не установлен"
        return 0
    fi
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        add_safe "rsyslog: служба активна"
    else
        add_risky "rsyslog: служба не активна"
    fi
}

apply_chrony_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install chrony, enable service"
        add_skipped "chrony dry-run: would install and enable"
        return 0
    fi
    log "[i]     chrony: установка пакета..."
    apt_update_once
    pkg_installed chrony || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" chrony >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "chrony: не удалось установить пакет"
        record_manifest_warning "chrony: apt-get install failed"
        return 0
    }
    if systemctl enable --now chrony >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        record_manifest_apply_report "chrony: установлен и включён"
        add_safe "chrony: служба синхронизации времени активна"
    else
        add_warning "chrony: пакет установлен, но запуск/enable службы не удался"
        record_manifest_warning "chrony: systemctl enable --now failed"
    fi
}

restore_chrony_module() {
    log "[i]     restore chrony: пакет не удаляется автоматически"
}

check_chrony_module() {
    if ! command -v chronyd >/dev/null 2>&1; then
        add_risky "chrony: не установлен"
        return 0
    fi
    if systemctl is-active --quiet chrony 2>/dev/null; then
        add_safe "chrony: служба активна"
    else
        add_risky "chrony: служба не активна"
    fi
}

apply_unattended_upgrades_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install unattended-upgrades, enable service"
        add_skipped "unattended-upgrades dry-run: would install and enable"
        return 0
    fi
    log "[i]     unattended-upgrades: установка пакета..."
    apt_update_once
    pkg_installed unattended-upgrades || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::="--force-confold" unattended-upgrades >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || {
        add_warning "unattended-upgrades: не удалось установить пакет"
        record_manifest_warning "unattended-upgrades: apt-get install failed"
        return 0
    }
    if systemctl enable --now unattended-upgrades >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        record_manifest_apply_report "unattended-upgrades: установлен и включён"
        add_safe "unattended-upgrades: автообновления безопасности активны"
    else
        add_warning "unattended-upgrades: пакет установлен, но запуск/enable службы не удался"
        record_manifest_warning "unattended-upgrades: systemctl enable --now failed"
    fi
}


apply_apport_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] disable apport (supplementary coredump/crash-reporting measure)"
        add_skipped "apport dry-run: would disable service"
        return 0
    fi
    if ! command -v apport >/dev/null 2>&1 && ! systemctl list-unit-files apport.service >/dev/null 2>&1; then
        add_safe "apport: служба не обнаружена"
        return 0
    fi
    if systemctl disable --now apport >/dev/null 2>&1; then
        record_manifest_apply_report "apport: отключён (дополнительная мера; crash-reporting выключен)"
        record_manifest_irreversible_change "apport: отключён — для включения: systemctl enable --now apport"
        add_safe "apport: отключён (конфликтовал с fs.suid_dumpable=0)"
    else
        add_warning "apport: не удалось отключить службу"
        record_manifest_warning "apport: systemctl disable --now failed"
    fi
}

restore_apport_module() {
    local had_apport_apply=""
    had_apport_apply="$(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
if not mf.exists():
    print("0")
    raise SystemExit(0)
data = json.loads(mf.read_text(encoding='utf-8'))
for item in data.get("apply_report", []):
    if isinstance(item, str) and item.startswith("apport: отключён"):
        print("1")
        raise SystemExit(0)
print("0")
PYJSON
)"
    if [[ "$had_apport_apply" != "1" ]]; then
        log "[i]     restore apport: модуль не применялся — пропуск"
        return 0
    fi
    log "[i]     restore apport: служба не включается автоматически"
    add_warning "restore apport: включите вручную если требуется: systemctl enable --now apport"
}

check_coredump_module() {
    local ok=1
    [[ -f "$COREDUMP_LIMITS_FILE" ]] || { add_risky "7.6 coredump: отсутствует $COREDUMP_LIMITS_FILE"; ok=0; }
    [[ -f "$COREDUMP_SYSTEMD_FILE" ]] || { add_risky "7.6 coredump: отсутствует $COREDUMP_SYSTEMD_FILE"; ok=0; }
    local core_pattern
    core_pattern="$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")"
    if [[ "$core_pattern" != "|/bin/false" ]]; then
        add_risky "7.6 coredump: kernel.core_pattern='${core_pattern}' (ожидается '|/bin/false')"
        ok=0
    fi
    (( ok == 1 )) && add_safe "7.6 coredump: конфигурация присутствует"
}

apply_coredump_module() {
    if (( DRY_RUN == 1 )); then
        add_skipped "7.6 coredump dry-run: would configure limits.d and systemd coredump.conf"
        return 0
    fi

    mkdir -p /etc/security/limits.d "$COREDUMP_SYSTEMD_DIR"

    if [[ -f "$COREDUMP_LIMITS_FILE" ]]; then
        local bak="$STATE_DIR/$(basename "$COREDUMP_LIMITS_FILE").bak-$TIMESTAMP"
        if ! backup_file_checked "$COREDUMP_LIMITS_FILE" "$bak" "7.6 coredump limits"; then
            add_skipped "7.6 coredump apply skipped: backup failed"
            return 0
        fi
        record_manifest_backup "$COREDUMP_LIMITS_FILE" "$bak"
    fi
    local existed=0
    [[ -e "$COREDUMP_LIMITS_FILE" ]] && existed=1 || true
    printf '# Managed by SecureLinux-NG
* hard core 0
* soft core 0
' > "$COREDUMP_LIMITS_FILE"
    (( existed == 0 )) && record_manifest_created_file "$COREDUMP_LIMITS_FILE"
    record_manifest_modified_file "$COREDUMP_LIMITS_FILE"

    if [[ -f "$COREDUMP_SYSTEMD_FILE" ]]; then
        local bak2="$STATE_DIR/$(basename "$COREDUMP_SYSTEMD_FILE").bak-$TIMESTAMP"
        if ! backup_file_checked "$COREDUMP_SYSTEMD_FILE" "$bak2" "7.6 coredump systemd"; then
            add_warning "7.6 coredump systemd backup failed"
        else
            record_manifest_backup "$COREDUMP_SYSTEMD_FILE" "$bak2"
        fi
    fi
    local existed2=0
    [[ -e "$COREDUMP_SYSTEMD_FILE" ]] && existed2=1 || true
    printf '# Managed by SecureLinux-NG
[Coredump]
Storage=none
ProcessSizeMax=0
' > "$COREDUMP_SYSTEMD_FILE"
    (( existed2 == 0 )) && record_manifest_created_file "$COREDUMP_SYSTEMD_FILE"
    record_manifest_modified_file "$COREDUMP_SYSTEMD_FILE"

    # kernel.core_pattern через sysctl dropin
    local coredump_sysctl="/etc/sysctl.d/98-securelinux-ng-coredump.conf"
    if [[ -f "$coredump_sysctl" ]]; then
        local bak3="$STATE_DIR/$(basename "$coredump_sysctl").bak-$TIMESTAMP"
        if ! backup_file_checked "$coredump_sysctl" "$bak3" "7.6 coredump sysctl"; then
            add_warning "7.6 coredump sysctl backup failed"
        else
            record_manifest_backup "$coredump_sysctl" "$bak3"
        fi
    fi
    local existed3=0
    [[ -e "$coredump_sysctl" ]] && existed3=1 || true
    printf '# Managed by SecureLinux-NG\nkernel.core_pattern = |/bin/false\n' > "$coredump_sysctl"
    local coredump_live_ok=0
    if sysctl -w kernel.core_pattern="|/bin/false" >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        coredump_live_ok=1
    fi
    (( existed3 == 0 )) && record_manifest_created_file "$coredump_sysctl"
    record_manifest_modified_file "$coredump_sysctl"

    record_manifest_apply_report "7.6 coredump: limits.d, systemd coredump.conf and kernel.core_pattern configured"
    if (( coredump_live_ok == 1 )); then
        add_safe "7.6 coredump: отключён через limits.d, systemd/coredump.conf и kernel.core_pattern"
    else
        add_warning "7.6 coredump: файлы записаны, но live-применение kernel.core_pattern не удалось"
        record_manifest_warning "7.6 coredump: sysctl -w kernel.core_pattern failed"
    fi
}

restore_coredump_module() {
    restore_file_from_manifest "$COREDUMP_LIMITS_FILE"
    restore_file_from_manifest "$COREDUMP_SYSTEMD_FILE"
    restore_file_from_manifest "/etc/sysctl.d/98-securelinux-ng-coredump.conf"
    if ! sysctl --system >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        add_warning "restore coredump: sysctl --system failed"
    fi
}

check_apport_module() {
    if systemctl is-active --quiet apport 2>/dev/null; then
        add_risky "apport: служба активна — crash-reporting должен быть отключён"
    else
        add_safe "apport: служба неактивна"
    fi
}
restore_unattended_upgrades_module() {
    log "[i]     restore unattended-upgrades: пакет не удаляется автоматически"
}

restore_empty_passwords_module() {
    local backup
    backup="$(restore_lookup_backup "/etc/shadow")"
    if [[ -z "$backup" || ! -f "$backup" ]]; then
        log "[i]     restore 2.1.1: нет backup /etc/shadow — пропуск"
        return 0
    fi
    log "[i]     restore 2.1.1: восстановление пустых полей пароля запрещено по соображениям безопасности — пропуск"
    add_warning "restore 2.1.1: пустые поля пароля в /etc/shadow не восстанавливаются; backup сохранён: $backup"
}

restore_runtime_paths_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/runtime." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_home_permissions_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and any(x in e.get("backup", "") for x in [".home.meta-", ".meta-"]) and "/home/" in e.get("original", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_suid_sgid_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/suid." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_cron_command_paths_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/cron_cmd." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_standard_system_paths_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/syspath." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_sudo_command_paths_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/sudo_cmd." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_user_cron_permissions_module() {
    local modified
    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        restore_metadata_from_stat_snapshot "$modified"
    done < <(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/cronuser." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
)
}

restore_grub_kernel_params_module() {
    restore_grub_module
}


check_unattended_upgrades_module() {
    if ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
        add_risky "unattended-upgrades: не установлен"
        return 0
    fi
    if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        add_safe "unattended-upgrades: автоматические обновления включены"
    else
        add_risky "unattended-upgrades: автоматические обновления не включены"
    fi
}

run_apply_mode() {
    log "[i]     Режим apply"
    run_preflight
    check_memory_requirements
    ensure_state_dir
    acquire_run_lock
    if (( DRY_RUN == 0 )); then
        log "[i]     Лог сохраняется: $LOG_FILE"
        log_debug "=== SecureLinux-NG $SCRIPT_VERSION apply start ==="
        log_debug "profile=$PROFILE os=$DISTRO_ID $DISTRO_VERSION_ID"
    fi
    if [[ -f "$MANIFEST_FILE" ]] && (( DRY_RUN == 0 )); then
        log ""
        log "[WARN]  Обнаружен существующий manifest: $MANIFEST_FILE"
        log "[WARN]  Повторный --apply без предварительного --restore перезапишет manifest."
        log "[WARN]  После этого --restore не сможет корректно откатить изменения."
        log ""
        log "[?]     Продолжить? (yes/no)"
        local _ans
        if [[ ! -t 0 ]] && ! test -c /dev/tty 2>/dev/null; then
            log "[i]     Неинтерактивный режим — прервано. Выполните --restore перед повторным --apply."
            exit 1
        fi
        read -r _ans < /dev/tty
        if [[ "$_ans" != "yes" && "$_ans" != "y" ]]; then
            log "[i]     Прервано администратором. Выполните --restore перед повторным --apply."
            exit 0
        fi
        log "[WARN]  Продолжение по явному подтверждению администратора."
        local _archive="${MANIFEST_FILE}.bak-${TIMESTAMP}"
        mv "$MANIFEST_FILE" "$_archive" && \
            log "[i]     Существующий manifest архивирован: $_archive" || \
            die "Не удалось архивировать существующий manifest: $MANIFEST_FILE"
    fi
    manifest_init

    apply_empty_passwords_module
    apply_ssh_root_login_module
    apply_ssh_hardening_module
    apply_account_audit_module
    apply_apparmor_module
    apply_aide_module
    apply_fail2ban_module
    apply_rkhunter_module
    apply_kernel_modules_module
    apply_mount_hardening_module
    apply_tmp_tmpfs_module
    apply_ufw_module
    apply_auditd_module
    apply_rsyslog_module
    apply_chrony_module
    apply_unattended_upgrades_module
    apply_apport_module
    apply_coredump_module
    apply_pam_wheel_module
    apply_faillock_module
    apply_password_policy_module
    apply_sudo_policy_module
    apply_fs_critical_files_module
    apply_runtime_paths_module
    apply_sudo_command_paths_module
    apply_sysctl_kernel_module
    apply_grub_kernel_params_module
    apply_sysctl_attack_surface_module
    apply_sysctl_userspace_protection_module
    apply_sysctl_network_module
    apply_home_permissions_module
    apply_cron_command_paths_module
    apply_user_cron_permissions_module
    apply_standard_system_paths_module
    apply_suid_sgid_module
    apply_cron_targets_module
    apply_systemd_unit_targets_module
    apply_modules_disabled_module

    write_report
    print_report_stdout
}

run_restore_mode() {
    log "[i]     Режим restore"
    run_preflight
    resolve_restore_manifest
    ensure_state_dir
    acquire_run_lock
    if [[ -f "$RESTORE_SOURCE_MANIFEST" ]]; then
        PROFILE="$(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
data = json.loads(mf.read_text(encoding='utf-8'))
print(data.get("profile", "baseline"))
PYJSON
)"
        [[ "$PROFILE" =~ ^(baseline|strict|paranoid)$ ]] || PROFILE="baseline"
    fi

    restore_ssh_root_login_module
    restore_ssh_hardening_module
    restore_account_audit_module
    restore_apparmor_module
    restore_aide_module
    restore_fail2ban_module
    restore_rkhunter_module
    restore_kernel_modules_module
    restore_mount_hardening_module
    restore_tmp_tmpfs_module
    restore_ufw_module
    restore_auditd_module
    restore_pam_wheel_module
    restore_faillock_module
    restore_password_policy_module
    restore_sudo_policy_module
    restore_sysctl_kernel_module
    restore_sysctl_network_module
    restore_sysctl_attack_surface_module
    restore_modules_disabled_module
    restore_sysctl_userspace_protection_module
    restore_rsyslog_module
    restore_chrony_module
    restore_unattended_upgrades_module
    restore_apport_module
    restore_coredump_module
    restore_empty_passwords_module
    restore_runtime_paths_module
    restore_home_permissions_module
    restore_suid_sgid_module
    restore_cron_command_paths_module
    restore_standard_system_paths_module
    restore_sudo_command_paths_module
    restore_user_cron_permissions_module
    restore_grub_kernel_params_module
    restore_fs_critical_files_module
    restore_cron_targets_module
    restore_systemd_unit_targets_module

    write_report
    print_report_stdout
}

run_report_mode() {
    log "[i]     Режим report"
    add_warning "report: режим не выполняет проверку системы — показывает только статическое покрытие ФСТЭК и preflight; для проверки состояния используйте --check"
    run_preflight
    ensure_state_dir
    write_report
    print_report_stdout
}

main() {
    parse_args "$@"
    require_cmds
    validate_args
    load_config
    validate_args_post_config
    validate_execution_context
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
