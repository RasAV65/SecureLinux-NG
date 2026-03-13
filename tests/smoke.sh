#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

TMP_STATE_DIR="$(pwd)/.tmp-test-state"
TMP_CONFIG="$(pwd)/.tmp-smoke.conf"
TMP_MANIFEST="$(pwd)/.tmp-restore-manifest.json"
TMP_REPORT="$(pwd)/.tmp-smoke-report.json"

cat > "$TMP_CONFIG" <<EOF
PROFILE=baseline
STATE_DIR=$TMP_STATE_DIR
REPORT_FILE=$TMP_REPORT
EOF

cat > "$TMP_MANIFEST" <<EOF
{
  "version": "16.0.0",
  "profile": "baseline",
  "mode": "apply",
  "timestamp": "2026-03-14T00:00:00",
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
EOF

./securelinux-ng.sh --version &&
./securelinux-ng.sh --help >/dev/null &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --report --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --restore --manifest "$TMP_MANIFEST" --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'fstec_items: 16' &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'fstec_partial: 16' &&
python3 - "$TMP_REPORT" <<'PY'
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
data = json.loads(report.read_text(encoding='utf-8'))
items = {entry["item"] for entry in data.get("fstec_items", [])}
required = {
    "2.1.2", "2.2.1", "2.2.2", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5",
    "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8",
}
missing = sorted(required - items)
if missing:
    raise SystemExit(f"Missing FSTEC items: {', '.join(missing)}")
PY

rc=$?
rm -f "$TMP_CONFIG" "$TMP_MANIFEST" "$TMP_REPORT"
rm -rf "$TMP_STATE_DIR"
exit $rc
