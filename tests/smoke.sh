#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

TMP_STATE_DIR="$(pwd)/.tmp-test-state"
TMP_CONFIG="$(pwd)/.tmp-smoke.conf"
TMP_MANIFEST="$(pwd)/.tmp-restore-manifest.json"

cat > "$TMP_CONFIG" <<EOF
PROFILE=baseline
STATE_DIR=$TMP_STATE_DIR
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
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'fstec_items: 6' &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'fstec_partial: 6' &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" | grep -q '2.1.2' &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" | grep -q '2.2.1' &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" | grep -q '2.2.2' &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" | grep -q '2.3.1' &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" | grep -q '2.3.3' &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" | grep -q '2.3.5'

rc=$?
rm -f "$TMP_CONFIG" "$TMP_MANIFEST"
rm -rf "$TMP_STATE_DIR"
exit $rc
