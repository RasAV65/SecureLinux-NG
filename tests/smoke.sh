#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

TMP_STATE_DIR="$(pwd)/.tmp-test-state"
TMP_CONFIG="$(pwd)/.tmp-smoke.conf"

cat > "$TMP_CONFIG" <<EOF
PROFILE=baseline
STATE_DIR=$TMP_STATE_DIR
EOF

./securelinux-ng.sh --version &&
./securelinux-ng.sh --help >/dev/null &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --report --config "$TMP_CONFIG" >/dev/null

rc=$?
rm -f "$TMP_CONFIG"
rm -rf "$TMP_STATE_DIR"
exit $rc
