#!/usr/bin/env bash
# Package the Provenex Splunk app into a .spl tarball ready for upload
# to Splunkbase or installation via Splunk Web's "Install app from file"
# flow.
#
# Output: dist/provenex-splunk-<version>.spl (a gzip tarball whose root
# entry is named "provenex" — that single-root-dir layout is what the
# Splunk app installer expects).
#
# Usage:
#   ./scripts/package_splunk_app.sh
#
# The script reads the version from siem/splunk/default/app.conf so the
# package version stays in lockstep with the source of truth.

set -euo pipefail

cd "$(dirname "$0")/.."

APP_CONF=siem/splunk/default/app.conf
VERSION=$(grep -E '^version' "$APP_CONF" | head -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ -z "$VERSION" ]]; then
  echo "error: could not read version from $APP_CONF" >&2
  exit 1
fi

OUT_DIR=dist
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/provenex-splunk-$VERSION.spl"

# Splunk expects the tarball's root to be a single directory named
# after the app. We stage the siem/splunk/ contents into a temp
# directory called "provenex" and tar that.
STAGE=$(mktemp -d -t provenex-splunk-stage-XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

cp -R siem/splunk "$STAGE/provenex"

# Drop OS / editor cruft.
find "$STAGE/provenex" \( \
    -name '.DS_Store' -o \
    -name '*.pyc' -o \
    -name '__pycache__' -o \
    -name '*.swp' -o \
    -name '*~' \
  \) -print -delete >/dev/null 2>&1 || true

tar -czf "$OUT_FILE" -C "$STAGE" provenex
echo "wrote $OUT_FILE ($(du -h "$OUT_FILE" | awk '{print $1}'))"
echo ""
echo "Install:"
echo "  Splunk Enterprise: cp $OUT_FILE \$SPLUNK_HOME/etc/apps/ && \$SPLUNK_HOME/bin/splunk restart"
echo "  Splunk Cloud / Web: Apps > Manage Apps > Install app from file > select $OUT_FILE"
