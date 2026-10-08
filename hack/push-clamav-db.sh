#!/usr/bin/env bash

set -euo pipefail

: "${REPOSITORY:=public.ecr.aws/k9v9d5v2/clamav-db}"
: "${TAG:=latest}"
: "${CLAMAV_MIRROR:=database.clamav.net}"
: "${DATA_DIR:=""}"

# -----------------------------
# Deps check
# -----------------------------
for bin in freshclam oras; do
    command -v "$bin" >/dev/null 2>&1 || {
        echo "Missing dependency: $bin" >&2
        exit 1
    }
done

# -----------------------------
# Download ClamAV DB
# -----------------------------
echo "Downloading ClamAV DB from ${CLAMAV_MIRROR}"

if [[ -n "$DATA_DIR" ]]; then
    save_to="$DATA_DIR"
else
    save_to=$(mktemp -d)
fi

{
    echo "DatabaseDirectory $save_to"
    echo "Foreground yes"
    echo "DatabaseOwner $USER"
    echo "DatabaseMirror $CLAMAV_MIRROR"
} | tee "${save_to}/freshclam.conf" >/dev/null

freshclam --config-file="${save_to}/freshclam.conf"

# -----------------------------
# Push as OCI artifact
# -----------------------------
echo "Pushing OCI artifact: ${REPOSITORY}:${TAG}"

pushd "$save_to"
oras push "${REPOSITORY}:${TAG}" \
    "./main.cvd:application/vnd.clamav.db" \
    "./daily.cvd:application/vnd.clamav.db" \
    "./bytecode.cvd:application/vnd.clamav.db"
popd
