#!/usr/bin/env bash
# Download cis-linux-mint-22-harden.sh from the public repo
#   https://github.com/lsprockets/linux_hardening_scripts
# No login and no token.
#
# Usage:
#   bash get-cis-mint22.sh
#   bash get-cis-mint22.sh /root/cis-linux-mint-22-harden.sh
#
set -euo pipefail

REPO="lsprockets/linux_hardening_scripts"
FILE="cis-linux-mint-22-harden.sh"
BRANCH="${BRANCH:-main}"
DEST="${1:-./${FILE}}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${FILE}"
CLONE_URL="https://github.com/${REPO}.git"

mkdir -p "$(dirname "$DEST")"
tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; rm -rf "${workdir:-}"; }
trap cleanup EXIT

download_raw() {
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --output "$tmp" "$RAW_URL"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp" "$RAW_URL"
    return
  fi
  return 1
}

download_git() {
  command -v git >/dev/null 2>&1 || return 1
  workdir="$(mktemp -d)"
  # Empty credential helper so a public clone does not prompt or reuse a saved login.
  git -c credential.helper= \
    -c advice.detachedHead=false \
    clone --depth 1 --branch "$BRANCH" "$CLONE_URL" "$workdir/repo"
  cp "$workdir/repo/${FILE}" "$tmp"
}

printf '%s\n' "downloading ${RAW_URL}"
if ! download_raw; then
  printf '%s\n' "curl/wget failed or is missing. Trying git clone."
  if ! download_git; then
    printf '%s\n' "need curl, wget, or git to download ${FILE}" >&2
    exit 1
  fi
fi

if [[ ! -s "$tmp" ]] || ! head -n 1 "$tmp" | grep -q '^#!/usr/bin/env bash'; then
  printf '%s\n' "download did not return the hardening script. Check ${RAW_URL}" >&2
  exit 1
fi

cp "$tmp" "$DEST"
chmod 755 "$DEST"
printf '%s\n' "saved ${DEST}"
printf '%s\n' "next, on the Mint box: sudo ${DEST} --dry-run"
