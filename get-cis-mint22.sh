#!/usr/bin/env bash
# Download the hardening scripts from the public repo
#   https://github.com/lsprockets/linux_hardening_scripts
# No login and no token.
#
# FILES is every .sh file in the repo root except get-cis*.sh.
# That list was taken from the repo root on main:
#   cis-linux-mint-22-harden.sh
#   get-cis-mint22.sh   (left out)
#
# Usage:
#   bash get-cis-mint22.sh
#   bash get-cis-mint22.sh /root
#
set -euo pipefail

REPO="lsprockets/linux_hardening_scripts"
BRANCH="${BRANCH:-main}"
CLONE_URL="https://github.com/${REPO}.git"
DEST_DIR="${1:-.}"

FILES=(
  cis-linux-mint-22-harden.sh
)

mkdir -p "$DEST_DIR"
workdir=""
cleanup() { rm -rf "${workdir:-}"; }
trap cleanup EXIT

raw_url() {
  printf 'https://raw.githubusercontent.com/%s/%s/%s\n' "$REPO" "$BRANCH" "$1"
}

fetch_one() {
  local name="$1" url dest
  url="$(raw_url "$name")"
  dest="${DEST_DIR%/}/${name}"
  printf '%s\n' "downloading ${url}"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --output "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
  else
    return 1
  fi
}

fetch_git() {
  local name dest
  command -v git >/dev/null 2>&1 || return 1
  workdir="$(mktemp -d)"
  printf '%s\n' "curl/wget failed or is missing. Cloning ${CLONE_URL}"
  git -c credential.helper= \
    -c advice.detachedHead=false \
    clone --depth 1 --branch "$BRANCH" "$CLONE_URL" "$workdir/repo"
  for name in "${FILES[@]}"; do
    dest="${DEST_DIR%/}/${name}"
    cp "$workdir/repo/${name}" "$dest"
    printf '%s\n' "copied ${name}"
  done
}

if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
  for name in "${FILES[@]}"; do
    [[ "$name" == get-cis*.sh ]] && continue
    fetch_one "$name"
  done
else
  fetch_git || {
    printf '%s\n' "need curl, wget, or git" >&2
    exit 1
  }
fi

for name in "${FILES[@]}"; do
  [[ "$name" == get-cis*.sh ]] && continue
  dest="${DEST_DIR%/}/${name}"
  if [[ ! -s "$dest" ]] || ! head -n 1 "$dest" | grep -q '^#!/usr/bin/env bash'; then
    printf '%s\n' "download did not return a shell script: ${name}" >&2
    exit 1
  fi
  chmod 755 "$dest"
  printf '%s\n' "saved ${dest}"
done

printf '%s\n' "next, on the Mint box: sudo ${DEST_DIR%/}/cis-linux-mint-22-harden.sh --dry-run"
