#!/bin/sh
# Installs the latest EnvRune release on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/YagoLagrottiBracco/vault/main/install.sh | sh
#
# Environment:
#   ENVRUNE_VERSION      version to install, such as 0.1.0 (default: latest)
#   ENVRUNE_INSTALL_DIR  destination directory (default: /usr/local/bin)
set -eu

REPO="YagoLagrottiBracco/vault"
INSTALL_DIR="${ENVRUNE_INSTALL_DIR:-/usr/local/bin}"

fail() { printf 'envrune install: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) fail "unsupported operating system: $(uname -s). On Windows, use the setup .exe from the releases page." ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

version="${ENVRUNE_VERSION:-}"
if [ -z "$version" ]; then
  latest_url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") \
    || fail "could not find the latest release"
  version="${latest_url##*/v}"
fi
version="${version#v}"

archive="envrune_${version}_${os}_${arch}.tar.gz"
base_url="https://github.com/$REPO/releases/download/v${version}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'Downloading EnvRune %s for %s/%s...\n' "$version" "$os" "$arch"
curl -fsSL -o "$tmp/$archive" "$base_url/$archive" || fail "download failed: $base_url/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base_url/checksums.txt" || fail "could not download checksums.txt"

expected=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$expected" ] || fail "no checksum listed for $archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" envrune

if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$tmp/envrune" "$INSTALL_DIR/envrune"
elif command -v sudo >/dev/null 2>&1; then
  printf 'Installing to %s (requires sudo)...\n' "$INSTALL_DIR"
  sudo mkdir -p "$INSTALL_DIR"
  sudo install -m 0755 "$tmp/envrune" "$INSTALL_DIR/envrune"
else
  fail "cannot write to $INSTALL_DIR; set ENVRUNE_INSTALL_DIR to a writable directory"
fi

printf 'EnvRune %s installed to %s/envrune\n' "$version" "$INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) printf 'Run "envrune" to create your vault.\n' ;;
  *) printf 'Add %s to your PATH, then run "envrune".\n' "$INSTALL_DIR" ;;
esac
