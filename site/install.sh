#!/bin/sh
# Install the exact KeyRX Linux x86-64/WSL release after verifying its archive.
set -eu

TARGET=x86_64-unknown-linux-musl
REPOSITORY=keyrx/keyrx

refuse() {
  printf 'keyrx install refused: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || refuse "required command is missing: $1"
}

test "$(uname -s 2>/dev/null)" = Linux || refuse "only Linux x86-64 and Windows through WSL are supported"
case "$(uname -m 2>/dev/null)" in
  x86_64|amd64) ;;
  *) refuse "only x86-64 is supported by this release" ;;
esac

test -n "${HOME:-}" || refuse 'HOME is empty'
case "$HOME" in
  /*) ;;
  *) refuse 'HOME is not an absolute path' ;;
esac

need curl
need sha256sum
need tar
need install
need mktemp
need mv

LATEST_URL="$(curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
  --head --output /dev/null --write-out '%{url_effective}' \
  "https://github.com/$REPOSITORY/releases/latest")"
LATEST_PREFIX="https://github.com/$REPOSITORY/releases/tag/v"
case "$LATEST_URL" in
  "$LATEST_PREFIX"*) VERSION="${LATEST_URL#"$LATEST_PREFIX"}" ;;
  *) refuse 'GitHub latest release did not resolve to the expected repository tag' ;;
esac
case "$VERSION" in ''|*[!0-9.]*) refuse 'latest release version is not canonical' ;; esac
old_ifs="$IFS"; IFS=.; set -- $VERSION; IFS="$old_ifs"
test "$#" -eq 3 || refuse 'latest release version is not MAJOR.MINOR.PATCH'
for part in "$@"; do
  test -n "$part" || refuse 'latest release version contains an empty part'
  case "$part" in 0|[1-9]|[1-9][0-9]*) ;; *) refuse 'latest release version has a leading zero' ;; esac
done
BASE_URL="https://github.com/$REPOSITORY/releases/download/v$VERSION"
ARCHIVE="keyrx-$VERSION-$TARGET.tar.gz"

INSTALL_ROOT="${CARGO_HOME:-$HOME/.cargo}"
case "$INSTALL_ROOT" in
  /*) ;;
  *) refuse 'the install root is not an absolute path' ;;
esac
BIN_DIR="$INSTALL_ROOT/bin"
ORIGINAL_PATH="$PATH"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/keyrx-install.XXXXXXXX")"
cleanup() { rm -rf -- "$WORKDIR"; }
trap cleanup EXIT HUP INT TERM
cd "$WORKDIR"

curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
  --output "$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
  --output "$ARCHIVE.sha256" "$BASE_URL/$ARCHIVE.sha256"

# The sidecar must name this exact archive once; no alternate path or extra line is admitted.
expected_line="$(sed -n '1p' "$ARCHIVE.sha256")"
test "$(wc -l < "$ARCHIVE.sha256" | tr -d ' ')" = 1 || refuse 'checksum sidecar is not one canonical line'
case "$expected_line" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*"  $ARCHIVE") ;;
  *) refuse 'checksum sidecar does not name the exact archive' ;;
esac
test "${#expected_line}" -eq "$((64 + 2 + ${#ARCHIVE}))" || refuse 'checksum sidecar digest is not canonical SHA-256'
sha256sum --check --strict "$ARCHIVE.sha256"

if command -v gh >/dev/null 2>&1; then
  GH_NO_UPDATE_NOTIFIER=1 gh attestation verify "$ARCHIVE" --repo "$REPOSITORY" >/dev/null
elif test "${KEYRX_REQUIRE_ATTESTATION:-0}" = 1; then
  refuse 'GitHub CLI is required by KEYRX_REQUIRE_ATTESTATION=1'
else
  printf '%s\n' 'keyrx install: SHA-256 verified; GitHub CLI absent, provenance verification skipped' >&2
fi

ROOT="keyrx-$VERSION-$TARGET"
EXPECTED="$(printf '%s\n' "$ROOT/" "$ROOT/keyrx" "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/SOURCE.json")"
ACTUAL="$(tar -tzf "$ARCHIVE")"
test "$ACTUAL" = "$EXPECTED" || refuse 'archive member set or order differs'
mkdir -p "$WORKDIR/extracted"
tar -xzf "$ARCHIVE" -C "$WORKDIR/extracted" --no-same-owner --no-same-permissions
SOURCE="$WORKDIR/extracted/$ROOT/keyrx"
test -f "$SOURCE" && test ! -L "$SOURCE" && test -x "$SOURCE" || refuse 'archive executable is missing or unsafe'
test "$("$SOURCE" --version)" = "keyrx $VERSION" || refuse 'archive executable version differs'
HOME="$HOME" NO_COLOR=1 KEYRX_NO_LINKS=1 "$SOURCE" verify

mkdir -p "$BIN_DIR"
test -d "$BIN_DIR" && test ! -L "$BIN_DIR" || refuse 'install bin directory is not a held directory'
STAGED="$BIN_DIR/.keyrx-install-$$"
test ! -e "$STAGED" && test ! -L "$STAGED" || refuse 'installer staging name already exists'
install -m 0755 "$SOURCE" "$STAGED"
test "$("$STAGED" --version)" = "keyrx $VERSION" || refuse 'staged executable version differs'
HOME="$HOME" NO_COLOR=1 KEYRX_NO_LINKS=1 "$STAGED" verify
mv -f -- "$STAGED" "$BIN_DIR/keyrx"
export PATH="$BIN_DIR:$PATH"
test "$(keyrx --version)" = "keyrx $VERSION" || refuse 'installed executable version differs'
HOME="$HOME" NO_COLOR=1 KEYRX_NO_LINKS=1 keyrx verify

printf 'keyrx %s installed at %s\n' "$VERSION" "$BIN_DIR/keyrx"
case ":$ORIGINAL_PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf 'Add this to your shell profile: export PATH="%s:$PATH"\n' "$BIN_DIR" ;;
esac
