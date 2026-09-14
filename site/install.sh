#!/bin/sh
# Install the exact KeyRX Linux x86-64/WSL release after verifying its archive.
set -eu
umask 077

TARGET=x86_64-unknown-linux-musl
REPOSITORY=keyrx/keyrx

refuse() {
  printf 'keyrx install refused: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || refuse "required command is missing: $1"
}

test -n "${HOME:-}" || refuse 'HOME is empty'
case "$HOME" in
  /*) ;;
  *) refuse 'HOME is not an absolute path' ;;
esac
case ":${PATH-}:" in
  *::*) refuse 'PATH has an empty component; first run: export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"' ;;
esac
case ":${PATH-}:" in *:/usr/bin:*|*:/bin:*) ;; *) refuse 'PATH is missing /usr/bin or /bin. Run: export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"; then fix profile lines that replace PATH instead of prepending to it' ;; esac
test "$(uname -s 2>/dev/null)" = Linux || refuse "only Linux x86-64 and Windows through WSL are supported"
case "$(uname -m 2>/dev/null)" in
  x86_64|amd64) ;;
  *) refuse "only x86-64 is supported by this release" ;;
esac
need id
USER_ID="$(id -u)" || refuse 'cannot identify the invoking user'
case "$USER_ID" in ''|*[!0-9]*) refuse 'cannot identify the invoking user' ;; esac
need stat
if test "$USER_ID" = 0; then
  printf '%s\n' 'keyrx install warning: this is a root shell; the install belongs to root, not another WSL user' >&2
fi

INSTALL_ROOT="${CARGO_HOME:-$HOME/.cargo}"
case "$INSTALL_ROOT" in
  /*) ;;
  *) refuse 'the install root is not an absolute path' ;;
esac
BIN_DIR="$INSTALL_ROOT/bin"
need tr
case "$BIN_DIR" in *:*) refuse 'the install bin path contains a PATH separator' ;; esac
test "$(printf '%s' "$BIN_DIR" | LC_ALL=C tr -d '[:cntrl:]')" = "$BIN_DIR" ||
  refuse 'the install bin path contains a control character'
INSTALL_ROOT_ID=''
BIN_DIR_ID=''
for candidate_dir in "$INSTALL_ROOT" "$BIN_DIR"; do
  if test -e "$candidate_dir" || test -L "$candidate_dir"; then
    test -d "$candidate_dir" && test ! -L "$candidate_dir" || refuse "install directory is not safe: $candidate_dir"
    test "$(stat -c %u -- "$candidate_dir")" = "$USER_ID" || refuse "install directory is not owned by the invoking user: $candidate_dir"
    directory_mode="$(stat -c %a -- "$candidate_dir")"
    case "$directory_mode" in ''|*[!0-7]*) refuse "install directory has an unsafe mode: $candidate_dir" ;; esac
    test "$((0$directory_mode & 022))" -eq 0 || refuse "install directory is group- or world-writable: $candidate_dir"
    if test "$candidate_dir" = "$INSTALL_ROOT"; then
      INSTALL_ROOT_ID="$(stat -c '%d:%i:%u:%a' -- "$candidate_dir")"
    else
      BIN_DIR_ID="$(stat -c '%d:%i:%u:%a' -- "$candidate_dir")"
    fi
  fi
done

EXISTING_KEYRX_ID=''
if test -e "$BIN_DIR/keyrx" || test -L "$BIN_DIR/keyrx"; then
  test -f "$BIN_DIR/keyrx" && test ! -L "$BIN_DIR/keyrx" && test -x "$BIN_DIR/keyrx" ||
    refuse 'existing keyrx is not a safe executable; refusing to replace it'
  test "$(stat -c %u -- "$BIN_DIR/keyrx")" = "$USER_ID" ||
    refuse 'existing keyrx is not owned by the invoking user'
  test "$(stat -c %h -- "$BIN_DIR/keyrx")" = 1 ||
    refuse 'existing keyrx has multiple hard links'
  keyrx_mode="$(stat -c %a -- "$BIN_DIR/keyrx")"
  case "$keyrx_mode" in ''|*[!0-7]*) refuse 'existing keyrx has an unsafe mode' ;; esac
  test "$((0$keyrx_mode & 022))" -eq 0 || refuse 'existing keyrx is group- or world-writable'
  EXISTING_KEYRX_ID="$(stat -c '%d:%i:%u:%h:%a' -- "$BIN_DIR/keyrx")"
fi

TRUSTED_INSTALLED_VERSION=''
if test "${KEYRX_TRUSTED_INSTALLED_VERSION+x}" = x; then
  TRUSTED_INSTALLED_VERSION="$KEYRX_TRUSTED_INSTALLED_VERSION"
  test -n "$EXISTING_KEYRX_ID" || refuse 'trusted installed version was supplied but no existing keyrx was found'
  case "$TRUSTED_INSTALLED_VERSION" in ''|*[!0-9.]*) refuse 'trusted installed version is not canonical' ;; esac
  old_ifs="$IFS"; IFS=.; set -- $TRUSTED_INSTALLED_VERSION; IFS="$old_ifs"
  test "$#" -eq 3 || refuse 'trusted installed version is not MAJOR.MINOR.PATCH'
  for part in "$@"; do
    test -n "$part" || refuse 'trusted installed version contains an empty part'
    case "$part" in 0|[1-9]|[1-9][0-9]*) ;; *) refuse 'trusted installed version has a leading zero' ;; esac
  done
fi

NO_PROFILE=0
if test "${KEYRX_INSTALL_NO_PROFILE+x}" = x; then
  test "$KEYRX_INSTALL_NO_PROFILE" = 1 || refuse 'KEYRX_INSTALL_NO_PROFILE must be exactly 1 when set'
  NO_PROFILE=1
fi

# The one-line installer runs in a child shell, so make the next interactive
# Bash shell work as well. A literal install path also survives a temporary
# CARGO_HOME value that is not exported by the next shell.
PROFILE=''
PROFILE_ID=''
if test "$NO_PROFILE" = 0; then
  case "${SHELL:-}" in */bash|bash) PROFILE="$HOME/.bashrc" ;; esac
fi
if test -n "$PROFILE"; then
  need cp
  need cmp
  need tail
  test -d "$HOME" && test ! -L "$HOME" || refuse 'HOME is not a safe directory for Bash profile setup'
  test "$(stat -c %u -- "$HOME")" = "$USER_ID" || refuse 'HOME is not owned by the invoking user'
  home_mode="$(stat -c %a -- "$HOME")"
  case "$home_mode" in ''|*[!0-7]*) refuse 'HOME has an unsafe mode' ;; esac
  test "$((0$home_mode & 022))" -eq 0 || refuse 'HOME is group- or world-writable; repair its permissions before installing'
  if test -e "$PROFILE" || test -L "$PROFILE"; then
    test -f "$PROFILE" && test ! -L "$PROFILE" || refuse '.bashrc is not a regular, non-symlink file; repair it manually before installing'
    test "$(stat -c %u -- "$PROFILE")" = "$USER_ID" || refuse '.bashrc is not owned by the invoking user; repair it manually before installing'
    test "$(stat -c %h -- "$PROFILE")" = 1 || refuse '.bashrc has multiple hard links; repair it manually before installing'
    profile_mode="$(stat -c %a -- "$PROFILE")"
    case "$profile_mode" in ''|*[!0-7]*) refuse '.bashrc has an unsafe mode' ;; esac
    test "$((0$profile_mode & 022))" -eq 0 || refuse '.bashrc is group- or world-writable; repair it manually before installing'
    test -r "$PROFILE" && test -w "$PROFILE" || refuse '.bashrc cannot be safely updated'
    PROFILE_ID="$(stat -c '%d:%i:%u:%h:%a' -- "$PROFILE")"
  fi
fi

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
if test -n "$TRUSTED_INSTALLED_VERSION"; then
  need sort
  need head
  if test "$TRUSTED_INSTALLED_VERSION" != "$VERSION" &&
    test "$(printf '%s\n' "$VERSION" "$TRUSTED_INSTALLED_VERSION" | sort -V | head -n 1)" = "$VERSION"; then
    refuse "latest release $VERSION is older than trusted installed keyrx $TRUSTED_INSTALLED_VERSION; refusing to downgrade"
  fi
fi
BASE_URL="https://github.com/$REPOSITORY/releases/download/v$VERSION"
ARCHIVE="keyrx-$VERSION-$TARGET.tar.gz"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/keyrx-install.XXXXXXXX")"
PROFILE_STAGE=''
STAGED=''
cleanup() {
  if test -n "$PROFILE_STAGE"; then rm -f -- "$PROFILE_STAGE"; fi
  if test -n "$STAGED"; then rm -f -- "$STAGED"; fi
  rm -rf -- "$WORKDIR"
}
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

if command -v gh >/dev/null 2>&1 &&
  GH_NO_UPDATE_NOTIFIER=1 gh attestation verify --help >/dev/null 2>&1; then
  GH_NO_UPDATE_NOTIFIER=1 gh attestation verify "$ARCHIVE" --repo "$REPOSITORY" >/dev/null
elif test "${KEYRX_REQUIRE_ATTESTATION:-0}" = 1; then
  refuse 'GitHub CLI with gh attestation verify is required by KEYRX_REQUIRE_ATTESTATION=1'
else
  printf '%s\n' 'keyrx install: SHA-256 verified; gh attestation verify unavailable, provenance verification skipped' >&2
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
for candidate_dir in "$INSTALL_ROOT" "$BIN_DIR"; do
  test -d "$candidate_dir" && test ! -L "$candidate_dir" &&
    test "$(stat -c %u -- "$candidate_dir")" = "$USER_ID" || refuse "install directory became unsafe: $candidate_dir"
  directory_mode="$(stat -c %a -- "$candidate_dir")"
  test "$((0$directory_mode & 022))" -eq 0 || refuse "install directory is group- or world-writable: $candidate_dir"
done
test -z "$INSTALL_ROOT_ID" ||
  test "$(stat -c '%d:%i:%u:%a' -- "$INSTALL_ROOT")" = "$INSTALL_ROOT_ID" ||
  refuse 'install root changed during installation'
test -z "$BIN_DIR_ID" ||
  test "$(stat -c '%d:%i:%u:%a' -- "$BIN_DIR")" = "$BIN_DIR_ID" ||
  refuse 'install bin directory changed during installation'
INSTALL_ROOT_HELD="$(stat -c '%d:%i:%u:%a' -- "$INSTALL_ROOT")"
BIN_DIR_HELD="$(stat -c '%d:%i:%u:%a' -- "$BIN_DIR")"
stage_candidate="$BIN_DIR/.keyrx-install-$$"
test ! -e "$stage_candidate" && test ! -L "$stage_candidate" || refuse 'installer staging name already exists'
STAGED="$stage_candidate"
install -m 0755 "$SOURCE" "$STAGED"
test "$("$STAGED" --version)" = "keyrx $VERSION" || refuse 'staged executable version differs'
HOME="$HOME" NO_COLOR=1 KEYRX_NO_LINKS=1 "$STAGED" verify
target_unchanged() {
  if test -n "$EXISTING_KEYRX_ID"; then
    test -f "$BIN_DIR/keyrx" && test ! -L "$BIN_DIR/keyrx" &&
      test "$(stat -c '%d:%i:%u:%h:%a' -- "$BIN_DIR/keyrx")" = "$EXISTING_KEYRX_ID"
  else
    test ! -e "$BIN_DIR/keyrx" && test ! -L "$BIN_DIR/keyrx"
  fi
}
test -d "$INSTALL_ROOT" && test ! -L "$INSTALL_ROOT" &&
  test "$(stat -c '%d:%i:%u:%a' -- "$INSTALL_ROOT")" = "$INSTALL_ROOT_HELD" &&
  test -d "$BIN_DIR" && test ! -L "$BIN_DIR" &&
  test "$(stat -c '%d:%i:%u:%a' -- "$BIN_DIR")" = "$BIN_DIR_HELD" &&
  target_unchanged ||
  refuse 'install directory changed before executable replacement'

# Escape shell metacharacters in the absolute path before writing Bash code.
escaped_bin="$(printf '%s' "$BIN_DIR" | sed 's/[\\$`\"]/\\&/g')"
if test -n "$PROFILE"; then
  profile_line="export PATH=\"$escaped_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH\""
  if test ! -e "$PROFILE" || test "$(tail -n 1 -- "$PROFILE")" != "$profile_line"; then
    PROFILE_STAGE="$(mktemp "$HOME/.keyrx-bashrc.XXXXXXXX")"
    test -f "$PROFILE_STAGE" && test ! -L "$PROFILE_STAGE" || refuse 'could not stage a safe Bash profile update'
    if test -e "$PROFILE"; then
      test -n "$PROFILE_ID" || refuse '.bashrc appeared during installation; refusing to overwrite it'
      cp -p -- "$PROFILE" "$WORKDIR/bashrc-original"
      cp --preserve=all -- "$PROFILE" "$PROFILE_STAGE"
      printf '\n%s\n' "$profile_line" >> "$PROFILE_STAGE"
      cmp -s -- "$PROFILE" "$WORKDIR/bashrc-original" || refuse '.bashrc changed during installation; refusing to overwrite it'
      test -f "$PROFILE" && test ! -L "$PROFILE" &&
        test "$(stat -c '%d:%i:%u:%h:%a' -- "$PROFILE")" = "$PROFILE_ID" ||
        refuse '.bashrc ownership, mode, or identity changed during installation'
    else
      test -z "$PROFILE_ID" && test ! -L "$PROFILE" || refuse '.bashrc disappeared or became unsafe during installation'
      printf '%s\n' "$profile_line" > "$PROFILE_STAGE"
    fi
    mv -f -- "$PROFILE_STAGE" "$PROFILE"
    PROFILE_STAGE=''
  fi
fi

test -d "$INSTALL_ROOT" && test ! -L "$INSTALL_ROOT" &&
  test "$(stat -c '%d:%i:%u:%a' -- "$INSTALL_ROOT")" = "$INSTALL_ROOT_HELD" &&
  test -d "$BIN_DIR" && test ! -L "$BIN_DIR" &&
  test "$(stat -c '%d:%i:%u:%a' -- "$BIN_DIR")" = "$BIN_DIR_HELD" &&
  target_unchanged ||
  refuse 'install directory or existing keyrx changed before executable replacement'
mv -f -- "$STAGED" "$BIN_DIR/keyrx"
STAGED=''
test "$("$BIN_DIR/keyrx" --version)" = "keyrx $VERSION" || refuse 'installed executable version differs'
HOME="$HOME" NO_COLOR=1 KEYRX_NO_LINKS=1 "$BIN_DIR/keyrx" verify

printf 'keyrx %s installed at %s\n' "$VERSION" "$BIN_DIR/keyrx"
if test "$NO_PROFILE" = 0; then
  printf 'If keyrx is not found in this terminal, run: export PATH="%s:$PATH"\n' "$escaped_bin"
  if test -n "$PROFILE"; then
    printf '%s\n' 'Open a new Bash shell, then run: command -v id && command -v curl && command -v keyrx && keyrx --version && keyrx verify'
  else
    printf '%s\n' 'SHELL does not indicate Bash, so no profile was changed. Add the install bin directory to your shell profile before opening a new shell.'
  fi
fi
