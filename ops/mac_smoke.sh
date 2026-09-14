#!/usr/bin/env bash
# Exercise a local source installation on a hosted Mac without exposing match secrets.
set -euo pipefail

test "$#" -eq 2
install_root="$1"
expected_arch="$2"
test "$(uname -s)" = Darwin
test "$(uname -m)" = "$expected_arch"
test -d "$install_root"
binary="$install_root/bin/keyrx"
test -f "$binary" && test -x "$binary" && test ! -L "$binary"
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
fake_cargo="$script_dir/mac_fake_cargo.sh"
test -f "$fake_cargo" && test -x "$fake_cargo"
test -d "${RUNNER_TEMP:?GitHub runner temp directory is required}"

scratch="$(mktemp -d "$RUNNER_TEMP/keyrx-mac-smoke.XXXXXXXX")"
chmod 0700 "$scratch"
cleanup() {
  if test -n "${scratch:-}" && test -d "$scratch"; then
    rm -r -- "$scratch"
  fi
}
trap cleanup EXIT
mkdir "$scratch/home" "$scratch/data"
chmod 0700 "$scratch/home" "$scratch/data"
export HOME="$scratch/home"
export XDG_DATA_HOME="$scratch/data"
export NO_COLOR=1
export KEYRX_NO_LINKS=1

"$binary" --version
"$binary" verify > /dev/null
"$binary" bench --threads 1 --indices 1 --seconds 1 > /dev/null

"$binary" grind --ends-with a --threads 1 --indices 1 --count 1 > /dev/null
sol_record="$XDG_DATA_HOME/keyrx/matches/a.a.md"
test -f "$sol_record" && test ! -L "$sol_record"
test "$(stat -f %Lp "$sol_record")" = 600
test "$(stat -f %Lp "$(dirname "$sol_record")")" = 700
"$binary" show -- "$sol_record" > /dev/null

"$binary" grind --chain evm --ends-with a --checksum \
  --threads 1 --indices 1 --count 1 > /dev/null
evm_record="$XDG_DATA_HOME/keyrx/matches/evm/a.cs.a.md"
test -f "$evm_record" && test ! -L "$evm_record"
test "$(stat -f %Lp "$evm_record")" = 600
test "$(stat -f %Lp "$(dirname "$evm_record")")" = 700
"$binary" show -- "$evm_record" > /dev/null

called="$scratch/cargo-called"
CARGO="$fake_cargo" KEYRX_TEST_INSTALL_ROOT="$install_root" \
  KEYRX_TEST_CARGO_CALLED="$called" \
  "$binary" --update > "$scratch/update.stdout"
test -f "$called"
grep -F 'Run keyrx again from this shell.' "$scratch/update.stdout" > /dev/null
"$binary" --version > /dev/null

printf 'macOS source install, verify, benchmark, Solana/EVM custody, and safe update handoff passed on %s\n' "$expected_arch"
