#!/bin/sh
# A no-network Cargo stand-in for the macOS source updater's held-exec smoke.
set -eu
test "$#" -eq 5
test "$1" = install
test "$2" = --locked
test "$3" = --root
test "$4" = "${KEYRX_TEST_INSTALL_ROOT:?}"
test "$5" = keyrx
test ! -e "${KEYRX_TEST_CARGO_CALLED:?}"
: > "$KEYRX_TEST_CARGO_CALLED"
