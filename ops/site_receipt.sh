#!/usr/bin/env bash
# The receipt for keyrx.tech, read THROUGH THE DOMAIN regardless of the origin host: / must be
# byte-identical to site/index.html, the site's VERSION equal to Cargo.toml's,
# the text files answering 200, an unknown path answering 404.
#   ops/site_receipt.sh            # verify the live site against this checkout
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; HOST="${HOST:-https://keyrx.tech}"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
curl -fsS --max-time 20 -H 'Cache-Control: no-cache' "$HOST/" -o "$tmp"
if cmp -s "$tmp" "$ROOT/site/index.html"; then echo "live / is byte-identical to site/index.html"; else echo "live / DIFFERS from site/index.html (not deployed yet?)"; exit 1; fi
want="$(grep -E '^version\s*=' "$ROOT/Cargo.toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
got="$(grep -oE "var VERSION='[^']+'" "$tmp" | head -1 | sed -E "s/.*'([^']+)'.*/\1/")"
[ "$got" = "$want" ] && echo "live VERSION $got = Cargo.toml $want" || { echo "live VERSION '$got' != Cargo.toml '$want'"; exit 1; }
for p in $(cd "$ROOT/site" && ls | grep -E '\.(txt|xml)$' || true); do code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$HOST/$p")"; [ "$code" = 200 ] && echo "/$p 200" || { echo "/$p $code"; exit 1; }; done
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$HOST/no-such-path")"; [ "$code" = 404 ] && echo "/no-such-path 404" || { echo "/no-such-path $code (expected 404)"; exit 1; }
