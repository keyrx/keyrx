# Security

keyRX is a vanity address grinder: it generates seed phrases and private keys and writes them
to a file on your machine. That makes every bug a potential key-safety bug, so this file says how
the project is checked, what to report, and how.

## Report a vulnerability

Email **dev@keyrx.tech**. Say what you found, how to reproduce it, and which version
(`keyrx --version`). Expect an acknowledgement within a few days and a fix in the next release;
you will be credited in the CHANGELOG unless you ask not to be. There is no bounty pool yet;
when there is, it will be stated here. Please do not open a public issue for a key-safety bug
before a fix exists.

## What is in scope

- The `keyrx` crate on crates.io and this repository: derivation (SLIP-0010, BIP32, BIP39),
  address encoding, matching, the match file, the terminal output, `verify`, `--update`.
- keyrx.tech: the site and its in-browser toy grind (which must never keep a key).

Out of scope: wallets that import what keyRX produces, the chains themselves, and social
engineering of people who run the tool.

## Supported versions

The newest release only. Every publish yanks the release before it on crates.io, so a fresh
`cargo install keyrx` can only land on the newest; `keyrx --update` brings an older install
forward. A yank never breaks an install you already have.

## How a release is checked, and how you can check it

- **`keyrx verify`**, on your own machine, before trusting a result: the base58 suffix path against
  full encoding on 50,000 keys; SLIP-0010 against a pinned `solana-keygen` answer; the BIP39
  passphrase vector; on EVM the "abandon … about" mnemonic's published account and key, EIP-55's
  four examples, private key 1, and the tool's own public test seed against an independent
  implementation (node crypto + noble). It then prints the manual cross-checks to run with
  `solana-keygen` and `cast` (or a throwaway MetaMask).
- **Tests and clippy** run before anything publishes (`publish.yml`); every framed line the CLI
  draws is measured in tests; the site's version is pinned to the crate's by a test.
- **Trusted publishing**: the crate is published by the `publish.yml` workflow through crates.io's
  OIDC trust; there is no long-lived publish token anywhere.
- **Provenance**: each published `.crate` carries a signed build-provenance attestation (Sigstore,
  via GitHub) naming the commit and the workflow that produced it. Check it with
  `gh attestation verify --owner keyrx keyrx-<version>.crate`, or read it under the repository's
  Attestations.
- **Reproducible**: `reproducible.yml` rebuilds the `.crate` from the tag on a clean runner and
  compares it with the registry's copy file for file (every file's sha256; the archive bytes
  themselves can differ between cargo versions by a tar timestamp, the contents cannot). You can do
  the same: `git checkout v<version> && cargo package --no-verify`, unpack that and
  `https://static.crates.io/crates/keyrx/keyrx-<version>.crate`, and compare the files.
- **SBOM**: every GitHub Release attaches `keyrx-sbom.cdx.json`, the dependency tree with versions
  and checksums (CycloneDX).
- **`cargo audit`** (`audit.yml`): the tree against the RustSec advisory database on every change
  and every week.
- **OpenSSF Scorecard** (`scorecard.yml`): an automated reading of repository practice, published;
  the badge in the README is that live number.

## What keyRX never does

No network calls at run time. No daemon, no service, no telemetry, no account. A seed or key
reaches the screen only when you ask (`--show-seed`, `show --seeds`, `show --keys`); a match is
written to a mode-0600 file in a mode-0700 directory before anything is printed, and if that
write fails the seed is not printed as a fallback. A losing candidate's key is never kept.
