# Security

keyRX is a vanity address grinder: it generates seed phrases and private keys and writes them
to a file on your machine. That makes every bug a potential key-safety bug, so this file says how
the project is checked, what to report, and how.

## Report a vulnerability

Email **security@keyrx.tech**. Say what you found, how to reproduce it, and which version
(`keyrx --version`). Expect an acknowledgement within a few days and a fix in the next release;
you will be credited in the CHANGELOG unless you ask not to be. There is no bounty pool yet;
when there is, it will be stated here. Please do not open a public issue for a key-safety bug
before a fix exists. (Everything that is not a vulnerability: dev@keyrx.tech.)

## What is in scope

- The `keyrx` crate on crates.io and this repository: derivation (SLIP-0010, BIP32, BIP39),
  address encoding, matching, the match file, the terminal output, `verify`, `--update`.
- keyrx.tech: the site and its in-browser suffix demo (which must never create or claim a key).

Out of scope: wallets that import what keyRX produces, the chains themselves, and social
engineering of people who run the tool.

## Supported versions

The newest release only. The consolidated workflow used for 0.4.13 and later is designed to yank
its governed predecessor only after the registry package, immutable GitHub Release and provenance
agree. A yank never breaks an existing install or lockfile; `keyrx --update` brings an older install
forward. Check crates.io itself for the current public version and yank state.

## How a release is checked, and how you can check it

- **`keyrx verify`**, on your own machine, before trusting a result: the base58 suffix path against
  full encoding on 50,000 keys; SLIP-0010 against a pinned `solana-keygen` answer; the BIP39
  passphrase vector; on EVM the "abandon … about" mnemonic's published account and key, EIP-55's
  four examples, private key 1, and the tool's own public test seed against an independent
  implementation (node crypto + noble). It then prints the manual cross-checks to run with
  `solana-keygen` and `cast` (or a throwaway MetaMask).
- **Tests and clippy** run before anything publishes (`publish.yml`); every framed line the CLI
  draws is measured in tests; the site's version is pinned to the crate's by a test.
- **Trusted publishing**: releases produced by the current `publish.yml` workflow use crates.io's
  OIDC trust; the repository workflow stores no long-lived publish token.
- **Provenance**: that workflow requires a signed build-provenance attestation (Sigstore,
  via GitHub) naming the commit and the workflow that produced it. Check it with
  `gh attestation verify --owner keyrx keyrx-<version>.crate`, or read it under the repository's
  Attestations.
- **Release agreement**: the one `publish.yml` state machine preserves the tag-built `.crate`,
  uploads those exact archive bytes, then downloads the registry copy and requires byte-for-byte
  equality. Before that, release preflight binds every packaged source file to the corresponding Git
  blob at the release commit. To inspect a release yourself, verify the release attestation and its
  `keyrx-<version>.crate.sha256`; a new local `cargo package` can be unpacked and compared by content,
  but archive metadata can vary across Cargo versions.
- **SBOM**: the current workflow requires its immutable GitHub Release to attach
  `keyrx-<version>.cdx.json`, the dependency tree with versions and checksums (CycloneDX).
- **`cargo audit`** (`audit.yml`): the tree against the RustSec advisory database on every change
  and every week.
- **OpenSSF Scorecard** (`scorecard.yml`): an automated reading of repository practice, published;
  the badge in the README is that live number.

## What keyRX never does

Grinding, estimating, benchmarking, showing and verifying make no network calls. The explicit
`--update` command invokes Cargo to fetch and install a release. There is no daemon, service,
telemetry or account. A seed or key reaches the screen only when you ask (`--show-seed`,
`show --seeds`, `show --keys`); on Unix a default match is written to a mode-0600 file in the
tool's mode-0700 directory before it is printed. A custom `--out` parent must be owned by the
caller and not group/world-writable. Secret-writing and `show` commands refuse on non-Unix
platforms until an owner-only ACL implementation is available; Windows users can use WSL.
If a write or durability flush fails, the seed is not printed as a fallback. A losing
candidate's key is never kept.

On Unix, `--update` resolves the root containing the running installed binary (unless an absolute
`CARGO_INSTALL_ROOT` is explicit), passes that root to Cargo, then opens the installed binary with
no link following. It requires a caller-owned, non-group/world-writable, executable, single-link
regular file and relaunches the held descriptor. Non-Unix automatic relaunch is refused until an
equivalent held-identity boundary exists; the CLI prints the manual `cargo install --locked keyrx`
command instead.
