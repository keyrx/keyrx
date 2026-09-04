<p align="center">
  <img src="https://raw.githubusercontent.com/keyrx/keyrx/v0.4.17/assets/x-header-1500x500.png" width="100%" alt="keyRX CLI: Solana and EVM vanity address grinder">
</p>

<p align="center">
  <em>The keyRX CLI. Solana and EVM vanity address grinder. One seed, many addresses, exact keys and paths. Offline grinding. Open. Verified. The mark is a record. What it seals comes next.</em><br>
  <sub>one seed · walk the tree · every match written once, mode 0600 · verified against solana-keygen, and against an independent implementation on EVM</sub>
</p>

<p align="center">
  <a href="https://github.com/keyrx/keyrx/blob/main/LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="https://crates.io/crates/keyrx"><img alt="crates.io" src="https://img.shields.io/crates/v/keyrx.svg"></a>
  <img alt="grinding mode" src="https://img.shields.io/badge/grinding-offline-brightgreen.svg">
</p>

# keyRX

**KEYRX, five exact letters, modeled at about 1 in 656,356,768. `solana-keygen grind` at its 13,600/sec:
a 13.4-hour mean, 9.3-hour median. In the cited keyRX run: 13 minutes to a match.**
Same machine and exact target: rates and the observed hit were measured. The odds use the transparent
base58 model and are labeled approximate because signing-key outputs are not uniform base58 text.
(A five-letter grind the old way ran 50 hours here and found nothing.)

Solana and EVM BIP39 vanity address grinder. Standalone terminal tool - no daemon
or service. Grinding, estimating, benchmarking, showing and verifying make no network
requests; only the explicit `--update` command asks Cargo to fetch a release. Replaces
`solana-keygen grind --use-mnemonic`; on EVM it
does the same thing for Ethereum, Base, Arbitrum, Optimism, Polygon, BNB, Robinhood Chain
and every chain that shares the key format (one key is every one of them).

Why it is fast: one mnemonic yields many addresses (keyRX supports account indices
0 through 2^31-1 in a derivation lane). Derive to
m/44'/501' once, then walk the account index; each extra candidate costs
two HMAC-SHA512 ops and one Ed25519 scalar mult instead of 2048 rounds of
PBKDF2. Suffix matching needs only the last N base58 characters.

    cargo install --locked keyrx                                         # from crates.io · Rust 1.85 or newer
    keyrx                                                                # the start screen
    RUSTFLAGS="-C target-cpu=native" cargo install --locked --path .    # from a clone, tuned to this CPU

    keyrx                                                               # start screen: every command and flag, explained
    keyrx verify                                                        # run first, always
    keyrx bench --indices 128                                           # measures and saves this 128-index workload
    keyrx estimate --ends-with KEYRX --indices 128                       # odds plus measured time for that profile
    keyrx grind --ends-with KEYRX --words 12 --indices 8 --out mint.txt  # bounded seed-recovery lane
    keyrx show mint.txt --keys                                           # read that custom output file
    keyrx grind --ends-with KEYRX --indices 128                          # one Markdown file per hit; prints its exact show command
    keyrx grind --starts-with cMaiL --ends-with gg --indices 128          # both ends: prefix AND suffix, one address
    keyrx show                                                           # list every managed record and its exact show command
    keyrx estimate --chain evm --ends-with dead                          # EVM: hex, any case by default
    keyrx grind --chain evm --ends-with dead                             # 0x...dead; prints the exact full-path show command
    keyrx grind --chain evm --starts-with 0xc0ffee --checksum            # the letters in EIP-55 case as typed, too
    keyrx show                                                           # EVM records are listed under evm/

`bench`, `grind`, and `show` require Unix owner-only file semantics; on Windows,
run them under WSL. While a single-match grind runs, one line rewrites in place
every 2s: candidates tried, rate, elapsed, and time to the 50% and 90% marks.
A multi-match run shows `found X/N` and mean remaining time instead. Every match
prints its address, path and the wallet import guidance for that path style and index.

## Security, and how to check a release

[![audit](https://github.com/keyrx/keyrx/actions/workflows/audit.yml/badge.svg)](https://github.com/keyrx/keyrx/actions/workflows/audit.yml)
[![release agreement](https://github.com/keyrx/keyrx/actions/workflows/publish.yml/badge.svg)](https://github.com/keyrx/keyrx/actions/workflows/publish.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/keyrx/keyrx/badge)](https://scorecard.dev/viewer/?uri=github.com/keyrx/keyrx)
[![attestations](https://img.shields.io/badge/provenance-attested-2f6f9f.svg)](https://github.com/keyrx/keyrx/attestations)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14185/badge)](https://www.bestpractices.dev/projects/14185)

`keyrx verify` first, on your own machine. Release evidence is tag-specific. The current
`publish.yml` uses crates.io trusted publishing: no long-lived publish token is stored, and a
short-lived crates.io token is obtained through OIDC only for an authorized upload. Every release
completed by that workflow carries a signed build-provenance attestation
(`gh attestation verify --owner keyrx keyrx-<version>.crate`), compares the tag-built package with
the registry copy, and attaches a CycloneDX SBOM. Provenance and SBOM assets were introduced in
0.4.7; check the exact tag's Actions run and GitHub Release rather than assuming an older release
has the current asset set. The dependency tree is audited against RustSec on every change and every
week, OpenSSF Scorecard reads repository practice continuously, and the project self-certifies
against the OpenSSF Best Practices criteria. What to report, and how (security@keyrx.tech):
[SECURITY.md](https://github.com/keyrx/keyrx/blob/main/SECURITY.md). How to contribute, and what a
change has to bring: [CONTRIBUTING.md](https://github.com/keyrx/keyrx/blob/main/CONTRIBUTING.md).

## The site

`site/index.html` is the keyrx.tech application document: its font is embedded and it makes no
third-party runtime requests; same-origin favicon and social-preview assets are served beside it.
It renders the CLI's own panels and runs a suffix probability demo in a Web Worker: random 32-byte
values, real base58, no keypair, seed, signer or derivation path, and nothing kept. A hit is not a
wallet and must never be funded. Two grids (78 desktop / 42 phone); every framed line is measured by
`node tests/site_harness.js site/index.html`.

## The look

Double-line frames with title tabs, an `ink` palette (healthy is hueless
grey; amber at 70%, rose at 90%), gauge bars in `█▌░`. Every
framed line is measured in tests - the width invariant is asserted, never
eyeballed. Colour drops out entirely when stdout is not a terminal.

## Verified on 2026-08-16

- `keyrx verify`: 50,000 pubkeys × 10 suffix lengths OK; derivation deterministic.
- **solana-keygen cross-check: identical** at both path styles for the
  `[7u8; 32]` test entropy - `8zzKEAB4Vqn…UQPh1j` (m/44'/501'/0'/0') and
  `2Ju5fiKYKf4…NjAnKo` (m/44'/501'/0'). Both are pinned as `#[test]`s.
- **A ground hit imports**: `grind --ends-with ab --indices 8` found a match
  in 0.15s and `solana-keygen pubkey "prompt://?full-path=m/44'/501'/6'/0'"`
  with that mnemonic returned the identical address.
- Bench (28 threads): 265,863/sec at 64 indices (19.5× the 13,600 baseline),
  331,793/sec at 128 (24.4×), 437,811/sec at 256 (32.2×). Per core: 9,495-15,636
  vs 284 baseline (33-55×).
- `cargo clippy --all-targets` clean; 10 tests green.

## Verified on 2026-08-20 (EVM)

- The "abandon … about" mnemonic derives its published first account
  `0x9858EfFD…EcaEda94` and key at `m/44'/60'/0'/0/0`; EIP-55's four specification
  examples round-trip; private key 1 is `0x7E5F4552…9395Bdf`. All pinned as `#[test]`s.
- **Independent cross-check**: the same `[7u8; 32]` test seed at indices 0, 1, 2 and 7,
  and with the passphrase "correct horse", derived by a separate implementation (node
  crypto + `@noble/curves` + `@noble/hashes`, a different language and libraries) gives
  the identical addresses and keys; pinned.
- **Two ground hits re-derive**: `grind --chain evm --ends-with dead --count 2` found
  two matches in about a second (317,800 candidates); both re-derived, address and key,
  by that independent implementation from the match file alone.
- Bench (28 threads, 64 indices): 333,501/sec, 11,911/sec/thread; the Solana loop on
  the same box and settings: 498,030/sec, 17,787/sec/thread.
- `cargo clippy --all-targets` clean; 41 tests green; every framed line measured.

## Secrets

Seed phrases never reach stdout, logs or panic output by default. A default grind
creates one mode-0600 Markdown record per successful hit; `--show-seed` is opt-in.
An explicit `--out FILE` retains the appendable private-ledger behavior. If that
ledger cannot be opened safely, the grind inserts `.recovered` before its extension
(`mint.txt` becomes `mint.recovered.txt`, also mode 0600 on Unix); if that fails too,
the grind never starts. A later write failure stops the grind, returns nonzero and
never prints the unpersisted seed as a fallback. Entropy, seed and derived key
material are zeroized.

Test only with 2-character targets. Every full mnemonic committed in a fixture,
test vector or source file is deliberately public: either a published standard
vector or a phrase derived from public constant entropy. No generated or secret
mnemonic is committed; the public test accounts are worthless by construction.

`--passphrase` grinds with a BIP39 passphrase (the "25th word"): prompted
on the terminal, hidden, typed twice; never read from a flag, a file or the
environment, never stored, never printed. The match file records only that
one was used - the seed alone will then NOT reach the address; the privkey
and keypair lines will, standalone. Most browser wallets have no passphrase
field on seed import, so a passphrase address is imported by KEY. `keyrx
verify` checks the passphrase path against the BIP39 specification's own
test vector ("TREZOR").

## Which wallet, which flags

A default grind writes each Solana hit into one self-contained, versioned Markdown
record. It includes a chain-specific import/recovery guide and the creation recipe
that selected the address and derivation lane. `--count`, `--out`, `--threads`, and
`--show-seed` are deliberately omitted so quantity, destination, workers, and
terminal display remain choices for the next run. Passphrase presence is recorded;
the passphrase value is never stored. Existing `.txt` ledgers remain readable and
explicit `--out FILE` keeps their append-compatible format.

The Markdown fields are uppercase headings with the exact value on the next line:
`ADDRESS`, `PATH`, `SEED` (12 or 24 words, restoring the whole tree), `PASSPHRASE`,
`PRIVATE KEY (BASE58)` (the 64-byte keypair used by current **Phantom** and
**Solflare** private-key import flows), and `KEYPAIR (JSON)` (the same 64 bytes as
`[1,2,...]` for `solana-keygen`). Wallet labels and onboarding change by version: choose the
installed wallet's **Import Private Key** route and paste the base58 value;
Phantom currently exposes that route during onboarding as well as inside an
existing wallet. The JSON array is the `solana-keygen` form, not the wallet
paste form. A key import lands on the exact address as a standalone account -
the index never matters, so grind wide (`--indices 128`). The receiving wallet's
unrelated seed does not recover an imported account: the match file (or an
equivalent backup of its recovery material) is the backup. Verified both ways:
the ground base58 key converted to bytes and the JSON line copied verbatim each
fed to `solana-keygen pubkey` print the identical address.

Importing the **seed** instead puts the address inside a recoverable HD wallet,
but recovery is wallet/version/path-discovery dependent. Use the exact printed
path where the installed wallet supports it and verify the resulting address
before funding; do not assume an unfunded high index will be discovered. If a
Phantom version walks the exact `m/44'/501'/N'/0'` family, index 89 is account
#90, reached after 89 Add Account steps from account #1. That relationship is
conditional on the installed wallet using that same family; the record's printed
path remains authoritative.
Use `--indices 8` to bound a seed-recovery match to account index 0 through 7;
whether and how a wallet discovers that path remains version-dependent. `--words` defaults to 12.
BIP39 defines
12- and 24-word phrases; confirm that the receiving wallet supports the length
and exact import path you choose. Private-key import is the exact-address lane.

## EVM (`--chain evm`, 0.4.0)

Same idea, other curve. One mnemonic pays PBKDF2 once; the BIP44 tree
`m/44'/60'/0'/0/N` is walked at one HMAC-SHA512 plus one secp256k1 scalar
multiplication per candidate, and the address is the last twenty bytes of
keccak-256 over the public key, written in EIP-55 case. Measured on the
development machine: about 11,900 candidates/sec per thread at 64 indices,
two thirds of the Ed25519 rate; a six-hex-digit suffix is under a minute on
a desktop, eight is hours. `keyrx bench --chain evm` measures yours and
`estimate --chain evm` reads it (its own file: the two loops cost nothing
alike). The benchmark uses one deliberately rare 16-hex suffix so matches do
not distort throughput; a different matcher shape is identified as an approximate
measured baseline rather than presented as that exact workload.

Patterns are hex, `0-9 a-f`, matched in **any case by default** because hex
has no case of its own; `0x` may lead a prefix. `--checksum` asks for more:
the letters must also come out in EIP-55 case exactly as typed, a coin flip
per letter, and `estimate` prints both numbers.

Each EVM hit receives its own EVM-specific Markdown record and guidance rather than
Solana copy. Its fields are `ADDRESS` (EIP-55), `PATH`, `SEED`, `PASSPHRASE`, and
`PRIVATE KEY (HEX)` in the `0x` form imported by MetaMask and Rabby. **MetaMask /
Rabby:** use the installed version's
Import account → Private key route and paste it: the exact address, standalone,
on every EVM chain, including any network you add to the wallet. Seed recovery
is wallet-dependent: use it only where the wallet can select the exact printed
`m/44'/60'/0'/0/N` path, and verify before funding.
`keyrx show` lists EVM records under `evm/` and prints the exact command for each.
`--passphrase`,
`--count`, `--out`, `--words` work the same on both chains; `--path` is
Solana-only.

`keyrx networks` prints the add-a-network steps for MetaMask and Rabby and the
values for EVM chains a wallet does not list by default, bare for pasting: today
Robinhood Chain (Ethereum L2, mainnet): RPC `https://rpc.mainnet.chain.robinhood.com`,
chain ID `4663`, currency `ETH`, explorer `https://robinhoodchain.blockscout.com`
(Blockscout); the chain id was checked against that RPC on 2026-08-21. The same address
and key work there; only the selected network differs.

`keyrx verify` checks the EVM path against the "abandon … about" mnemonic's
published first account and key, this tool's own public test seed at four
indices against an independent implementation (node crypto + noble), the
four EIP-55 specification examples, and private key 1; and prints the manual
cross-check (`cast wallet address --mnemonic … --mnemonic-index 0`, or a
throwaway MetaMask).

## Where matches go

By default, `~/.local/share/keyrx/matches/` (or `$XDG_DATA_HOME/keyrx/matches/`), a
mode-0700 managed directory of its own on Unix. Each successful hit is one mode-0600
Markdown file. The name combines the requested pattern with the exact address text
that matched: `--ends-with coined --ignore-case` can write
`coined.ic.coiNED.md`. If that exact name already exists, keyRX creates
`coined.ic.coiNED.02.md`, then `.03.md`, using create-new semantics and never
overwriting a prior key. Prefix-only and prefix-plus-suffix searches preserve the
realized address edges the same way. EVM files sit under `matches/evm/`.

After its final custody check, a successful default grind prints the exact copy-ready
`keyrx show -- '<full-managed-path>/<record>.md'` command for every record it just created,
including actual case, duplicate suffix, and the EVM directory. The full path makes the command
unambiguous from any working directory. It never adds `--seeds` or `--keys`.
`keyrx show` lists both new Markdown records and legacy `.txt` ledgers and prints an
exact command for each (`--seeds` / `--keys` reveal the secrets). `--out FILE`
explicitly selects the existing appendable ledger format. A no-match default grind
leaves no recovery record; every created Markdown file contains exactly one hit.

## Known behaviour (unchanged from the reference, by instruction)

Superseded releases are yanked on crates.io when a new one publishes (never deleted; an
existing install keeps working). On Unix, `keyrx --update` preserves the install root of
the running `<root>/bin/keyrx`, holds the newly installed executable by descriptor and
relaunches that exact inode. An explicit root must be absolute. Other platforms refuse
the automatic relaunch and print the manual Cargo command.

`--count N` reserves exactly N output slots before writing. Threads that find
later candidates after all slots are reserved discard them; a default run creates
exactly N one-hit Markdown records unless interrupted or a write fails. An explicit
`--out FILE` ledger receives those N complete records.
Keep `--indices` low for seed recovery unless the receiving wallet/version has
been proven to discover the exact printed path. Private-key import is not
index-dependent.

## The mark

The mark is a record: sixty-four hex digits of a hash on an 8×8 grid, a cell lit
where the digit is 8 or above; the upper half blue, the lower half amber. The CLI prints it above the
start screen. [`assets/logo.svg`](https://github.com/keyrx/keyrx/blob/main/assets/logo.svg) is the
source ([`assets/make_mark.py`](https://github.com/keyrx/keyrx/blob/main/assets/make_mark.py) draws
it from the hash) and every raster is cut from that file. What the record is will be said when the
time comes.

## Changelog

[CHANGELOG.md](https://github.com/keyrx/keyrx/blob/main/CHANGELOG.md) - one section per version on crates.io.

## Licence and name

MIT - use it, fork it, ship it, sell it. The code is yours under that licence, and
with it the look: anyone may build a grinder that frames its panels the same way.
The **name**, the **mark**, the files under `assets/`, and the branded
`site/favicon*` and `site/og.png` files are not part of
the grant - see [TRADEMARK.md](https://github.com/keyrx/keyrx/blob/main/TRADEMARK.md) and
[`assets/LICENSE`](https://github.com/keyrx/keyrx/blob/main/assets/LICENSE). Forks rebrand.
