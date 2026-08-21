<p align="center">
  <img src="assets/x-header-1500x500.png" width="100%" alt="keyRX: Solana and EVM vanity address grinder">
</p>

<p align="center">
  <em>Solana and EVM vanity address grinder. One seed, unlimited addresses, keys for every wallet. Offline. Open. Verified. The mark is a record. What it seals comes next.</em><br>
  <sub>one seed · walk the tree · every match written once, mode 0600 · verified against solana-keygen, and against an independent implementation on EVM</sub>
</p>

<p align="center">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="https://crates.io/crates/keyrx"><img alt="crates.io" src="https://img.shields.io/crates/v/keyrx.svg"></a>
  <img alt="dependencies at runtime" src="https://img.shields.io/badge/network-none-brightgreen.svg">
</p>

# keyRX

**KEYRX, five exact letters, 1 in 656,356,768. `solana-keygen grind` at its 13,600/sec:
a 13-hour median. keyRX: 13 minutes, a match.** Same machine, same odds - measured, not
estimated. (A five-letter grind the old way ran 50 hours here and found nothing.)

Solana and EVM BIP39 vanity address grinder. Standalone terminal tool — no daemon,
no service, no network. Replaces `solana-keygen grind --use-mnemonic`; on EVM it
does the same thing for Ethereum, Base, Arbitrum, Optimism, Polygon, BNB and every
chain that shares the key format (one key is every one of them).

Why it is fast: one mnemonic yields unlimited addresses. Derive to
m/44'/501' once, then walk the account index; each extra candidate costs
two HMAC-SHA512 ops and one Ed25519 scalar mult instead of 2048 rounds of
PBKDF2. Suffix matching needs only the last N base58 characters.

    cargo install keyrx && clear && keyrx                               # from crates.io · Rust 1.85 or newer · lands on the start screen
    RUSTFLAGS="-C target-cpu=native" cargo install --path .             # from a clone, tuned to this CPU

    keyrx                                                               # start screen: every command and flag, explained
    keyrx verify                                                        # run first, always
    keyrx bench --indices 128                                           # measures AND saves the rate estimate uses
    keyrx estimate --ends-with KEYRX                                     # measured; what --ignore-case and --indices 128 buy
    keyrx grind --ends-with KEYRX --words 12 --indices 8 --out mint.txt  # Phantom
    keyrx grind --ends-with KEYRX --indices 128 --out mint.txt           # Solflare
    keyrx show KEYRX --keys                                              # the private key, for Phantom 'Import Private Key'
    keyrx estimate --chain evm --ends-with dead                          # EVM: hex, any case by default
    keyrx grind --chain evm --ends-with dead                             # 0x...dead; the key imports into MetaMask/Rabby
    keyrx grind --chain evm --starts-with 0xc0ffee --checksum            # the letters in EIP-55 case as typed, too
    keyrx show evm/dead --keys                                           # the 0x hex private key

While grinding, one line rewrites in place every 2s: candidates tried, rate,
elapsed, time to the 50% and 90% marks. Every match prints its address, path
and the exact wallet import steps for that path style and index.

## The site

`site/index.html` is keyrx.tech - one self-contained file (font subset
embedded, zero external requests) that renders the CLI's own panels and runs a
real toy grind in a Web Worker: real random keys, real base58, the address
shown and nothing kept. Two grids (78 desktop / 42 phone); every framed line
is measured by `node tests/site_harness.js site/index.html`.

## The look

Double-line frames with title tabs, an `ink` palette (healthy is hueless
grey; amber at 70%, rose at 90%), gauge bars in `█▌░`. Every
framed line is measured in tests - the width invariant is asserted, never
eyeballed. Colour drops out entirely when stdout is not a terminal.

## Verified on 2026-08-16

- `keyrx verify`: 50,000 pubkeys × 10 suffix lengths OK; derivation deterministic.
- **solana-keygen cross-check: identical** at both path styles for the
  `[7u8; 32]` test entropy — `8zzKEAB4Vqn…UQPh1j` (m/44'/501'/0'/0') and
  `2Ju5fiKYKf4…NjAnKo` (m/44'/501'/0'). Both are pinned as `#[test]`s.
- **A ground hit imports**: `grind --ends-with ab --indices 8` found a match
  in 0.15s and `solana-keygen pubkey "prompt://?full-path=m/44'/501'/6'/0'"`
  with that mnemonic returned the identical address.
- Bench (28 threads): 265,863/sec at 64 indices (19.5× the 13,600 baseline),
  331,793/sec at 128 (24.4×), 437,811/sec at 256 (32.2×). Per core: 9,495–15,636
  vs 284 baseline (33–55×).
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

Seed phrases never reach stdout, logs or panic output by default. Matches
go to a mode-0600 file (`--out`). `--show-seed` is opt-in. If the match
file cannot be written, the seed goes to `<out>.recovered` (also 0600); if
that fails too the grind STOPS and prints address+path only — never the
seed. Entropy, seed and derived key material are zeroized.

Test only with 2-character targets. No mnemonic in any fixture, snapshot or
committed file: the two pinned addresses derive from public constant entropy
and are worthless by construction.

`--passphrase` grinds with a BIP39 passphrase (the "25th word"): prompted
on the terminal, hidden, typed twice; never read from a flag, a file or the
environment, never stored, never printed. The match file records only that
one was used — the seed alone will then NOT reach the address; the privkey
and keypair lines will, standalone. Most browser wallets have no passphrase
field on seed import, so a passphrase address is imported by KEY. `keyrx
verify` checks the passphrase path against the BIP39 specification's own
test vector ("TREZOR").

## Which wallet, which flags

Every match writes five lines: `address`, `path`, `seed` (12 or 24 words -
restores the whole tree), `privkey` (the base58 64-byte keypair - what
**Phantom "Import Private Key"** pastes) and `keypair` (the same 64 bytes as a
JSON array `[1,2,...]` - what **Solflare** and `solana-keygen` import). A key
import lands on the exact address in one paste as a standalone account - the
index never matters, so grind wide (`--indices 128`). One thing every wallet
hides: a fresh Phantom or MetaMask insists on a seed phrase first and only then
offers an import; the wallet must exist (any seed, it never sees this key), and
the key import ADDS an account to it. Standalone means a seed
will not recover it: the match file *is* the backup. Verified both ways: a
ground base58 key converted to bytes, and the JSON line copied verbatim, each
fed to `solana-keygen pubkey` print the identical address.

Importing the **seed** instead puts the address inside a recoverable HD wallet.
Solflare takes the exact path the match printed. Phantom does not take a path -
it reaches account N by clicking "add account" N times - so a seed-into-Phantom
grind should use `--indices 8`. `--words` defaults to 12 (what Phantom
generates); every major wallet imports 12 or 24.

## EVM (`--chain evm`, 0.4.0)

Same idea, other curve. One mnemonic pays PBKDF2 once; the BIP44 tree
`m/44'/60'/0'/0/N` is walked at one HMAC-SHA512 plus one secp256k1 scalar
multiplication per candidate, and the address is the last twenty bytes of
keccak-256 over the public key, written in EIP-55 case. Measured on the
development machine: about 11,900 candidates/sec per thread at 64 indices,
two thirds of the Ed25519 rate; a six-hex-digit suffix is under a minute on
a desktop, eight is hours. `keyrx bench --chain evm` measures yours and
`estimate --chain evm` reads it (its own file: the two loops cost nothing
alike).

Patterns are hex, `0-9 a-f`, matched in **any case by default** because hex
has no case of its own; `0x` may lead a prefix. `--checksum` asks for more:
the letters must also come out in EIP-55 case exactly as typed, a coin flip
per letter, and `estimate` prints both numbers.

A match writes four lines under `matches/evm/<pattern>.txt`: `address`
(EIP-55), `path`, `seed`, and `privkey` as the `0x` hex every EVM wallet
imports. **MetaMask / Rabby:** a wallet must exist first (any seed; it never
sees this key); then account menu → Import account → Private key, paste it: the
exact address, standalone, on every EVM chain, including any network you add to
the wallet. Or import THIS seed as the wallet and "add account" N times
(account N+1 is the one). `keyrx show` lists EVM files as
`evm/<pattern>`; `keyrx show evm/dead --keys` reads one. `--passphrase`,
`--count`, `--out`, `--words` work the same on both chains; `--path` is
Solana-only.

`keyrx networks` prints the add-a-network steps for MetaMask and Rabby and the
values for EVM chains a wallet does not list by default, bare for pasting: today
Robinhood Chain (Ethereum L2, mainnet): RPC `https://rpc.mainnet.chain.robinhood.com`,
chain ID `4663`, currency `ETH`, explorer `https://explorer.mainnet.chain.robinhood.com`
(Blockscout); the chain id was checked against that RPC on 2026-08-21. The same address
and key work there; only the selected network differs.

`keyrx verify` checks the EVM path against the "abandon … about" mnemonic's
published first account and key, this tool's own public test seed at four
indices against an independent implementation (node crypto + noble), the
four EIP-55 specification examples, and private key 1; and prints the manual
cross-check (`cast wallet address --mnemonic … --mnemonic-index 0`, or a
throwaway MetaMask).

## Where matches go

`~/.local/share/keyrx/matches/` (or `$XDG_DATA_HOME/keyrx/matches/`), a
mode-0700 directory of its own - never the current directory. Each file is
mode 0600 and named after the pattern: `--ends-with KEYRX` -> `KEYRX.txt`,
`--ignore-case` -> `KEYRX.ic.txt`, several patterns join with `+`. EVM files
sit under `matches/evm/` (`dead.txt`, `--checksum` -> `DeAd.cs.txt`). `--out`
overrides. `keyrx show` lists the files; `keyrx show KEYRX` reads one
(`--seeds` / `--keys` reveal the secrets).

## Known behaviour (unchanged from the reference, by instruction)

Superseded releases are yanked on crates.io when a new one publishes (never deleted; an
existing install keeps working). `keyrx --update` keeps you on the newest.

`--count N` may return slightly more than N matches: several threads can
hit before the stop flag propagates. Every extra match is written and
valid. Phantom walks account indices sequentially when adding accounts, so
keep `--indices` low if Phantom is the target; Solflare takes custom paths.

## The mark

The mark is a record, sealed on chain: sixty-four hex digits of a hash on an 8×8 grid, a cell lit
where the digit is 8 or above; the upper half blue, the lower half amber. The CLI prints it above the
start screen. `assets/logo.svg` is the source (`assets/make_mark.py` draws it from the hash) and every
raster is cut from that file. What the record is will be said when the time comes.

## Changelog

[CHANGELOG.md](https://github.com/keyrx/keyrx/blob/main/CHANGELOG.md) — one section per version on crates.io.

## Licence and name

MIT — use it, fork it, ship it, sell it. The code is yours under that licence, and
with it the look: anyone may build a grinder that frames its panels the same way.
The **name**, the **mark**, and the files under `assets/` are not part of
the grant — see [TRADEMARK.md](TRADEMARK.md) and `assets/LICENSE`. Forks rebrand.
