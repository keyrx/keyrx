# Changelog

All notable changes to keyRX, newest first. Versions are the ones on crates.io.

## 0.4.14 - 2026-09-02

- Restore the normal one-tag release path: a protected version tag, short-lived crates.io OIDC
  credential, and one sequential run now publish the crate and immutable GitHub Release without a
  repository-administration token, temporary branch admission, or manual recovery dispatch.
- Restore `keyrx.sol` beside the authoritative Solana address on keyrx.tech, in both desktop and
  mobile layouts.
- Make the concurrent benchmark custody test prove the refusal path from its output and diagnostic
  instead of depending on wall-clock timing.

## 0.4.13 - 2026-09-02

- Match output and grind coordination are fail-closed: private files are opened without following
  links, must be caller-owned and single-link, concurrent grinds cannot share a target, exact match
  counts are reserved before a record is written, bounded files cannot grow beyond the read limit,
  and invalid zero-work requests are refused.
- Secret-bearing values have shorter lifetimes and are zeroized more consistently. `verify` now
  returns a failing process status when either chain's self-test fails. Existing EVM records refuse
  scalar zero before address derivation.
- Benchmark caches are bound to the CLI version, operating system, architecture and derivation
  profile and exact matcher workload; a persistent shared/exclusive guard closes the read-versus-new-
  benchmark race, failed ceremonies poison the lane, and estimates label a different workload as an
  approximate measured baseline. The rare EVM benchmark target is 16 hex digits so winner handling
  cannot materially distort the throughput sample.
- Pattern feasibility and odds use the same accepted edge pairs. Conflicting or impossible
  alternatives cannot inflate probability; near-complete EIP-55 constraints are exhaustively
  enumerated under a fixed budget. Full and near-complete Solana text is refused because valid point
  text alone cannot prove a clamped signing-key preimage. Every Solana odds row is labeled as an
  approximate model, overlaps are counted once, and wait quantiles never report zero trials.
- `keyrx --update` preserves a running custom Cargo install root, refuses empty or relative roots,
  opens the installed Unix executable without following links, requires a caller-owned, not-group/world-writable
  single-link inode and relaunches that held descriptor. Unsupported platforms fail closed and print
  the manual Cargo command.
- keyrx.tech now labels its browser activity as a probability demonstration, not wallet generation,
  and its version, modeled odds, current Phantom/Solflare base58 private-key guidance, JSON
  `solana-keygen` guidance, install copy and verification language match the CLI. Its panels expose
  heading semantics, asynchronous demo outcomes reach the live region at the actual outcome, native
  browser function keys remain native, and the measured speed and bounded seed-path index are explicit.
- `estimate` now fits its complete benchmark basis inside the terminal frame instead of clipping the
  actionable command into a misleading fragment.
- The release workflow is consolidated behind one preflighted, fail-closed publication path with
  pinned actions, exact artifact checks, and only explicitly recognized restart states. No release
  is performed by installing this version.

## 0.4.12 - 2026-08-24

- A prefix and suffix supplied together are one combined hunt. Every candidate must satisfy both
  constraints, and `--count` counts complete combined matches rather than separate pattern jobs.

## 0.4.11 - 2026-08-22

- `keyrx --help` introduces itself as the keyRX CLI too (its summary line was the one place that
  still said only what it does, not which product it is). Completes 0.4.10. No behaviour change.

## 0.4.10 - 2026-08-22

- The product names itself **keyRX CLI** wherever it introduces itself: the page title and cards of
  keyrx.tech, the README, and the crate description (the start screen already read keyRX | CLI).
  Two products share the keyRX name now, and this is the one with no token; saying CLI every time
  keeps that sentence true without a footnote. No behaviour change.

## 0.4.9 - 2026-08-22

- The donate panel names the Solana wallet as `keyrx.sol` only. 0.4.8 printed `keyrx.sol · keyrx.sns`
  and called them two spellings of one domain; `.sns` is not a spelling of anything, so it is gone
  from the CLI and the site. The addresses are unchanged.

## 0.4.8 - 2026-08-22

- The donate panel names the wallets as well as printing them: keyrx.sol · keyrx.sns (one
  on-chain domain, two spellings) under the Solana address, keyrx.eth · keyrx.base.eth · keyrx.hoodfi.eth under the EVM address (ENS, Basename,
  Robinhood Chain), each resolving to the address shown; the address stays the thing to read.
  The site says the same. The two addresses are now the wallets those names resolve to:
  Solana `2pSgpgA6TqdynuAdVpFEZbyVRrKi5oTyvxGL9gjKEYRX`, EVM `0x036CC610fb2883DB9504dD172FA94fEe89900000`;
  the previous `Gi2z…KEYRX` and `0x34F0…00000` are retired, so a name and the address under it
  pay the same wallet.
- The GitHub Release carries the provenance statement a second way: `keyrx-<version>.crate.intoto.jsonl`,
  the in-toto statement and its signature (the DSSE envelope) taken out of the Sigstore bundle, under the
  name SLSA tooling reads. It claims nothing new; the bundle (`.sigstore.json`) is still the file to
  verify with, since it also carries the signing certificate and the transparency-log entry. No change
  to the tool.

## 0.4.7 - 2026-08-21

- Every GitHub Release now carries the `.crate` packaged from the tag, its Sigstore provenance
  bundle (`keyrx-<version>.crate.sigstore.json`; check with `gh attestation verify keyrx-<version>.crate
  --owner keyrx`) and the CycloneDX SBOM. Robinhood Chain is named among the EVM chains on the start
  screen, in `--help`, the README and the site (the same address works there; `keyrx networks` has
  its values). No change to grinding, matching or files.

## 0.4.6 - 2026-08-21

- `keyrx networks`: the first framed row read "network nameRobinhood Chain" - a key one character
  wider than the key column ran into its value. The key is `name`; the bare line below the frame
  still says "network name". Nothing else changes.

## 0.4.5 - 2026-08-21

- `keyrx networks`: the add-a-network steps for MetaMask and Rabby, and the five values a wallet's
  form asks for, for EVM chains it does not list by default - framed for reading, then each value
  bare on its own line for pasting (the rule the keys follow). First entry: Robinhood Chain
  (Ethereum L2, mainnet), RPC `https://rpc.mainnet.chain.robinhood.com`, chain ID 4663, ETH,
  Blockscout explorer; the chain id was checked against that RPC on 2026-08-21, and a test pins
  the table. The EVM panel, COMMANDS and A TYPICAL SESSION point at it; the site's EVM section
  carries the same block with click/tap-to-copy on each value.

## 0.4.4 - 2026-08-21

- Import steps said plainly, on both chains: a fresh Phantom or MetaMask insists on a seed phrase
  first and only then offers a private-key import, so every place that says "import the key" now
  says "a wallet must exist first (any seed; it never sees this key), then the key import ADDS an
  account"; and the seed route says "import THIS seed as the wallet, then 'add account' N times:
  account N+1 is the one". MATCH panel, import hints, the EVM panel, THE 128, RECIPES, README and
  the site's WALLETS and EVM sections. No functional change.

## 0.4.3 - 2026-08-21

- A TYPICAL SESSION: every row is one line again. The `--checksum` example was the one command
  too long for the column and wrapped into a two-line row among one-line rows; it is gone from
  this panel (RECIPES carries the full `--checksum` command, and the EVM panel explains the flag).
  No functional change.

## 0.4.2 - 2026-08-21

- DONATE shows the EVM address: `0x34F08966E43Fb58C5112ae6dB8BbadC2bae00000`, one address for every EVM chain, ground with
  `--chain evm` (a five-zero suffix, EIP-55 case as printed). The same string is in the site's DONATE
  panel with click-to-copy. Nothing else changes.

## 0.4.1 - 2026-08-21

- The full EVM pass on the start screen: COMMANDS names both chains and the per-chain `bench`;
  THE 128 says what a branch costs on secp256k1 and why `--indices` buys less there; WHAT A MATCH
  WRITES carries the EVM four-line block as rows; RECIPES gains EVM (key import) and EVM EIP-55
  (`--checksum`); A TYPICAL SESSION gains `bench --chain evm` and `show evm/dead --keys`; `verify`
  and `show` help texts name both chains; `estimate --chain evm` without a bench says what its model
  is anchored to. DONATE gains an EVM address slot, empty until the ground wallet is set and shown
  only then; the ask reads "a Sol or two, or some ETH". No change to grinding, matching, or files.
- keyrx.tech: F8 is EVM (GitHub and X move to F9 and F10), with an EVM section carrying the session
  commands, the measured numbers and the verify line; THE 128 and WHAT A MATCH WRITES carry the EVM
  lines; DONATE has the same slot with click-to-copy for either address.

## 0.4.0 - 2026-08-20

- **`--chain evm`**: Ethereum and every EVM chain (Base, Arbitrum, Optimism, Polygon, BNB, Avalanche
  C-Chain: one key, all of them). The same idea as the Solana path, on secp256k1: one mnemonic pays
  PBKDF2 once, then the BIP44 tree `m/44'/60'/0'/0/N` is walked at one HMAC-SHA512 plus one scalar
  multiplication per candidate; the address is the last twenty bytes of keccak-256 over the public
  key, written in EIP-55 case. `estimate`, `grind` and `bench` take `--chain evm`; `bench --chain evm`
  measures its own rate and `estimate` reads it (a separate file, `bench-evm.txt`, because the two
  loops cost nothing alike). Measured on the development machine: 11,900 candidates/sec per thread at
  64 indices, about two thirds of the Ed25519 rate; a six-hex-digit suffix is under a minute on a
  desktop, eight is hours.
- EVM patterns are hex (`0-9 a-f`), matched in **any case by default**, because hex has no case of
  its own; `0x` is allowed in front of a prefix. **`--checksum`** asks for more: the letters must also
  come out in EIP-55 case exactly as typed, a coin flip per letter, and `estimate` prints both
  numbers (`--checksum` and `--ignore-case` together is refused; `--checksum` without `--chain evm`
  is refused).
- An EVM match writes four lines under `matches/evm/<pattern>.txt` (Solana files stay exactly where
  they were): `address` in EIP-55 case, `path m/44'/60'/0'/0/N`, `seed`, and `privkey` as the `0x`
  hex every EVM wallet imports (MetaMask and Rabby: Import account → Private key; or the seed, then
  "add account" N times). `keyrx show` lists them as `evm/<pattern>`; `keyrx show evm/dead --keys`
  reads one. `--passphrase`, `--count`, `--out`, `--words` work the same on both chains; `--path` is
  Solana-only (EVM has the one path).
- `keyrx verify` gained **SELF-TEST · EVM**: the "abandon … about" mnemonic's published first
  account and key; this tool's own public test seed at four indices against an independent
  implementation (node crypto + noble, a different language and libraries); a passphrase case; the
  four EIP-55 specification examples; private key 1; and the hot loop's walk against the straight
  derivation. The manual cross-check panel adds the EVM line (`cast wallet address --mnemonic …
  --mnemonic-index 0`, or a throwaway MetaMask). Two new crates, `k256` and `sha3`; no network,
  no service, nothing else changes.
- The start screen gained an EVM panel and three session rows; the mark's line reads "Solana and
  EVM vanity address grinder."

## 0.3.4 - 2026-08-20

- Release hygiene, no change to the binary: from this release on, publishing yanks the release
  before it (and anything listed in `ops/yank.txt`: 0.3.0, 0.3.1, 0.3.2 go with this one), so a
  fresh `cargo install keyrx` can only land on the newest. A yank never deletes a version or breaks
  an existing install or lockfile; it only stops new installs of a superseded one. If you pinned an
  old version on purpose, `keyrx --update` brings you forward.

## 0.3.3 - 2026-08-19

- A TYPICAL SESSION: every row is one line again, command column then note, with at least one column of
  air before the border (indent 2, gutter 3). The three notes that were trimmed to fit say what they
  meant. No functional change.

## 0.3.2 - 2026-08-19

- A TYPICAL SESSION: three notes were a character or two past the frame and clipped (the room
  check counted the gutter wrong). Every note now ends inside the border. No functional change.

## 0.3.1 - 2026-08-19

- The start screen's A TYPICAL SESSION panel now shows the variations, each with a one-line note:
  verify · bench · `estimate --count 10` · grind · `--count 10` · `--indices 8` for Phantom ·
  `--passphrase` · `--starts-with Key --ends-with RX` · `--ignore-case` · `show` · `show --keys` ·
  `--update`. The site's INSTALL panel gained the `--passphrase` line. No functional change.

## 0.3.0 - 2026-08-19

- `grind --passphrase` - a BIP39 passphrase (the "25th word"). Prompted on the terminal, hidden, typed
  twice; never read from a flag, a file or the environment; never stored, never printed. The grind
  derives every candidate from `PBKDF2(mnemonic, "mnemonic" + passphrase)`, exactly as every wallet
  that takes one does. The match file gains one line under the seed - `passphrase used - NOT stored:
  the seed alone will not reach this address; the keys will` - the fact, never the passphrase; `show`
  marks such matches; the MATCH panel and the GRIND panel say so. Most browser wallets have no
  passphrase field on seed import: import the KEY, which is standalone.
- `keyrx verify` now also checks the passphrase path against the BIP39 specification's first test
  vector ("abandon … about" + "TREZOR" → the published seed), pinned; and the manual cross-check note
  says what to type at solana-keygen's prompt for a passphrase grind.
- Minor version bump because the match file format gained a line (older `show` ignores it).

## 0.2.13 - 2026-08-19

- `keyrx estimate --count N` - when you intend to grind N matches, the ODDS panel adds "time to all
  N matches": 50% / 90% / mean, each match an independent wait, so the mean is exactly N times the
  first match's and the spread narrows as N grows (Gamma quantiles, Wilson-Hilferty). The start
  screen's `--count N` entry says so and says all N land in the one file. The site's INSTALL panel
  shows `keyrx grind --ends-with KEYRX --count 10  # ten of them, one file`.

## 0.2.12 - 2026-08-19

- `keyrx --update` - the install line, `cargo install keyrx && clear && keyrx`, as one flag. It finds
  cargo ($CARGO, PATH, $CARGO_HOME/bin, ~/.cargo/bin), runs `cargo install keyrx` with cargo's own
  output on screen ("already installed" means you have the latest), then clears the screen and starts
  the freshly installed keyrx, so the first thing you see is the new start screen with the new version
  on it. Without cargo it prints the rustup line and the install line and exits 1. Listed in the
  COMMANDS panel and on the site's INSTALL panel.
- The site's masthead version is one constant, and a cargo test pins it to Cargo.toml: a release can
  no longer publish with keyrx.tech a version behind (0.2.10 did, for an hour).

## 0.2.11 - 2026-08-19

- One grey line says how the links work - `ctrl/cmd-click a path to open the folder` - in the GRIND
  panel, the MATCH panel, `show`'s MATCH FILES and the start screen's `file` line. Terminals differ on
  the modifier (Windows Terminal, VS Code, GNOME, Konsole: ctrl · iTerm2 and VS Code on a Mac: cmd ·
  kitty, WezTerm: a plain click), so it names both. Printed only when links are being emitted - a
  terminal without `NO_COLOR` - so piped output never mentions clicking.

## 0.2.10 - 2026-08-19

- The matches folder is clickable. Wherever a panel prints it - the GRIND foot (`in …/keyrx/matches`),
  the `matches ->` line, the MATCH panel's seed/keys lines, `show`'s MATCH FILES title, the start
  screen's `file` line - the path is a terminal hyperlink that opens the folder in your file manager
  (Windows Terminal, VS Code, iTerm2, GNOME, kitty, WezTerm, foot, Konsole). Under WSL the link is the
  `\\wsl.localhost\<distro>\…` form Windows can open. A click opens the FOLDER, never the match
  file: seeds are read with `show --keys`, on purpose. Piped output and `NO_COLOR` carry no escapes,
  as before. Width measurement now understands OSC sequences, so a link can never widen a frame.

## 0.2.9 - 2026-08-19

- Every example pattern is now `KEYRX` (and `Key` for a prefix). The old example, `MINT`, contains an
  `I`, which base58 does not have - so the very command the start screen suggested could never be
  ground. The tool refused it correctly; the examples did not. Odds in the ignore-case note updated
  for five letters (1 in 656M → 1 in 20.5M, 32x). No functional change.

## 0.2.8 - 2026-08-19

- The masthead title reads `keyRX | CLI`. No functional change.

## 0.2.7 - 2026-08-18

- The masthead's bottom line: keyRX.tech at the text column, dev@keyrx.tech at the right edge -
  start screen, `--help`, and the site. No functional change.

## 0.2.6 - 2026-08-18

- The one line now sits beside the seal on the start screen and above `--help`, and on the site's
  masthead. No functional change.

## 0.2.5 - 2026-08-18

- One line, everywhere: the crate description, `--help`, the README tagline, the site's description
  and llms.txt now read the same sentence. No functional change.

## 0.2.4 - 2026-08-18

- The terminal mark at its true shape: sixteen columns by eight lines of full blocks (a text cell
  is about twice as tall as it is wide, so the half-block version was twice as wide as the mark).
  Same on the site's masthead. No functional change.

## 0.2.3 - 2026-08-18

- Captions and file comments around the mark trimmed. No functional change.

## 0.2.2 - 2026-08-18

- The mark. keyRX now carries one mark everywhere: a seal - sixty-four hex digits of a hash on an
  8x8 grid, a cell lit where the digit is 8 or above. In the terminal it is four lines of
  half-blocks above the start screen and `--help`, coloured only on a TTY (`NO_COLOR` respected);
  in the repository it is `assets/logo.svg` (source, generated by `assets/make_mark.py`) and every
  raster cut from it; on keyrx.tech it is the masthead, the favicon and the OG image. Retired: the
  capsule.
- Site: the masthead seal (desktop), the embedded font subset gains the two half-block glyphs it
  needed (5.2 KB, same tables), banner and OG regenerated by `assets/render_banner.cjs`.
- No change to grinding, matching, files or flags.

## 0.2.1 - 2026-08-18

- Declares its minimum Rust: `rust-version = "1.85"` - the floor set by the dependencies
  (clap 4.6, base64ct, zeroize), and proven by building and running the tests on 1.85.0.
  One call that needed 1.87 (`is_multiple_of`) was rewritten as plain arithmetic.
- README: the banner, one comment column in the install and command block, and the
  install line says which Rust it needs.

## 0.2.0 - 2026-08-17

- First release on crates.io: `cargo install keyrx`.
- The crate carries the CLI and nothing else - source, manifests, README, LICENSE,
  TRADEMARK (the mark and the assets are not part of the MIT grant).
- Everything the site describes: `verify`, `bench`, `estimate`, `grind` (`--ends-with`,
  `--starts-with`, `--ignore-case`, `--words`, `--indices`), `show`, `donate`; matches
  written once, mode 0600, both key encodings; the start screen with recipes.
