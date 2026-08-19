# Changelog

All notable changes to keyRX, newest first. Versions are the ones on crates.io.

## 0.3.2 — 2026-08-19

- A TYPICAL SESSION: three notes were a character or two past the frame and clipped (the room
  check counted the gutter wrong). Every note now ends inside the border. No functional change.

## 0.3.1 — 2026-08-19

- The start screen's A TYPICAL SESSION panel now shows the variations, each with a one-line note:
  verify · bench · `estimate --count 10` · grind · `--count 10` · `--indices 8` for Phantom ·
  `--passphrase` · `--starts-with Key --ends-with RX` · `--ignore-case` · `show` · `show --keys` ·
  `--update`. The site's INSTALL panel gained the `--passphrase` line. No functional change.

## 0.3.0 — 2026-08-19

- `grind --passphrase` — a BIP39 passphrase (the "25th word"). Prompted on the terminal, hidden, typed
  twice; never read from a flag, a file or the environment; never stored, never printed. The grind
  derives every candidate from `PBKDF2(mnemonic, "mnemonic" + passphrase)`, exactly as every wallet
  that takes one does. The match file gains one line under the seed — `passphrase used - NOT stored:
  the seed alone will not reach this address; the keys will` — the fact, never the passphrase; `show`
  marks such matches; the MATCH panel and the GRIND panel say so. Most browser wallets have no
  passphrase field on seed import: import the KEY, which is standalone.
- `keyrx verify` now also checks the passphrase path against the BIP39 specification's first test
  vector ("abandon … about" + "TREZOR" → the published seed), pinned; and the manual cross-check note
  says what to type at solana-keygen's prompt for a passphrase grind.
- Minor version bump because the match file format gained a line (older `show` ignores it).

## 0.2.13 — 2026-08-19

- `keyrx estimate --count N` — when you intend to grind N matches, the ODDS panel adds "time to all
  N matches": 50% / 90% / mean, each match an independent wait, so the mean is exactly N times the
  first match's and the spread narrows as N grows (Gamma quantiles, Wilson–Hilferty). The start
  screen's `--count N` entry says so and says all N land in the one file. The site's INSTALL panel
  shows `keyrx grind --ends-with KEYRX --count 10  # ten of them, one file`.

## 0.2.12 — 2026-08-19

- `keyrx --update` — the install line, `cargo install keyrx && clear && keyrx`, as one flag. It finds
  cargo ($CARGO, PATH, $CARGO_HOME/bin, ~/.cargo/bin), runs `cargo install keyrx` with cargo's own
  output on screen ("already installed" means you have the latest), then clears the screen and starts
  the freshly installed keyrx, so the first thing you see is the new start screen with the new version
  on it. Without cargo it prints the rustup line and the install line and exits 1. Listed in the
  COMMANDS panel and on the site's INSTALL panel.
- The site's masthead version is one constant, and a cargo test pins it to Cargo.toml: a release can
  no longer publish with keyrx.tech a version behind (0.2.10 did, for an hour).

## 0.2.11 — 2026-08-19

- One grey line says how the links work — `ctrl/cmd-click a path to open the folder` — in the GRIND
  panel, the MATCH panel, `show`'s MATCH FILES and the start screen's `file` line. Terminals differ on
  the modifier (Windows Terminal, VS Code, GNOME, Konsole: ctrl · iTerm2 and VS Code on a Mac: cmd ·
  kitty, WezTerm: a plain click), so it names both. Printed only when links are being emitted - a
  terminal without `NO_COLOR` - so piped output never mentions clicking.

## 0.2.10 — 2026-08-19

- The matches folder is clickable. Wherever a panel prints it — the GRIND foot (`in …/keyrx/matches`),
  the `matches ->` line, the MATCH panel's seed/keys lines, `show`'s MATCH FILES title, the start
  screen's `file` line — the path is a terminal hyperlink that opens the folder in your file manager
  (Windows Terminal, VS Code, iTerm2, GNOME, kitty, WezTerm, foot, Konsole). Under WSL the link is the
  `\\wsl.localhost\<distro>\…` form Windows can open. A click opens the FOLDER, never the match
  file: seeds are read with `show --keys`, on purpose. Piped output and `NO_COLOR` carry no escapes,
  as before. Width measurement now understands OSC sequences, so a link can never widen a frame.

## 0.2.9 — 2026-08-19

- Every example pattern is now `KEYRX` (and `Key` for a prefix). The old example, `MINT`, contains an
  `I`, which base58 does not have — so the very command the start screen suggested could never be
  ground. The tool refused it correctly; the examples did not. Odds in the ignore-case note updated
  for five letters (1 in 656M → 1 in 20.5M, 32x). No functional change.

## 0.2.8 — 2026-08-19

- The masthead title reads `keyRX | CLI`. No functional change.

## 0.2.7 — 2026-08-18

- The masthead's bottom line: keyRX.tech at the text column, dev@keyrx.tech at the right edge —
  start screen, `--help`, and the site. No functional change.

## 0.2.6 — 2026-08-18

- The one line now sits beside the seal on the start screen and above `--help`, and on the site's
  masthead. No functional change.

## 0.2.5 — 2026-08-18

- One line, everywhere: the crate description, `--help`, the README tagline, the site's description
  and llms.txt now read the same sentence. No functional change.

## 0.2.4 — 2026-08-18

- The terminal mark at its true shape: sixteen columns by eight lines of full blocks (a text cell
  is about twice as tall as it is wide, so the half-block version was twice as wide as the mark).
  Same on the site's masthead. No functional change.

## 0.2.3 — 2026-08-18

- Captions and file comments around the mark trimmed. No functional change.

## 0.2.2 — 2026-08-18

- The mark. keyRX now carries one mark everywhere: a seal — sixty-four hex digits of a hash on an
  8x8 grid, a cell lit where the digit is 8 or above. In the terminal it is four lines of
  half-blocks above the start screen and `--help`, coloured only on a TTY (`NO_COLOR` respected);
  in the repository it is `assets/logo.svg` (source, generated by `assets/make_mark.py`) and every
  raster cut from it; on keyrx.tech it is the masthead, the favicon and the OG image. Retired: the
  capsule.
- Site: the masthead seal (desktop), the embedded font subset gains the two half-block glyphs it
  needed (5.2 KB, same tables), banner and OG regenerated by `assets/render_banner.cjs`.
- No change to grinding, matching, files or flags.

## 0.2.1 — 2026-08-18

- Declares its minimum Rust: `rust-version = "1.85"` — the floor set by the dependencies
  (clap 4.6, base64ct, zeroize), and proven by building and running the tests on 1.85.0.
  One call that needed 1.87 (`is_multiple_of`) was rewritten as plain arithmetic.
- README: the banner, one comment column in the install and command block, and the
  install line says which Rust it needs.

## 0.2.0 — 2026-08-17

- First release on crates.io: `cargo install keyrx`.
- The crate carries the CLI and nothing else — source, manifests, README, LICENSE,
  TRADEMARK (the mark and the assets are not part of the MIT grant).
- Everything the site describes: `verify`, `bench`, `estimate`, `grind` (`--ends-with`,
  `--starts-with`, `--ignore-case`, `--words`, `--indices`), `show`, `donate`; matches
  written once, mode 0600, both key encodings; the start screen with recipes.
