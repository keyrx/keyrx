# Changelog

All notable changes to keyRX, newest first. Versions are the ones on crates.io.

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
