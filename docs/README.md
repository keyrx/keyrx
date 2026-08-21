# keyRX documentation

The documentation for keyRX lives in three places, all kept in step with the code:

- **Install:** one line, `cargo install keyrx && clear && keyrx`; Rust 1.85 or newer; or from a
  clone with `cargo install --path .`. See the README section [Install](../README.md) and
  <https://keyrx.tech> (F3, INSTALL).
- **Start:** `keyrx` with no arguments prints the start screen, which explains every command and
  every flag in place: WHAT THIS IS, COMMANDS, PATTERN FLAGS, EVM, GRIND FLAGS, THE 128, WHAT A
  MATCH WRITES, RECIPES, A TYPICAL SESSION. `keyrx <command> --help` for any one of them.
- **Use:** the README sections *Which wallet, which flags*, *EVM (`--chain evm`)*, *Where
  matches go*; the RECIPES and A TYPICAL SESSION panels; the site's WALLETS (F5) and EVM (F8)
  sections, which carry the same commands with click-to-copy; `keyrx networks` for adding an EVM
  network to a wallet.
- **Use securely:** `keyrx verify` first, on your own machine; the match file holds seed and keys
  (mode 0600, in a directory of its own); nothing is printed unless you ask (`--show-seed`,
  `show --seeds`, `show --keys`); import and verify the address before funding it; what the tool
  never does and how a release is checked are in [SECURITY.md](../SECURITY.md); how to contribute
  in [CONTRIBUTING.md](../CONTRIBUTING.md).
- **Reference:** the match file format (five lines, four on EVM), the derivation paths
  (`m/44'/501'/N'/0'`, `m/44'/501'/N'`, `m/44'/60'/0'/0/N`), the pattern alphabets (base58 without
  0 O I l; hex 0-9 a-f), and every flag, in the README and the start screen. The changelog is
  [CHANGELOG.md](../CHANGELOG.md).
