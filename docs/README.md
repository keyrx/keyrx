# keyRX documentation

The documentation for keyRX lives in three places, all kept in step with the code:

- **Install:** `cargo install --locked keyrx`, then `keyrx`; Rust 1.85 or newer; or from a
  clone with `cargo install --locked --path .`. See the README section [Install](../README.md) and
  <https://keyrx.tech> (F3, INSTALL).
- **Start:** `keyrx` with no arguments prints the start screen, which explains every command and
  every flag in place: WHAT THIS IS, COMMANDS, PATTERN FLAGS, EVM, GRIND FLAGS, THE 128, WHAT A
  MATCH WRITES, RECIPES, A TYPICAL SESSION. `keyrx <command> --help` for any one of them.
- **Use:** the README sections *Which wallet, which flags*, *EVM (`--chain evm`)*, *Where
  matches go*; the RECIPES and A TYPICAL SESSION panels; the site's WALLETS (F5) and EVM (F8)
  sections, which carry the same commands with click-to-copy; `keyrx networks` for adding an EVM
  network to a wallet.
- **Use securely:** `keyrx verify` first, on your own machine; every match record holds seed and
  keys (mode 0600, inside an owner-only managed directory); nothing is printed unless you ask (`--show-seed`,
  `show --seeds`, `show --keys`); import and verify the address before funding it; what the tool
  never does and how a release is checked are in [SECURITY.md](../SECURITY.md); how to contribute
  in [CONTRIBUTING.md](../CONTRIBUTING.md).
- **Reference:** the default format (one self-contained, versioned Markdown record per successful
  hit, with uppercase field headings and each exact value below its heading), the actual-case names
  (`coined.ic.coiNED.md`, then `.02.md`, `.03.md` without overwrite), the explicit `--out FILE`
  append-ledger format retained for earlier `.txt` files, the exact copy-ready `keyrx show` command
  printed for each new default record, `keyrx show` support for both formats, the paths
  (`m/44'/501'/N'/0'`, `m/44'/501'/N'`, `m/44'/60'/0'/0/N`), the pattern alphabets (base58 without
  0 O I l; hex 0-9 a-f), and every flag, in the README and the start screen. The changelog is
  [CHANGELOG.md](../CHANGELOG.md).
