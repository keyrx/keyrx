// keyRX -- Solana and EVM vanity address grinder
//
// Standalone terminal tool. No daemon, no service, no network.
//
// Why it's fast: `solana-keygen grind --use-mnemonic` generates a fresh
// mnemonic per candidate, paying 2048 rounds of PBKDF2-HMAC-SHA512 (~1.2ms)
// to test ONE address. This generates one mnemonic, derives to m/44'/501'
// once (that prefix is constant across all indices), then walks the account
// index. Each extra candidate costs 2 HMAC-SHA512 ops plus one Ed25519
// scalar mult -- about 21us.
//
// Second trick: suffix matching only needs the last N base58 characters.
// Base58 emits trailing chars first (repeated `% 58`), so N divmods instead
// of the full ~44.
//
// What a match gives you: the address, its path in the seed's tree, the seed
// phrase (restores the whole tree), AND the keypair in both wallet-import
// forms -- base58 for Phantom's "Import Private Key", the JSON byte array for
// Solflare and solana-keygen. A key import lands on the exact address in one
// paste, standalone; the account index only matters if you import the SEED
// (Phantom walks indices with "add account", Solflare takes the path).
//
//   keyrx                                  <- start screen: everything explained
//   keyrx verify                           <- run this first, always
//   keyrx bench --indices 128
//   keyrx estimate --ends-with KEYRX
//   keyrx grind --ends-with KEYRX --indices 128
//   keyrx show KEYRX --keys

mod evm;
mod ui;

use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x8000_0000;
/// The donation address. ONE place - the CLI panel reads it, and the site
/// carries the same string in its own DONATE_SOL const; change both
/// together. Set once the keyRX vanity grind lands; until then the panel
/// says so rather than showing an address that is not ours.
const DONATE_SOL: &str = "2pSgpgA6TqdynuAdVpFEZbyVRrKi5oTyvxGL9gjKEYRX";
/// The EVM donation address - one address for every EVM chain - ground with this tool's
/// `--chain evm`. Same rule as DONATE_SOL: ONE place here, the same string in the site's
/// DONATE_EVM const, change both together. Empty until it is set; the panel then shows
/// the Solana address alone rather than a placeholder.
const DONATE_EVM: &str = "0x036CC610fb2883DB9504dD172FA94fEe89900000";

/// An EVM network a wallet does not list by default, with the five values its "add a
/// network" form asks for. Printed by `keyrx networks` - framed for reading, then bare,
/// one value per line, for pasting. Every value here was checked against the live RPC
/// (eth_chainId) on the date given; a wrong chain id would send a reader's transactions
/// to the wrong place, so nothing in this table is guessed.
struct Network {
    name: &'static str,
    what: &'static str,
    rpc: &'static str,
    chain_id: u64,
    symbol: &'static str,
    explorer: &'static str,
    explorer_note: &'static str,
    checked: &'static str,
}
const NETWORKS: &[Network] = &[Network {
    name: "Robinhood Chain",
    what: "Ethereum L2 (Arbitrum stack), mainnet",
    rpc: "https://rpc.mainnet.chain.robinhood.com",
    chain_id: 4663,
    symbol: "ETH",
    explorer: "https://explorer.mainnet.chain.robinhood.com",
    explorer_note: "Blockscout",
    checked: "2026-08-21",
}];
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ---------------------------------------------------------------- CLI

/// The mark above `--help` (see ui::SEAL), plain when piped.
fn help_seal() -> String {
    let l = ui::seal_lines();
    let mut out = format!(" {}  keyRX | CLI", l[0]);
    for (i, line) in l.iter().enumerate().skip(1) {
        let t = match i { 1 => ui::ABOUT[0].to_string(), 2 => ui::ABOUT[1].to_string(), 3 => ui::ABOUT[2].to_string(), 5 => ui::ABOUT[3].to_string(), 7 => format!("{}  ·  {}", ui::SITE, ui::CONTACT), _ => String::new() };
        out.push_str(&format!("\n {}{}{}", line, if t.is_empty() { "" } else { "  " }, t));
    }
    out
}

#[derive(Parser)]
#[command(name = "keyrx", version, about = "The keyRX CLI: Solana and EVM BIP39 vanity address grinder", before_help = help_seal())]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Update: `cargo install keyrx`, then clear, then keyrx - the install line as one flag.
    #[arg(long)]
    update: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Self-test: base58, both derivations (Solana SLIP-0010, EVM BIP32/keccak/EIP-55)
    /// against pinned answers. Run before trusting a result.
    Verify,

    /// Show expected time for a pattern without grinding.
    Estimate {
        #[command(flatten)]
        pattern: PatternArgs,
        #[arg(long, default_value_t = num_threads())]
        threads: usize,
        #[arg(long, default_value_t = 64)]
        indices: u32,
        /// How many matches you intend to grind (`grind --count N`): adds the time to all N.
        #[arg(long, default_value_t = 1)]
        count: usize,
    },

    /// Measure actual throughput on this machine.
    Bench {
        /// Which loop to measure: sol (Ed25519) or evm (secp256k1). Saved per chain.
        #[arg(long, value_enum, default_value_t = Chain::Sol)]
        chain: Chain,
        #[arg(long, default_value_t = num_threads())]
        threads: usize,
        #[arg(long, default_value_t = 64)]
        indices: u32,
        #[arg(long, default_value_t = 15)]
        seconds: u64,
    },

    /// Optional, and it changes nothing: MIT, no paid tier, nothing gated.
    Donate,

    /// EVM networks a wallet does not list by default (Robinhood Chain): the add-a-network
    /// steps for MetaMask/Rabby and the five values, printed bare for pasting.
    Networks,

    /// List matches - addresses and paths; seeds and keys withheld by default.
    /// With no FILE, lists every match file in the matches directory (EVM files as evm/NAME).
    Show {
        /// A match file, or a bare pattern name (KEYRX -> matches/KEYRX.txt; evm/dead -> matches/evm/dead.txt).
        file: Option<String>,
        /// Also print the seed phrases. Off by default.
        #[arg(long)]
        seeds: bool,
        /// Also print the private keys (Phantom "Import Private Key"; MetaMask/Rabby "Import account"). Off by default.
        #[arg(long)]
        keys: bool,
    },

    /// Grind for real.
    Grind {
        #[command(flatten)]
        pattern: PatternArgs,
        #[arg(long, default_value_t = num_threads())]
        threads: usize,
        /// Account indices tried per mnemonic. Higher = faster, but the match
        /// lands at a higher account index. Phantom does NOT take a path - it
        /// reaches account N by N 'add account' clicks - so use 8 for Phantom.
        /// Solflare takes a custom path: use 128. (See the start screen.)
        #[arg(long, default_value_t = 64)]
        indices: u32,
        /// Stop after this many matches.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Mnemonic length: 12 or 24. Default 12 - what Phantom generates and
        /// what most people are used to; every major wallet imports either.
        #[arg(long, default_value_t = 12)]
        words: usize,
        /// Output file for matches (created mode 0600). Default: a file named
        /// after the pattern in the matches directory - KEYRX -> .../matches/KEYRX.txt
        #[arg(long)]
        out: Option<String>,
        /// Also print the seed phrase to stdout. Off by default so seeds stay
        /// out of scrollback, tmux buffers, and anything reading your terminal.
        #[arg(long)]
        show_seed: bool,
        /// Use a BIP39 passphrase (the "25th word"). Prompted, hidden, typed twice;
        /// never stored, never printed. The seed alone will then NOT reach the
        /// address - the keys in the match file will. Most browser wallets have no
        /// passphrase field on seed import: import the KEY.
        #[arg(long)]
        passphrase: bool,
    },
}

#[derive(Args, Clone)]
struct PatternArgs {
    /// Suffix to match. Repeatable.
    #[arg(long = "ends-with")]
    ends_with: Vec<String>,
    /// Prefix to match. Repeatable. Costs more than a suffix.
    #[arg(long = "starts-with")]
    starts_with: Vec<String>,
    /// Case-insensitive matching. Roughly 2^letters more likely: KEYRX goes from
    /// 1 in 11.3M to 1 in 707K.
    #[arg(long)]
    ignore_case: bool,
    /// Derivation path style. phantom = m/44'/501'/N'/0' (Phantom, Solflare
    /// default); legacy = m/44'/501'/N' (Solflare custom). Pick the wallet you
    /// will import into. Solana only: EVM is always m/44'/60'/0'/0/N.
    #[arg(long, value_enum, default_value_t = PathStyle::Phantom)]
    path: PathStyle,
    /// Which chain's addresses. sol: Solana, base58, Ed25519 at m/44'/501'.
    /// evm: Ethereum and every EVM chain (Base, Arbitrum, Optimism, Polygon,
    /// BNB, Robinhood Chain...), hex, secp256k1 at m/44'/60'/0'/0/N - one key,
    /// every one of them.
    #[arg(long, value_enum, default_value_t = Chain::Sol)]
    chain: Chain,
    /// EVM only: the letters a-f in your pattern must ALSO match the address's
    /// EIP-55 checksum casing as typed. Hex has no case of its own, so without
    /// this a pattern matches any case; with it each letter halves the odds.
    #[arg(long)]
    checksum: bool,
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Debug)]
enum Chain {
    /// Solana: base58 address, Ed25519, SLIP-0010 at m/44'/501'/N'/0'
    Sol,
    /// Ethereum and every EVM chain: hex address, secp256k1, BIP44 m/44'/60'/0'/0/N
    Evm,
}

#[derive(Copy, Clone, ValueEnum, PartialEq)]
enum PathStyle {
    /// m/44'/501'/N'/0'  -- Phantom, Solflare default
    Phantom,
    /// m/44'/501'/N'     -- Solflare legacy
    Legacy,
}

fn num_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8)
}

// ---------------------------------------------------------------- crypto

fn master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(seed);
    split(mac.finalize().into_bytes().as_slice())
}

/// SLIP-0010 hardened derivation. Ed25519 supports hardened only.
/// data = 0x00 || parent_key || ser32(index | 0x80000000)
fn derive_hardened(key: &[u8; 32], chain: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(chain).unwrap();
    mac.update(&[0u8]);
    mac.update(key);
    mac.update(&(index | HARDENED).to_be_bytes());
    split(mac.finalize().into_bytes().as_slice())
}

#[inline]
fn split(out: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    c.copy_from_slice(&out[32..]);
    (k, c)
}

/// Last `n` base58 characters only. Leading zero bytes become leading '1's,
/// which only affect the front of the string -- irrelevant for suffixes.
#[inline]
fn b58_suffix(pubkey: &[u8; 32], n: usize, out: &mut [u8]) {
    let mut num = *pubkey;
    for i in 0..n {
        let mut rem: u32 = 0;
        for byte in num.iter_mut() {
            let cur = (rem << 8) | (*byte as u32);
            *byte = (cur / 58) as u8;
            rem = cur % 58;
        }
        out[n - 1 - i] = B58[rem as usize];
    }
}

// ---------------------------------------------------------------- matching

struct Matcher {
    chain: Chain,
    suffixes: Vec<Vec<u8>>,
    prefixes: Vec<Vec<u8>>,
    ignore_case: bool,
    /// EVM: the typed case of a-f must match EIP-55 casing. Off: hex is matched in any case.
    checksum: bool,
    max_suffix: usize,
    needs_full: bool,
}

impl Matcher {
    fn new(p: &PatternArgs) -> Result<Self, String> {
        if p.ends_with.is_empty() && p.starts_with.is_empty() {
            return Err("need at least one --ends-with or --starts-with".into());
        }
        if p.chain == Chain::Evm { return Self::new_evm(p); }
        if p.checksum { return Err("--checksum is EIP-55, an EVM thing - add --chain evm".into()); }
        let check = |s: &String| -> Result<Vec<u8>, String> {
            if s.is_empty() {
                return Err("empty pattern".into());
            }
            for c in s.bytes() {
                if !B58.contains(&c) {
                    return Err(format!("'{}' is not base58 (0 O I l are excluded)", c as char));
                }
            }
            Ok(s.clone().into_bytes())
        };
        let suffixes: Vec<_> = p.ends_with.iter().map(check).collect::<Result<_, _>>()?;
        let prefixes: Vec<_> = p.starts_with.iter().map(check).collect::<Result<_, _>>()?;
        let max_suffix = suffixes.iter().map(|s| s.len()).max().unwrap_or(0);
        if max_suffix > 16 {
            return Err("suffix longer than 16 chars".into());
        }
        Ok(Matcher {
            chain: Chain::Sol,
            needs_full: !prefixes.is_empty(),
            max_suffix,
            suffixes,
            prefixes,
            ignore_case: p.ignore_case,
            checksum: false,
        })
    }

    /// EVM patterns: hex digits, `0x` allowed only at the front of a prefix. Stored
    /// lowercase unless --checksum, when the typed case is the thing being asked for.
    fn new_evm(p: &PatternArgs) -> Result<Self, String> {
        if p.checksum && p.ignore_case {
            return Err("--checksum binds the typed case to EIP-55; --ignore-case frees it - pick one".into());
        }
        let keep = p.checksum;
        let check = |s: &String, is_prefix: bool| -> Result<Vec<u8>, String> {
            let body = evm::check_pattern(s, is_prefix)?;
            if body.len() > 40 { return Err("longer than an address (40 hex digits)".into()); }
            Ok(if keep { body.into_bytes() } else { body.to_ascii_lowercase().into_bytes() })
        };
        let suffixes: Vec<_> = p.ends_with.iter().map(|s| check(s, false)).collect::<Result<_, _>>()?;
        let prefixes: Vec<_> = p.starts_with.iter().map(|s| check(s, true)).collect::<Result<_, _>>()?;
        let max_suffix = suffixes.iter().map(|s| s.len()).max().unwrap_or(0);
        if max_suffix > 16 {
            return Err("suffix longer than 16 chars".into());
        }
        Ok(Matcher {
            chain: Chain::Evm,
            needs_full: !prefixes.is_empty(),
            max_suffix,
            suffixes,
            prefixes,
            ignore_case: !p.checksum,
            checksum: p.checksum,
        })
    }

    #[inline]
    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.ignore_case { a.eq_ignore_ascii_case(b) } else { a == b }
    }

    /// EVM: does this address match? `lower` is its forty lowercase hex digits. The
    /// any-case test is the cheap one and runs first; only a candidate that passes it
    /// pays for the EIP-55 casing, and only when --checksum asked for it.
    #[inline]
    fn evm_hit(&self, lower: &[u8; 40], addr: &[u8; 20]) -> bool {
        let mut cand = false;
        for s in &self.suffixes {
            if lower[40 - s.len()..].eq_ignore_ascii_case(s) { cand = true; break; }
        }
        if !cand {
            for p in &self.prefixes {
                if lower[..p.len()].eq_ignore_ascii_case(p) { cand = true; break; }
            }
        }
        if !cand { return false; }
        if !self.checksum { return true; }
        let cs = evm::eip55(addr);
        let cs = &cs.as_bytes()[2..];
        for s in &self.suffixes {
            if &cs[40 - s.len()..] == s.as_slice() { return true; }
        }
        for p in &self.prefixes {
            if &cs[..p.len()] == p.as_slice() { return true; }
        }
        false
    }

    /// Per-candidate hit probability.
    fn probability(&self) -> f64 {
        if self.chain == Chain::Evm {
            // sixteen digits, any case - unless --checksum, when every letter must also
            // land on its EIP-55 case, a coin flip each
            let one = |pat: &Vec<u8>| -> f64 {
                let letters = if self.checksum { pat.iter().filter(|c| c.is_ascii_alphabetic()).count() } else { 0 };
                1.0 / 16f64.powi(pat.len() as i32) / 2f64.powi(letters as i32)
            };
            return self.suffixes.iter().map(one).sum::<f64>() + self.prefixes.iter().map(one).sum::<f64>();
        }
        let variants = |pat: &Vec<u8>| -> f64 {
            let mut n = 1.0f64;
            for &c in pat {
                if self.ignore_case && c.is_ascii_alphabetic() {
                    // base58 lacks 0 O I l, so o/i/L have only one case
                    let k = B58.iter().filter(|&&x| x.eq_ignore_ascii_case(&c)).count();
                    n *= k as f64;
                }
            }
            n / 58f64.powi(pat.len() as i32)
        };
        self.suffixes.iter().map(variants).sum::<f64>()
            + self.prefixes.iter().map(variants).sum::<f64>()
    }
}

// ---------------------------------------------------------------- worker

struct Hit {
    chain: Chain,
    index: u32,
    /// Solana: base58. EVM: `0x` + forty hex digits in EIP-55 case.
    address: String,
    mnemonic: Zeroizing<String>,
    /// A BIP39 passphrase was used. The passphrase itself is never carried,
    /// written, or printed - only the fact, so the file can say the seed
    /// alone will not reach this address.
    passphrase: bool,
    /// The wallet-import form: base58 of the 64-byte keypair (32-byte secret
    /// followed by the 32-byte public key) - what Phantom's "Import Private
    /// Key" pastes.
    privkey: Zeroizing<String>,
    /// The same 64 bytes as a JSON array - `[12,34,...]` - what Solflare's
    /// keypair import and solana-keygen read. Empty for EVM, which has one
    /// import form: the hex private key, carried in `privkey`.
    keypair_json: Zeroizing<String>,
}

/// The 64-byte keypair: secret32 || pubkey32.
fn keypair_bytes(secret: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let sk = SigningKey::from_bytes(secret);
    let mut kp = Zeroizing::new([0u8; 64]);
    kp[..32].copy_from_slice(secret);
    kp[32..].copy_from_slice(&sk.verifying_key().to_bytes());
    kp
}

/// base58(secret32 || pubkey32) - the standard Solana keypair encoding.
fn keypair_b58(secret: &[u8; 32]) -> Zeroizing<String> {
    let kp = keypair_bytes(secret);
    Zeroizing::new(bs58::encode(&kp[..]).into_string())
}

/// The same 64 bytes as the JSON byte array solana-keygen writes and Solflare
/// pastes: `[12,34,...]`, no spaces.
fn keypair_json(secret: &[u8; 32]) -> Zeroizing<String> {
    let kp = keypair_bytes(secret);
    let body: Vec<String> = kp.iter().map(|b| b.to_string()).collect();
    Zeroizing::new(format!("[{}]", body.join(",")))
}

#[allow(clippy::too_many_arguments)]
fn grind_loop(
    m: &Matcher,
    path: PathStyle,
    indices: u32,
    entropy_len: usize,
    passphrase: &str,
    stop: &AtomicBool,
    counter: &AtomicU64,
    on_hit: &dyn Fn(Hit),
) {
    let mut suffix = [0u8; 16];
    let mut local: u64 = 0;
    let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);

    while !stop.load(Ordering::Relaxed) {
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = match bip39::Mnemonic::from_entropy(&entropy) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // BIP39: seed = PBKDF2(mnemonic, "mnemonic" + passphrase). The passphrase is
        // the only thing that changes here; every wallet that takes one does exactly this.
        let seed = Zeroizing::new(mnemonic.to_seed(passphrase));

        // m/44'/501' is constant across every index -- compute once per mnemonic
        let (mut k, mut c) = master_key(seed.as_ref());
        let (mut k2, mut c2) = derive_hardened(&k, &c, 44);
        let (kp, cp) = derive_hardened(&k2, &c2, 501);
        k.zeroize(); c.zeroize(); k2.zeroize(); c2.zeroize();

        for idx in 0..indices {
            let (mut ka, mut ca) = derive_hardened(&kp, &cp, idx);
            let mut kf = if path == PathStyle::Phantom {
                derive_hardened(&ka, &ca, 0).0
            } else {
                ka
            };
            let pk = SigningKey::from_bytes(&kf).verifying_key().to_bytes();
            kf.zeroize(); ka.zeroize(); ca.zeroize();

            local += 1;
            if local >= 4096 {
                counter.fetch_add(local, Ordering::Relaxed);
                local = 0;
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }

            let mut hit = false;
            if m.max_suffix > 0 {
                b58_suffix(&pk, m.max_suffix, &mut suffix);
                for s in &m.suffixes {
                    if m.eq(&suffix[m.max_suffix - s.len()..m.max_suffix], s) {
                        hit = true;
                        break;
                    }
                }
            }
            if !hit && m.needs_full {
                let full = bs58::encode(pk).into_string();
                for p in &m.prefixes {
                    if full.len() >= p.len() && m.eq(&full.as_bytes()[..p.len()], p) {
                        hit = true;
                        break;
                    }
                }
            }

            if hit {
                counter.fetch_add(local, Ordering::Relaxed);
                local = 0;
                // The secret was zeroized before the match test (kept alive
                // for no candidate that loses). Re-derive it for the winner:
                // two HMACs, on the one path in ~10 million that needs it.
                let (mut ka2, mut ca2) = derive_hardened(&kp, &cp, idx);
                let mut secret = if path == PathStyle::Phantom {
                    derive_hardened(&ka2, &ca2, 0).0
                } else {
                    ka2
                };
                let privkey = keypair_b58(&secret);
                let keypair_json = keypair_json(&secret);
                secret.zeroize(); ka2.zeroize(); ca2.zeroize();
                on_hit(Hit {
                    chain: Chain::Sol,
                    index: idx,
                    address: bs58::encode(pk).into_string(),
                    mnemonic: Zeroizing::new(mnemonic.to_string()),
                    passphrase: !passphrase.is_empty(),
                    privkey,
                    keypair_json,
                });
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }
        }
    }
    counter.fetch_add(local, Ordering::Relaxed);
}

/// The EVM hot loop: one mnemonic, PBKDF2 once, `m/44'/60'/0'/0` once (four
/// derivations and two public keys), then every account index at one HMAC and
/// one secp256k1 scalar multiplication. The address is keccak of the public
/// key, forty hex digits; suffix and prefix both read straight off it, so there
/// is no cheap-lane/full-lane split here - the scalar multiplication is the cost.
fn grind_loop_evm(
    m: &Matcher,
    indices: u32,
    entropy_len: usize,
    passphrase: &str,
    stop: &AtomicBool,
    counter: &AtomicU64,
    on_hit: &dyn Fn(Hit),
) {
    let mut hex = [0u8; 40];
    let mut local: u64 = 0;
    let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);

    while !stop.load(Ordering::Relaxed) {
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = match bip39::Mnemonic::from_entropy(&entropy) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
        // the one-in-2^127 seed with an invalid node in its tree is simply not used
        let Some(branch) = evm::Branch::from_seed(seed.as_ref()) else { continue };

        for idx in 0..indices {
            let Some(addr) = branch.address_at(idx) else { continue };

            local += 1;
            if local >= 1024 {
                counter.fetch_add(local, Ordering::Relaxed);
                local = 0;
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }

            evm::hex40(&addr, &mut hex);
            if m.evm_hit(&hex, &addr) {
                counter.fetch_add(local, Ordering::Relaxed);
                local = 0;
                // the private key is re-derived for the winner only: one HMAC
                let Some(k) = branch.key_at(idx) else { continue };
                on_hit(Hit {
                    chain: Chain::Evm,
                    index: idx,
                    address: evm::eip55(&addr),
                    mnemonic: Zeroizing::new(mnemonic.to_string()),
                    passphrase: !passphrase.is_empty(),
                    privkey: evm::privkey_hex(&k),
                    keypair_json: Zeroizing::new(String::new()),
                });
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }
        }
    }
    counter.fetch_add(local, Ordering::Relaxed);
}

/// Per-candidate cost beyond the once-per-mnemonic PBKDF2, for the THEORETICAL
/// model only (an estimate prefers the rate `bench` measured on this machine).
/// Solana: two HMAC-SHA512 and one Ed25519 scalar multiplication. EVM: one
/// HMAC-SHA512, one secp256k1 scalar multiplication, one keccak.
fn per_candidate_cost(chain: Chain) -> f64 {
    match chain { Chain::Sol => 21e-6, Chain::Evm => EVM_PER_CANDIDATE }
}
/// Measured on the development machine, 2026-08-20, release build: the number
/// the model is anchored to until `bench --chain evm` replaces it with yours.
const EVM_PER_CANDIDATE: f64 = 65e-6;

/// Candidates per second per thread the model predicts at `indices` per mnemonic.
fn model_rate(chain: Chain, indices: u32) -> f64 {
    1.0 / (1.2e-3 / indices as f64 + per_candidate_cost(chain))
}

// ---------------------------------------------------------------- rate cache

/// `bench` writes the measured rate here; `estimate` reads it. The
/// theoretical model (1.2ms/indices + 21us) ran 2.6x optimistic on the
/// first machine it met -- an estimate should come from what THIS box
/// measured, not from a formula.
/// `<XDG_DATA_HOME or ~/.local/share>/keyrx/` - the tool's own directory.
fn data_dir() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("keyrx")
}

/// One measured rate per chain: `bench.txt` for Solana (the file the first
/// releases wrote), `bench-evm.txt` for EVM. The two loops cost nothing alike.
fn rate_cache_path(chain: Chain) -> std::path::PathBuf {
    data_dir().join(match chain { Chain::Sol => "bench.txt", Chain::Evm => "bench-evm.txt" })
}

/// Where matches live by default: `<XDG_DATA_HOME or ~/.local/share>/keyrx/matches/`.
/// A home of its own, never the current directory, because a file that holds
/// seed phrases should not land wherever the shell happens to be.
fn matches_dir() -> std::path::PathBuf {
    data_dir().join("matches")
}

/// EVM matches sit one level down, `matches/evm/`: the same pattern on two
/// chains must not share a file, and the Solana files stay exactly where every
/// earlier release put them.
fn matches_dir_for(chain: Chain) -> std::path::PathBuf {
    match chain { Chain::Sol => matches_dir(), Chain::Evm => matches_dir().join("evm") }
}

/// The pattern names the file: --ends-with KEYRX -> KEYRX.txt; several patterns
/// join with '+'; prefixes carry a trailing '_' so KEYRX_ (prefix) and KEYRX
/// (suffix) do not collide; case-insensitive adds '.ic'. EVM files go under
/// matches/evm/, named by the hex (a leading 0x dropped), '.cs' for --checksum.
fn default_out(p: &PatternArgs) -> String {
    let mut parts: Vec<String> = Vec::new();
    let strip = |s: &String| -> String {
        if p.chain == Chain::Evm { s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s).to_string() } else { s.clone() }
    };
    for s in &p.ends_with { parts.push(strip(s)); }
    for s in &p.starts_with { parts.push(format!("{}_", strip(s))); }
    let mut name = if parts.is_empty() { "matches".to_string() } else { parts.join("+") };
    match p.chain {
        Chain::Sol => if p.ignore_case { name.push_str(".ic"); },
        Chain::Evm => if p.checksum { name.push_str(".cs"); } else { name = name.to_ascii_lowercase(); },
    }
    name.push_str(".txt");
    matches_dir_for(p.chain).join(name).to_string_lossy().into_owned()
}

/// A path for the eye: files under the tool's own data dir print as
/// `matches/KEYRX.txt`; anything else prints whole. The full path is always
/// in the foot of the panel that names the file.
fn short_path(p: &str) -> String {
    let dir = matches_dir();
    if let Ok(rel) = std::path::Path::new(p).strip_prefix(&dir) {
        return format!("matches/{}", rel.display());
    }
    p.to_string()
}

/// The match file as `short_path` prints it, clickable: the click opens the
/// FOLDER it sits in, never the file - a seed is read with `show --keys`, on
/// purpose, not by a stray click into whatever the desktop opens .txt with.
fn out_link(p: &str) -> String {
    let path = std::path::Path::new(p);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let abs = std::fs::canonicalize(&dir)
        .unwrap_or_else(|_| std::env::current_dir().map(|c| c.join(&dir)).unwrap_or(dir));
    ui::link(&ui::file_url(&abs), &short_path(p))
}

fn save_rate(chain: Chain, threads: usize, indices: u32, rate: f64) {
    let p = rate_cache_path(chain);
    if let Some(d) = p.parent() { let _ = std::fs::create_dir_all(d); }
    let _ = std::fs::write(&p, format!("{} {} {:.0}\n", threads, indices, rate));
}

/// (threads, indices, rate) from the last bench of that chain, if any.
fn load_rate(chain: Chain) -> Option<(usize, u32, f64)> {
    let s = std::fs::read_to_string(rate_cache_path(chain)).ok()?;
    let mut it = s.split_whitespace();
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Scale a measured rate to other settings using the model's SHAPE (the
/// PBKDF2 amortisation curve), anchored to the real number.
fn scale_rate(chain: Chain, measured: f64, m_threads: usize, m_idx: u32, threads: usize, indices: u32) -> f64 {
    measured / m_threads as f64 * threads as f64 * model_rate(chain, indices) / model_rate(chain, m_idx)
}

// ---------------------------------------------------------------- output

/// 656356768 -> "656,356,768". Whole numbers only; the callers round first.
fn group(v: f64) -> String {
    let s = format!("{:.0}", v);
    let (neg, digits) = match s.strip_prefix('-') { Some(d) => (true, d), None => (false, s.as_str()) };
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 { out.push(','); }
        out.push(ch);
    }
    if neg { format!("-{}", out) } else { out }
}

fn fmt_dur(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--".into();
    }
    if secs < 90.0 {
        format!("{:.0}s", secs)
    } else if secs < 5400.0 {
        format!("{:.1}m", secs / 60.0)
    } else if secs < 172_800.0 {
        format!("{:.1}h", secs / 3600.0)
    } else {
        format!("{:.1}d", secs / 86400.0)
    }
}

fn path_str(style: PathStyle, idx: u32) -> String {
    match style {
        PathStyle::Phantom => format!("m/44'/501'/{}'/0'", idx),
        PathStyle::Legacy => format!("m/44'/501'/{}'", idx),
    }
}

/// The path a hit sits at, per chain. EVM has one path style: BIP44
/// m/44'/60'/0'/0/N, what MetaMask, Rabby, Ledger Live and Trezor Suite walk.
fn path_for(chain: Chain, style: PathStyle, idx: u32) -> String {
    match chain {
        Chain::Sol => path_str(style, idx),
        Chain::Evm => format!("m/44'/60'/0'/0/{}", idx),
    }
}

/// How to get this address into a wallet, said once, at the moment it
/// matters. One short line per wallet so nothing is ever clipped by the frame.
fn import_hint(chain: Chain, style: PathStyle, idx: u32) -> Vec<String> {
    if chain == Chain::Evm {
        return if idx == 0 {
            vec!["Seed:     or THIS seed as the wallet - this is its FIRST account".to_string()]
        } else {
            vec![format!("Seed:     or THIS seed as the wallet, 'add account' {}x = account #{}", idx, idx + 1)]
        };
    }
    match style {
        PathStyle::Phantom => {
            if idx == 0 {
                vec!["Seed:     or THIS seed as the wallet: account #1 in Phantom/Solflare".to_string()]
            } else {
                vec![
                    format!("Seed:     or THIS seed as the wallet - Solflare path {}", path_str(style, idx)),
                    format!("          Phantom: 'add account' {}x = account #{}", idx, idx + 1),
                ]
            }
        }
        PathStyle::Legacy => vec![
            format!("Seed:     Solflare, derivation path {} (legacy)", path_str(style, idx)),
        ],
    }
}

/// `keyrx show`: list matches in the file WITHOUT the seeds. Address and path
/// are safe to read aloud, paste, and verify; the seed stays in the 0600 file.
fn cmd_show(file: Option<String>, with_seed: bool, with_key: bool) {
    ui::masthead("show");
    let file = match file {
        Some(f) if std::path::Path::new(&f).exists() => f,
        Some(f) => {
            // a bare pattern name: KEYRX -> matches/KEYRX.txt; dead -> matches/evm/dead.txt
            // when no Solana file of that name exists; evm/dead names the EVM file outright
            let stem = f.trim_end_matches(".txt");
            let sol = matches_dir().join(format!("{}.txt", stem));
            let evm = matches_dir_for(Chain::Evm).join(format!("{}.txt", stem.trim_start_matches("evm/")));
            let cand = if sol.exists() || (!evm.exists() && !stem.starts_with("evm/")) { sol } else { evm };
            if cand.exists() { cand.to_string_lossy().into_owned() }
            else {
                let lock = format!("{}.grinding", cand.display());
                let running = |p: &str| -> bool {
                    std::fs::read_to_string(p).ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .map(|pid| std::path::Path::new(&format!("/proc/{}", pid)).exists())
                        .unwrap_or(false)
                };
                if running(&lock) {
                    // A grind is working on exactly this file: wait for the
                    // first hit and draw it, instead of answering "nothing"
                    // to a question that will have an answer in a moment.
                    println!("{}", ui::top("GRINDING", &format!("{}", cand.file_name().unwrap().to_string_lossy())));
                    println!("{}", ui::note("a grind for this pattern is running - waiting for the first match."));
                    println!("{}", ui::note("Ctrl-C to stop waiting; the grind keeps going."));
                    println!("{}", ui::bot("the file appears on the first hit"));
                    let _ = std::io::stdout().flush();
                    loop {
                        std::thread::sleep(Duration::from_millis(400));
                        if cand.exists() { break; }
                        if !running(&lock) {
                            println!("\n{}", ui::note("the grind exited without a match."));
                            std::process::exit(1);
                        }
                    }
                    // let the writer finish its append
                    std::thread::sleep(Duration::from_millis(200));
                    cand.to_string_lossy().into_owned()
                } else {
                    println!("{}", ui::top("NO MATCHES", &format!("{}", cand.display())));
                    println!("{}", ui::note("no grind is running for this pattern and no match file exists."));
                    println!("{}", ui::note("start one:  keyrx grind --ends-with <pattern>"));
                    println!("{}", ui::bot("`keyrx show` alone lists what exists"));
                    println!();
                    std::process::exit(1);
                }
            }
        }
        None => {
            let dir = matches_dir();
            println!("{}", ui::top("MATCH FILES", &ui::dir_link(&dir)));
            // Solana files at the top level, EVM files under evm/ - listed as evm/NAME,
            // which is also what `show` takes to read one
            let list = |d: &std::path::Path| -> Vec<String> {
                let mut v: Vec<String> = std::fs::read_dir(d).map(|rd| rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n.ends_with(".txt")).collect()).unwrap_or_default();
                v.sort();
                v
            };
            let mut names: Vec<(std::path::PathBuf, String)> = list(&dir).into_iter().map(|n| (dir.join(&n), n.trim_end_matches(".txt").to_string())).collect();
            let evm_dir = matches_dir_for(Chain::Evm);
            names.extend(list(&evm_dir).into_iter().map(|n| (evm_dir.join(&n), format!("evm/{}", n.trim_end_matches(".txt")))));
            if names.is_empty() {
                println!("{}", ui::note("no match files yet - grind writes them here, named after the pattern"));
            }
            for (path, stem) in &names {
                let cnt = std::fs::read_to_string(path)
                    .map(|t| t.split("\n\n").filter(|b| b.contains("address ")).count()).unwrap_or(0);
                println!("{}", ui::kv(stem, &format!("{} match(es)   keyrx show {}", cnt, stem)));
            }
            if ui::links_on() { println!("{}", ui::mid("")); println!("{}", ui::note(&format!("{} (the path in the title)", ui::CLICK_HINT))); }
            println!("{}", ui::bot("every file is mode 0600 · seeds and keys inside"));
            println!();
            return;
        }
    };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => { eprintln!("cannot read {}: {}", file, e); std::process::exit(1); }
    };
    println!("{}", ui::top("MATCHES", &{ let d = std::path::Path::new(&file).parent().map(|d| d.to_path_buf()).unwrap_or_default(); let abs = std::fs::canonicalize(&d).unwrap_or(d); ui::link(&ui::file_url(&abs), &file) }));
    let mut n = 0;
    type Secret = (usize, String, Option<String>, Option<String>, Option<String>);
    let mut secrets: Vec<Secret> = Vec::new();
    for block in text.split("\n\n") {
        let mut addr = None; let mut path = None; let mut seed = None; let mut key = None; let mut kp = None;
        let mut pass = false;
        for line in block.lines() {
            if let Some(v) = line.strip_prefix("address ") { addr = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("path ") { path = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("seed ") { seed = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("privkey ") { key = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("keypair ") { kp = Some(v.trim()); }
            else if line.starts_with("passphrase used") { pass = true; }
        }
        if let (Some(a), Some(p)) = (addr, path) {
            n += 1;
            println!("{}", ui::mid(&format!("  {}{:>2}.{} {}{}{}  {}{}{}", ui::gry(), n, ui::r(), ui::wht(), a, ui::r(), ui::accent(), p, ui::r())));
            if pass { println!("{}", ui::mid(&format!("      {}+ passphrase - the seed alone will not reach it; the keys will{}", ui::warn(), ui::r()))); }
            if with_seed || with_key {
                secrets.push((n, a.to_string(), seed.map(str::to_string), key.map(str::to_string), kp.map(str::to_string)));
            }
        }
    }
    if n == 0 {
        println!("{}", ui::note("no matches in this file"));
    }
    let foot = match (with_seed, with_key) {
        (false, false) => "seeds and keys withheld · --seeds / --keys to print them",
        _ => "secrets below, one per line, bare - clear your scrollback when done",
    };
    println!("{}", ui::bot(foot));
    // Anything meant to be PASTED prints as one unbroken plain line OUTSIDE
    // the frame: a secret split across framed rows copies with border glyphs
    // and padding in it - a wrapped key pasted into Phantom did not take.
    for (i, a, seed, key, kp) in secrets {
        println!();
        println!(" {}{:>2}. {}{}", ui::gry(), i, a, ui::r());
        if with_seed {
            println!(" {}seed{}", ui::gry(), ui::r());
            println!("{}", seed.as_deref().unwrap_or("(missing)"));
        }
        if with_key {
            if a.starts_with("0x") {
                // an EVM match: one key form, the hex every EVM wallet imports
                println!(" {}privkey  hex - MetaMask/Rabby: Import account -> Private key{}", ui::gry(), ui::r());
                println!("{}", key.as_deref().unwrap_or("(missing)"));
            } else {
                println!(" {}privkey  base58 - Phantom: Import Private Key{}", ui::gry(), ui::r());
                println!("{}", key.as_deref().unwrap_or("(missing)"));
                println!(" {}keypair  JSON array - Solflare, solana-keygen{}", ui::gry(), ui::r());
                println!("{}", kp.as_deref().unwrap_or("(missing)"));
            }
        }
    }
    println!();
}

/// Written under the seed when a passphrase was used - the fact, never the passphrase.
const PASSPHRASE_LINE: &str = "\npassphrase used - NOT stored: the seed alone will not reach this address; the keys will";

fn write_hit(out: &str, h: &Hit, style: PathStyle) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(out)?;
    match h.chain {
        Chain::Sol => writeln!(
            f,
            "address {}\npath    {}\nseed    {}{}\nprivkey {}\nkeypair {}\n",
            h.address,
            path_str(style, h.index),
            h.mnemonic.as_str(),
            if h.passphrase { PASSPHRASE_LINE } else { "" },
            h.privkey.as_str(),
            h.keypair_json.as_str()
        ),
        // EVM has one import form - the hex private key - so four lines, no keypair
        Chain::Evm => writeln!(
            f,
            "address {}\npath    {}\nseed    {}{}\nprivkey {}\n",
            h.address,
            path_for(Chain::Evm, style, h.index),
            h.mnemonic.as_str(),
            if h.passphrase { PASSPHRASE_LINE } else { "" },
            h.privkey.as_str()
        ),
    }
}

/// Time-to-first-match rows, framed. The 50% line carries the accent: it is
/// the number the operator plans around.
/// Time to ALL of n matches. Each match is an independent wait with mean
/// 1/(prob*rate), so the total is Gamma(n, mean): its mean is exactly n times
/// the first match's, and its spread narrows as n grows. The 50% and 90%
/// rows use the Wilson-Hilferty approximation to the Gamma quantile, which is
/// within about a percent for n >= 2 (n == 1 uses the exact rows above).
fn quantiles_n(prob: f64, rate: f64, n: usize) {
    let k = n as f64;
    let mean_one = 1.0 / prob / rate;
    for (label, z) in [("50%", 0.0f64), ("90%", 1.2815516)] {
        let q = k * (1.0 - 1.0 / (9.0 * k) + z * (1.0 / (9.0 * k)).sqrt()).powi(3);
        let row = if label == "50%" { ui::kv_accent(label, &fmt_dur(q * mean_one)) } else { ui::kv(label, &fmt_dur(q * mean_one)) };
        println!("{}", row);
    }
    println!("{}", ui::kv("mean", &format!("{}   ({} x the mean above)", fmt_dur(k * mean_one), n)));
}

fn quantiles(prob: f64, rate: f64) {
    for (label, q) in [("50%", 0.5f64), ("90%", 0.9), ("99%", 0.99)] {
        let n = (1.0 - q).ln() / (1.0 - prob).ln();
        let row = if label == "50%" {
            ui::kv_accent(label, &fmt_dur(n / rate))
        } else {
            ui::kv(label, &fmt_dur(n / rate))
        };
        println!("{}", row);
    }
    println!("{}", ui::kv("mean", &fmt_dur(1.0 / prob / rate)));
}

// ---------------------------------------------------------------- main

fn main() {
    let cli = Cli::parse();
    if cli.update { cmd_update(); return; }
    let cmd = match cli.cmd {
        Some(c) => c,
        None => { cmd_start(); return; }
    };
    match cmd {
        Cmd::Verify => cmd_verify(),
        Cmd::Estimate { pattern, threads, indices, count } => cmd_estimate(pattern, threads, indices, count),
        Cmd::Bench { chain, threads, indices, seconds } => cmd_bench(chain, threads, indices, seconds),
        Cmd::Show { file, seeds, keys } => cmd_show(file, seeds, keys),
        Cmd::Donate => cmd_donate(),
        Cmd::Networks => cmd_networks(),
        Cmd::Grind { pattern, threads, indices, count, words, out, show_seed, passphrase } => {
            let out = out.unwrap_or_else(|| default_out(&pattern));
            cmd_grind(pattern, threads, indices, count, words, out, show_seed, passphrase)
        }
    }
}

/// The start screen: `keyrx` with no arguments. Every command, every flag,
/// and the two ideas you need - what a path index is, and why --indices
/// trades speed for where the match lands.
/// `keyrx --update`: the install line - cargo install keyrx && clear && keyrx -
/// as one flag. cargo does the work with its own output on screen; if it ends
/// clean, the screen is cleared and the freshly installed keyrx starts, so the
/// first thing you see is the new start screen with the new version on it.
fn cmd_update() {
    ui::masthead(&format!("v{}", env!("CARGO_PKG_VERSION")));
    let Some(cargo) = find_cargo() else {
        println!("{}", ui::top("UPDATE", ""));
        println!("{}", ui::crit_line("cargo is not on PATH - keyrx is installed and updated by cargo."));
        println!("{}", ui::note("install Rust from https://rustup.rs (one command), then:"));
        println!("{}", ui::note("cargo install keyrx && clear && keyrx"));
        println!("{}", ui::bot(""));
        println!();
        std::process::exit(1);
    };
    println!("{}", ui::top("UPDATE", "cargo install keyrx && clear && keyrx"));
    println!("{}", ui::kv("running", &format!("{} install keyrx", cargo.display())));
    println!("{}", ui::note("cargo's output follows - \"already installed\" means you have the latest"));
    println!("{}", ui::bot("then the screen clears and the new keyrx starts"));
    println!();
    let status = std::process::Command::new(&cargo).arg("install").arg("keyrx").status();
    match status {
        Ok(st) if st.success() => {}
        Ok(st) => { eprintln!("cargo install keyrx exited with {}", st); std::process::exit(st.code().unwrap_or(1)); }
        Err(e) => { eprintln!("could not run {}: {}", cargo.display(), e); std::process::exit(1); }
    }
    // the binary cargo just wrote: <cargo root>/bin/keyrx, or whatever is running
    // us if that cannot be found (a dev build started from a clone, say)
    let bin = installed_keyrx().unwrap_or_else(|| std::env::current_exe().unwrap_or_else(|_| "keyrx".into()));
    if std::io::IsTerminal::is_terminal(&std::io::stdout()) { print!("\x1b[2J\x1b[H"); }
    let _ = std::io::Write::flush(&mut std::io::stdout());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&bin).exec();
        eprintln!("could not start {}: {}", bin.display(), err);
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        let code = std::process::Command::new(&bin).status().map(|s| s.code().unwrap_or(0)).unwrap_or(1);
        std::process::exit(code);
    }
}

/// cargo, wherever rustup put it: $CARGO (set when run under cargo), then PATH,
/// then $CARGO_HOME/bin, then ~/.cargo/bin.
fn find_cargo() -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) { "cargo.exe" } else { "cargo" };
    if let Some(c) = std::env::var_os("CARGO") { let p = std::path::PathBuf::from(c); if p.is_file() { return Some(p); } }
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) { let p = d.join(exe); if p.is_file() { return Some(p); } }
    }
    cargo_home().map(|h| h.join("bin").join(exe)).filter(|p| p.is_file())
}

/// Where `cargo install` writes binaries: $CARGO_INSTALL_ROOT/bin, else $CARGO_HOME/bin, else ~/.cargo/bin.
fn installed_keyrx() -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) { "keyrx.exe" } else { "keyrx" };
    let root = std::env::var_os("CARGO_INSTALL_ROOT").map(std::path::PathBuf::from).or_else(cargo_home)?;
    Some(root.join("bin").join(exe)).filter(|p| p.is_file())
}

fn cargo_home() -> Option<std::path::PathBuf> {
    if let Some(h) = std::env::var_os("CARGO_HOME") { return Some(std::path::PathBuf::from(h)); }
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(|h| std::path::PathBuf::from(h).join(".cargo"))
}

fn cmd_start() {
    ui::masthead(&format!("v{}", env!("CARGO_PKG_VERSION")));
    let n = ui::note;
    let kvw = ui::kvw;
    let cont = ui::cont;
    let blank = || println!("{}", ui::mid(""));
    let head = |t: &str| println!("{}", ui::mid(&format!("  {}{}{}{}", ui::b(), ui::wht(), t, ui::r())));

    println!("{}", ui::top("WHAT THIS IS", "one seed, unlimited addresses, keys for every wallet"));
    println!("{}", n("Grinds Solana and EVM vanity addresses - an address that ends (or"));
    println!("{}", n("starts) with the letters you choose - and hands you everything a"));
    println!("{}", n("wallet needs to hold it: seed phrase, derivation path, and the key in"));
    println!("{}", n("every import form (base58 and JSON array for Solana, 0x hex for EVM)."));
    blank();
    println!("{}", n("Fast because `solana-keygen grind` pays 2048 rounds of PBKDF2 (~1.2 ms)"));
    println!("{}", n("to test ONE address; keyRX pays it once per seed, then walks that"));
    println!("{}", n("seed's account indices at ~21 us each: 20-60x the throughput."));
    blank();
    println!("{}", n("Standalone. No daemon, no service, no network. Secrets go to a"));
    println!("{}", n("mode-0600 file in a directory of their own, never to the screen"));
    println!("{}", n("unless you ask."));
    println!("{}", ui::bot("verify -> bench -> estimate -> grind -> show"));

    println!("{}", ui::top("COMMANDS", "in the order you use them"));
    println!("{}", kvw("verify", "self-test: base58, both derivations (Solana, EVM) and"));
    println!("{}", cont("the pinned answers. Prints the manual cross-checks."));
    println!("{}", cont("Run first, always."));
    blank();
    println!("{}", kvw("bench", "measures this machine's real rate and SAVES it for"));
    println!("{}", cont("estimate, per chain.  --chain evm  --indices N"));
    blank();
    println!("{}", kvw("estimate", "odds and time-to-match for a pattern, from the"));
    println!("{}", cont("measured rate. Says what --ignore-case, --checksum"));
    println!("{}", cont("or --indices 128 would buy.   --chain sol|evm"));
    blank();
    println!("{}", kvw("grind", "the real thing. Same pattern flags as estimate,"));
    println!("{}", cont("plus output. Ctrl-C stops after the current batch."));
    blank();
    println!("{}", kvw("show", "lists matches from the file: address + path,"));
    println!("{}", cont("seeds withheld. --seeds / --keys print them too."));
    blank();
    println!("{}", kvw("donate", "optional, and it changes nothing."));
    println!("{}", kvw("networks", "EVM networks a wallet does not list (Robinhood Chain):"));
    println!("{}", cont("the add-a-network steps and values, bare, for pasting."));
    blank();
    println!("{}", kvw("--update", "cargo install keyrx && clear && keyrx, as one flag."));
    println!("{}", cont("cargo prints its work; then the new start screen."));
    println!("{}", ui::bot("every command takes --help"));

    println!("{}", ui::top("PATTERN FLAGS", "estimate and grind"));
    println!("{}", kvw("--ends-with S", "suffix. Repeatable. Cheap: only the last N base58"));
    println!("{}", cont("characters are computed per candidate."));
    blank();
    println!("{}", kvw("--starts-with P", "prefix. Repeatable. Slower: needs the full address."));
    blank();
    println!("{}", kvw("--ignore-case", "match either case. ~2^letters more likely:"));
    println!("{}", cont("KEYRX goes from 1 in 656M to 1 in 20.5M."));
    blank();
    println!("{}", kvw("--path phantom", "m/44'/501'/N'/0'   Phantom, Solflare default"));
    println!("{}", kvw("--path legacy", "m/44'/501'/N'      Solflare custom path"));
    blank();
    println!("{}", kvw("--chain evm", "Ethereum and every EVM chain instead of Solana:"));
    println!("{}", cont("hex patterns, m/44'/60'/0'/0/N. See EVM below."));
    println!("{}", kvw("--checksum", "EVM: letters must land in EIP-55 case as typed."));
    blank();
    println!("{}", n("base58 has no 0 O I l - patterns using them are rejected."));
    println!("{}", ui::bot("suffixes are the fast lane"));

    println!("{}", ui::top("EVM", "Ethereum, Base, Arbitrum, Polygon, BNB, Robinhood: one key"));
    println!("{}", kvw("--chain evm", "a 0x address: forty hex digits. secp256k1 in the BIP44"));
    println!("{}", cont("tree at m/44'/60'/0'/0/N - the path MetaMask, Rabby,"));
    println!("{}", cont("Ledger Live, Trezor Suite walk. One key, every chain."));
    blank();
    println!("{}", kvw("patterns", "0-9 and a-f. Matched in ANY case by default: hex has"));
    println!("{}", cont("no case of its own. 0x is allowed in front of a prefix."));
    println!("{}", kvw("--checksum", "the letters must ALSO come out in EIP-55 case exactly"));
    println!("{}", cont("as you typed them. Each letter halves the odds: rarer,"));
    println!("{}", cont("and it shows. estimate prints both numbers."));
    blank();
    println!("{}", kvw("import", "MetaMask/Rabby: a wallet must exist first (any seed; it"));
    println!("{}", cont("never sees this key). Then: account menu -> Import"));
    println!("{}", cont("account -> Private key -> the 0x hex: this address,"));
    println!("{}", cont("every chain. Or import THIS seed as the wallet, then"));
    println!("{}", cont("'add account' N times: account N+1 is this one."));
    blank();
    println!("{}", kvw("files", "matches/evm/<pattern>.txt  ·  keyrx show evm/<pattern>"));
    println!("{}", kvw("networks", "keyrx networks - add-a-network steps and the values for"));
    println!("{}", cont("chains a wallet does not list (Robinhood Chain, 4663)."));
    println!("{}", kvw("rate", "keyrx bench --chain evm. secp256k1 costs more per"));
    println!("{}", cont("candidate than Ed25519, so --indices buys less here;"));
    println!("{}", cont("estimate --chain evm says what, from your own bench."));
    println!("{}", ui::bot("the 25th word, --count, --out, --words work the same on both chains"));

    println!("{}", ui::top("GRIND FLAGS", ""));
    println!("{}", kvw("--out FILE", "where matches go. Created mode 0600. Default: a file"));
    println!("{}", cont("named after the pattern - KEYRX -> matches/KEYRX.txt"));
    blank();
    println!("{}", kvw("--count N", "stop after N matches. Default 1. May return a"));
    println!("{}", cont("couple more when threads hit at once - all valid."));
    println!("{}", cont("All land in the one file. estimate --count N prints"));
    println!("{}", cont("the time to all N - each match is independent."));
    blank();
    println!("{}", kvw("--passphrase", "BIP39 passphrase, the '25th word'. Prompted, hidden,"));
    println!("{}", cont("twice; never stored or printed. The seed alone then"));
    println!("{}", cont("does NOT reach the address - the keys do. Most browser"));
    println!("{}", cont("wallets have no passphrase field: import the KEY."));
    blank();
    println!("{}", kvw("--words 12|24", "mnemonic length. Default 12 - what Phantom generates"));
    println!("{}", cont("and what most people are used to. Every major wallet"));
    println!("{}", cont("imports either; 12 words is 128 bits, plenty."));
    println!("{}", kvw("--threads N", "default: every core."));
    blank();
    println!("{}", kvw("--show-seed", "ALSO print the seed to the screen. Off by default:"));
    println!("{}", cont("keep it out of scrollback, tmux, screen shares."));
    println!("{}", ui::bot(""));

    println!("{}", ui::top("THE 128", "what --indices means and why it matters"));
    println!("{}", n("One seed phrase is a TREE of addresses, not one address. Wallets"));
    println!("{}", n("number the branches: account 0, 1, 2 ... - that is the N' in"));
    println!("{}", n("m/44'/501'/N'/0'. Every branch is a real address; all of them"));
    println!("{}", n("belong to that phrase."));
    blank();
    println!("{}", n("Turning a phrase into the tree's root costs ~1.2 ms (PBKDF2)."));
    println!("{}", n("Stepping to the next branch costs ~21 us. --indices is how many"));
    println!("{}", n("branches you check per phrase before throwing the phrase away:"));
    blank();
    println!("{}", kvw("--indices 8", "1.2 ms + 8 x 21 us    =   8 candidates per ~1.4 ms"));
    println!("{}", kvw("--indices 128", "1.2 ms + 128 x 21 us  = 128 candidates per ~3.9 ms"));
    println!("{}", cont("about six times more per unit of the expensive work"));
    blank();
    println!("{}", n("The cost: the match lands on ANY branch you checked - with 128 it"));
    println!("{}", n("may be account 97. That only matters if you import the SEED:"));
    println!("{}", n("Solflare takes the path directly; Phantom reaches account 97 by"));
    println!("{}", n("clicking 'add account' 97 times."));
    blank();
    println!("{}", n("Or skip the tree entirely: every match also writes its PRIVATE KEY,"));
    println!("{}", n("and Phantom's 'Import Private Key' (once a wallet exists) lands on the"));
    println!("{}", n("address in one paste, standalone. The index never matters - grind wide."));
    blank();
    head("Private key: --indices 128  ·  Seed into Phantom: --indices 8");
    blank();
    println!("{}", n("EVM: the same 1.2 ms per phrase, then ~65 us per branch (secp256k1"));
    println!("{}", n("costs more than Ed25519), so --indices buys less there. MetaMask"));
    println!("{}", n("walks indices with 'add account' too; the KEY import skips them."));
    println!("{}", ui::bot("estimate shows the exact speed difference on this machine"));

    println!("{}", ui::top("WHAT A MATCH WRITES", "and where"));
    println!("{}", n("Each match appends five lines to its file, created mode 0600 in a"));
    println!("{}", n("mode-0700 directory of its own - never the current directory:"));
    blank();
    println!("{}", kvw("address", "the vanity address"));
    println!("{}", kvw("path", "m/44'/501'/N'/0' - where it sits in the seed's tree"));
    println!("{}", kvw("seed", "the 12 or 24 words - restores the WHOLE tree"));
    println!("{}", kvw("privkey", "base58 keypair - Phantom 'Import Private Key' pastes it"));
    println!("{}", kvw("keypair", "the same key as a JSON array [1,2,...] - Solflare and"));
    println!("{}", cont("solana-keygen import it. Both are standalone: a seed"));
    println!("{}", cont("will not recover them - the file IS the backup."));
    blank();
    println!("{}", kvw("file", &ui::dir_link(&matches_dir())));
    println!("{}", cont("named after the pattern: KEYRX.txt / KEYRX.ic.txt"));
    if ui::links_on() { println!("{}", cont(ui::CLICK_HINT)); }
    blank();
    head("EVM (--chain evm): four lines, under matches/evm/");
    println!("{}", kvw("address", "0x + forty hex digits, in EIP-55 case"));
    println!("{}", kvw("path", "m/44'/60'/0'/0/N - MetaMask, Rabby, Ledger Live walk it"));
    println!("{}", kvw("seed", "the 12 or 24 words - restores the WHOLE tree"));
    println!("{}", kvw("privkey", "0x hex - MetaMask/Rabby 'Import account -> Private key'"));
    println!("{}", cont("one key form, every EVM chain. The file IS the backup."));
    println!("{}", ui::bot("keyrx show   lists the files · keyrx show KEYRX / show evm/dead reads one"));

    println!("{}", ui::top("RECIPES", "pick the wallet you will import into"));
    let cmd = |c: &str| println!("{}", ui::mid(&format!("    {}{}{}", ui::accent(), c, ui::r())));
    let sub = |t: &str| println!("{}", ui::mid(&format!("    {}{}{}", ui::gry(), t, ui::r())));
    let wal = |w: &str, t: &str| println!("{}", ui::mid(&format!("  {}{}{}{}  {}{}{}",
        ui::b(), ui::wht(), w, ui::r(), ui::gry(), t, ui::r())));
    wal("Any wallet", "key import - the simplest route, exact address");
    cmd("keyrx grind --ends-with KEYRX --indices 128");
    sub("keyrx show KEYRX --keys: base58 for Phantom, JSON array for");
    sub("Solflare. Standalone; keep the file - a seed will not recover it.");
    sub("A wallet must exist first (any seed); the key import ADDS an account.");
    blank();
    wal("Phantom", "by seed - the address inside a recoverable HD wallet");
    cmd("keyrx grind --ends-with KEYRX --words 12 --indices 8");
    sub("import the 12 words, then 'add account' until the address shows");
    sub("(0-7 clicks). Slower to find: about 4x the wide grind.");
    blank();
    wal("Solflare", "by seed - takes a custom path, so the grind runs wide");
    cmd("keyrx grind --ends-with KEYRX --indices 128");
    sub("import the words, choose the exact path the match printed.");
    blank();
    wal("Either", "case-insensitive: 32x more likely for KEYRX");
    cmd("keyrx grind --ends-with KEYRX --ignore-case --indices 8");
    sub("matches keyrx, Keyrx, KEYRX, kEyRx... - only an exact-case grind");
    sub("guarantees the letters print exactly KEYRX.");
    blank();
    wal("Prefix", "the address STARTS with your letters");
    cmd("keyrx grind --starts-with Key --indices 128");
    sub("slower per candidate: a prefix needs the whole address encoded,");
    sub("a suffix only its last N characters. Same odds per letter.");
    sub("Repeatable, and combinable: --starts-with Key --ends-with RX");
    blank();
    wal("EVM", "MetaMask, Rabby, Ledger Live - one key, every EVM chain");
    cmd("keyrx grind --chain evm --ends-with dead --indices 128");
    sub("hex, any case: 0x...dead, 0x...DEAD, 0x...DeAd all count. keyrx show");
    sub("evm/dead --keys: the 0x hex. MetaMask/Rabby need a wallet first;");
    sub("then account menu -> Import account -> Private key: an added account.");
    blank();
    wal("EVM, EIP-55", "the letters land in checksum case exactly as typed");
    cmd("keyrx grind --chain evm --ends-with DeAd --checksum");
    sub("rarer by a coin flip per letter (here 16x): the address prints DeAd.");
    sub("prefix with 0x: --starts-with 0xc0ffee. estimate prints both odds.");
    println!("{}", ui::bot("estimate first: it prints the odds for THIS machine"));

    println!("{}", ui::top("A TYPICAL SESSION", "and the variations, in the order you reach for them"));
    // command, then a grey note: beside it when the row has room (with a column of air before
    // the border), beneath it when not. Indent 2, command column 44, one space, "# ", the note.
    let step = |c: &str, n: &str| {
        if 2 + c.chars().count().max(44) + 3 + n.chars().count() < ui::IN {
            println!("{}", ui::mid(&format!("  {}{:<44}{} {}# {}{}", ui::accent(), c, ui::r(), ui::gry(), n, ui::r())));
        } else {
            cmd(c);
            println!("{}", ui::mid(&format!("    {}# {}{}", ui::gry(), n, ui::r())));
        }
    };
    step("keyrx verify", "once per machine");
    step("keyrx bench --indices 128", "this box's rate, saved");
    step("keyrx estimate --ends-with KEYRX --count 10", "odds; time to one and ten");
    step("keyrx grind --ends-with KEYRX --indices 128", "the real thing");
    step("keyrx grind --ends-with KEYRX --count 10", "ten of them, one file");
    step("keyrx grind --ends-with KEYRX --indices 8", "Phantom: 8 clicks max");
    step("keyrx grind --ends-with KEYRX --passphrase", "a 25th word, prompted");
    step("keyrx grind --starts-with Key --ends-with RX", "both ends at once");
    step("keyrx grind --ends-with KEYRX --ignore-case", "any case, 32x likelier");
    step("keyrx estimate --chain evm --ends-with dead", "EVM: hex, any case");
    step("keyrx grind --chain evm --ends-with dead", "0x...dead, MetaMask/Rabby");
    step("keyrx bench --chain evm", "the EVM rate, saved");
    step("keyrx show evm/dead --keys", "the 0x hex private key");
    step("keyrx networks", "add a network: Robinhood");
    step("keyrx show", "every match file");
    step("keyrx show KEYRX --keys", "one file, keys revealed");
    step("keyrx --update", "latest, then this screen");
    blank();
    println!("{}", ui::warn_line("import and verify the address BEFORE funding."));
    println!("{}", ui::warn_line("the match file holds seed and keys. Treat it like a key - it is one."));
    println!("{}", ui::bot("keyrx <command> --help · keyrx.tech · MIT"));
    println!();
}

fn cmd_donate() {
    ui::masthead("donate");
    println!("{}", ui::top("DONATE", "optional, and it changes nothing"));
    println!("{}", ui::note("keyRX is MIT and stays that way. No paid tier, no hosted version"));
    println!("{}", ui::note("waiting behind it, no feature held back. Nothing is gated on this."));
    println!("{}", ui::mid(""));
    println!("{}", ui::mid(&format!("  {}{}Solana{}", ui::b(), ui::wht(), ui::r())));
    #[allow(clippy::const_is_empty)]   // empty until the vanity grind lands
    if DONATE_SOL.is_empty() {
        println!("{}", ui::note("address not set yet - it will be a keyRX vanity address, ground"));
        println!("{}", ui::note("with this tool. Check keyrx.tech."));
    } else {
        println!("{}", ui::mid(&format!("  {}{}{}", ui::warn(), DONATE_SOL, ui::r())));
        // The same wallet, by name: keyrx.sol resolves to DONATE_SOL (the domain is owned by
        // that wallet and carries no SOL record, so it pays the owner). The address stays the
        // thing to read; the name is a convenience a reader can check for themselves.
        println!("{}", ui::mid(&format!("  {}keyrx.sol{}  {}the same address, by name{}", ui::wht(), ui::r(), ui::gry(), ui::r())));
    }
    #[allow(clippy::const_is_empty)]   // empty until the EVM vanity grind lands
    if !DONATE_EVM.is_empty() {
        println!("{}", ui::mid(""));
        println!("{}", ui::mid(&format!("  {}{}EVM{}  {}Ethereum, Base, Arbitrum, Polygon, BNB... one address for all{}", ui::b(), ui::wht(), ui::r(), ui::gry(), ui::r())));
        println!("{}", ui::mid(&format!("  {}{}{}", ui::warn(), DONATE_EVM, ui::r())));
        // keyrx.eth (ENS, every EVM chain), keyrx.base.eth (Base), keyrx.hoodfi.eth (Robinhood
        // Chain): all resolve to the address above. Same rule: aliases of the address.
        println!("{}", ui::mid(&format!("  {}keyrx.eth   keyrx.base.eth   keyrx.hoodfi.eth{}  {}the same address, by name{}", ui::wht(), ui::r(), ui::gry(), ui::r())));
    }
    println!("{}", ui::mid(""));
    println!("{}", ui::note("If you got more out of this than it cost you to read the source,"));
    println!("{}", ui::note("that trade already worked. Chip in a Sol or two, or some ETH, if"));
    println!("{}", ui::note("you like. It buys nothing - no tier, no badge, no priority - which"));
    println!("{}", ui::note("is what makes it a donation and not a purchase."));
    println!("{}", ui::mid(""));
    println!("{}", ui::mid(&format!("  {}{}There will be no keyRX token from the developer of keyRX.{}", ui::b(), ui::wht(), ui::r())));
    println!("{}", ui::note("No presale. No airdrop. No community round. No Phase 3."));
    println!("{}", ui::mid(""));
    println!("{}", ui::note("You can launch one - someone always does. The ask: creator fees"));
    println!("{}", ui::note("plus 3% of supply to the address above, and the token's socials"));
    println!("{}", ui::note("pointed at @keyrx_tech and keyrx.tech - the only two places this"));
    println!("{}", ui::note("project exists. What you may not do is LARP as this project while"));
    println!("{}", ui::note("you do it: no \"official\", no borrowed name, no invented team."));
    println!("{}", ui::mid(""));
    println!("{}", ui::mid(&format!("  {}{}X is the only place keyRX exists.{}", ui::b(), ui::wht(), ui::r())));
    println!("{}", ui::note("No Discord, no Telegram, no Reddit, no group chat, no \"community\"."));
    println!("{}", ui::note("If something calls itself keyRX anywhere other than @keyrx_tech or"));
    println!("{}", ui::note("keyrx.tech, it is not us."));
    println!("{}", ui::bot("a listing is not an endorsement · DYOR"));
    println!();
}

/// `keyrx networks`: how to add an EVM network to a wallet, and the values for the ones
/// wallets do not ship with. Framed for reading; then each value bare on its own line,
/// outside the frame, because a value copied out of a framed row comes with border
/// glyphs and padding in it - the same rule the keys follow.
fn cmd_networks() {
    ui::masthead("networks");
    println!("{}", ui::top("ADD A NETWORK", "the same address on every EVM chain; some you add once"));
    println!("{}", ui::note("MetaMask and Rabby ship the big chains. For any other EVM chain you add"));
    println!("{}", ui::note("the network once; the ACCOUNT does not change - same 0x address, same"));
    println!("{}", ui::note("key - only the network you are looking at."));
    println!("{}", ui::mid(""));
    println!("{}", ui::kv("MetaMask", "network selector (top left) -> Add a custom network ->"));
    println!("{}", ui::kv("", "fill the five fields below -> Save -> select it"));
    println!("{}", ui::kv("Rabby", "More -> Add Custom Network -> the same fields"));
    println!("{}", ui::bot("values bare below the frame, one per line, for pasting"));
    for n in NETWORKS {
        println!("{}", ui::top(n.name, n.what));
        println!("{}", ui::kv("name", n.name));
        println!("{}", ui::kv("RPC URL", &ui::link(n.rpc, n.rpc)));
        println!("{}", ui::kv("chain ID", &n.chain_id.to_string()));
        println!("{}", ui::kv("currency", n.symbol));
        println!("{}", ui::kv("explorer", &format!("{}  ({})", ui::link(n.explorer, n.explorer), n.explorer_note)));
        println!("{}", ui::bot(&format!("chain id checked against the live RPC on {}", n.checked)));
        for (label, value) in [("network name", n.name.to_string()), ("RPC URL", n.rpc.to_string()),
                               ("chain ID", n.chain_id.to_string()), ("currency symbol", n.symbol.to_string()),
                               ("block explorer", n.explorer.to_string())] {
            println!(" {}{}{}", ui::gry(), label, ui::r());
            println!("{}", value);
        }
    }
    println!();
}

/// The BIP39 specification's first English test vector, with its passphrase.
const BIP39_VECTOR_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
fn bip39_passphrase_vector_holds() -> bool {
    let mn = bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    let seed = mn.to_seed("TREZOR");
    let hex: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
    mn.to_string() == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" && hex == BIP39_VECTOR_SEED
}

fn cmd_verify() {
    ui::masthead("verify");
    println!("{}", ui::top("SELF-TEST", "run this before trusting a result"));
    let mut buf = [0u8; 16];
    let mut pk = [0u8; 32];
    for i in 0..50_000 {
        OsRng.fill_bytes(&mut pk);
        let full = bs58::encode(pk).into_string();
        for n in 1..=10usize {
            if full.len() < n {
                continue;
            }
            b58_suffix(&pk, n, &mut buf);
            if buf[..n] != full.as_bytes()[full.len() - n..] {
                println!("{}", ui::crit_line(&format!("b58_suffix MISMATCH iter={} n={}", i, n)));
                println!("{}", ui::bot("STOP"));
                std::process::exit(1);
            }
        }
    }
    println!("{}", ui::ok_line("b58_suffix vs full encoding   50,000 pubkeys x 10 lengths"));

    let mn = bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap();
    let seed = mn.to_seed("");
    let run = || {
        let (k, c) = master_key(&seed);
        let (k, c) = derive_hardened(&k, &c, 44);
        let (k, c) = derive_hardened(&k, &c, 501);
        let (k, c) = derive_hardened(&k, &c, 0);
        let (kf, _) = derive_hardened(&k, &c, 0);
        bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string()
    };
    let addr = run();
    if addr != run() {
        println!("{}", ui::crit_line("derivation NOT deterministic"));
        println!("{}", ui::bot("STOP"));
        std::process::exit(1);
    }
    println!("{}", ui::ok_line("derivation deterministic"));
    // BIP39 with a passphrase: the specification's own first test vector
    // (entropy 0x00 x16 = "abandon ... about", passphrase "TREZOR"). If the
    // seed for it ever moves, --passphrase would be deriving the wrong tree.
    if bip39_passphrase_vector_holds() {
        println!("{}", ui::ok_line("BIP39 passphrase matches the spec vector  (\"TREZOR\", pinned)"));
    } else {
        println!("{}", ui::crit_line("BIP39 passphrase seed DOES NOT match the specification vector"));
        println!("{}", ui::bot("STOP"));
        std::process::exit(1);
    }
    // The pinned solana-keygen answer for this public test entropy - checked
    // by hand on 2026-08-16 and locked as a test. If it ever moves, STOP.
    const XCHECK: &str = "8zzKEAB4VqnUchbsmAor9QzyVWVQFanQGJYQw8UQPh1j";
    if addr == XCHECK {
        println!("{}", ui::ok_line("SLIP-0010 matches solana-keygen  (pinned cross-check)"));
    } else {
        println!("{}", ui::crit_line("SLIP-0010 does NOT match the pinned solana-keygen answer"));
    }
    println!("{}", ui::bot(if addr == XCHECK { "all green" } else { "STOP - do not fund anything from this build" }));

    // EVM: every pinned answer - the published mnemonic, the independent reference for
    // this tool's own test seed, EIP-55's examples, private key 1 - and the walk.
    println!("{}", ui::top("SELF-TEST · EVM", "secp256k1 · BIP32 · keccak · EIP-55"));
    let mut evm_ok = true;
    for (what, ok) in evm::self_test() {
        evm_ok &= ok;
        println!("{}", if ok { ui::ok_line(&what) } else { ui::crit_line(&format!("{}  - DOES NOT HOLD", what)) });
    }
    println!("{}", ui::bot(if evm_ok { "all green" } else { "STOP - do not fund anything from this build" }));

    println!("{}", ui::top("MANUAL CROSS-CHECK", "one command, once per machine"));
    println!("{}", ui::note("Nothing automated can prove SLIP-0010 matches what wallets do."));
    println!("{}", ui::note("A wrong build grinds normally and prints an address no wallet"));
    println!("{}", ui::note("can derive. Confirm once with Solana's own tool:"));
    println!("{}", ui::mid(""));
    println!("{}", ui::kv("test seed", "(throwaway, public constant, never fund it)"));
    // Never clip a seed word: a truncated word is a wrong word. Eight per row
    // fits the frame at the longest BIP39 word length.
    let words: Vec<&str> = mn.words().collect();
    for chunk in words.chunks(8) {
        println!("{}", ui::mid(&format!("    {}{}{}", ui::wht(), chunk.join(" "), ui::r())));
    }
    println!("{}", ui::mid(""));
    println!("{}", ui::kv("this build", &addr));
    println!("{}", ui::kv("path", "m/44'/501'/0'/0'"));
    println!("{}", ui::mid(""));
    println!("{}", ui::note("run:  solana-keygen pubkey \"prompt://?full-path=m/44'/501'/0'/0'\""));
    println!("{}", ui::note("      paste the seed, empty passphrase - the two addresses must match"));
    println!("{}", ui::note("      (a --passphrase grind: type the same passphrase at its prompt)"));
    println!("{}", ui::mid(""));
    println!("{}", ui::kv("EVM", "the same seed at m/44'/60'/0'/0/0, throwaway wallet:"));
    println!("{}", ui::kv("this build", evm::TEST_SEED_ACCOUNTS[0].1));
    println!("{}", ui::note("run:  cast wallet address --mnemonic \"<the seed above>\" --mnemonic-index 0"));
    println!("{}", ui::note("      or import the seed in a fresh MetaMask: account 1 must show it"));
    println!("{}", ui::bot("if they differ, STOP"));
    println!();
}

/// The pattern line, per chain: `*KEYRX` / `Key*` for Solana; `*dead` / `0xdead*`
/// for EVM, with what the case means on that chain.
fn pattern_line(m: &Matcher, p: &PatternArgs) -> String {
    let pats: Vec<String> = match m.chain {
        Chain::Sol => m.suffixes.iter().map(|s| format!("*{}", String::from_utf8_lossy(s)))
            .chain(m.prefixes.iter().map(|s| format!("{}*", String::from_utf8_lossy(s)))).collect(),
        Chain::Evm => m.suffixes.iter().map(|s| format!("*{}", String::from_utf8_lossy(s)))
            .chain(m.prefixes.iter().map(|s| format!("0x{}*", String::from_utf8_lossy(s)))).collect(),
    };
    let case = match (m.chain, p.ignore_case, p.checksum) {
        (Chain::Sol, true, _) => "   (case-insensitive)",
        (Chain::Sol, false, _) => "",
        (Chain::Evm, _, true) => "   (EVM · letters in EIP-55 case)",
        (Chain::Evm, _, false) => "   (EVM · any case)",
    };
    format!("{}{}", pats.join("  "), case)
}

fn cmd_estimate(p: PatternArgs, threads: usize, indices: u32, count: usize) {
    let m = match Matcher::new(&p) {
        Ok(m) => m,
        Err(e) => { eprintln!("error: {}", e); std::process::exit(1); }
    };
    let chain = p.chain;
    let prob = m.probability();
    let measured = load_rate(chain);
    let bench_cmd = match chain { Chain::Sol => "keyrx bench", Chain::Evm => "keyrx bench --chain evm" };
    let (rate, basis) = match measured {
        Some((mt, mi, mr)) => (scale_rate(chain, mr, mt, mi, threads, indices),
                               format!("measured here ({} threads, {} idx), scaled", mt, mi)),
        None => (model_rate(chain, indices) * threads as f64, format!("THEORETICAL - run `{}` first", bench_cmd)),
    };
    ui::masthead("estimate");
    println!("{}", ui::top("ODDS", "before you grind"));
    println!("{}", ui::kv("pattern", &pattern_line(&m, &p)));
    println!("{}", ui::kv("odds", &format!("1 in {}", group(1.0 / prob))));
    println!("{}", ui::kv("rate", &format!("{}/sec  ({} threads, {} indices/mnemonic{})", group(rate), threads, indices,
        if chain == Chain::Evm { " · secp256k1" } else { "" })));
    println!("{}", if measured.is_some() { ui::note(&format!("basis      {}", basis)) }
                   else { ui::warn_line(&format!("basis    {}", basis)) });
    println!("{}", ui::mid(""));
    println!("{}", ui::note("time to first match"));
    quantiles(prob, rate);
    if count > 1 {
        println!("{}", ui::mid(""));
        println!("{}", ui::note(&format!("time to all {} matches  (grind --count {} - each one is independent)", count, count)));
        quantiles_n(prob, rate, count);
    }
    println!("{}", ui::bot(if measured.is_some() { "from this machine's own bench" } else { match chain {
        Chain::Sol => "theoretical - ran 2.6x optimistic on real hardware",
        Chain::Evm => "theoretical - anchored to one measured machine; bench yours",
    } }));

    // The levers, as numbers.
    let mut levers: Vec<String> = Vec::new();
    let has_letters = m.suffixes.iter().chain(m.prefixes.iter()).any(|s| s.iter().any(|c| c.is_ascii_alphabetic()));
    if chain == Chain::Sol && !p.ignore_case && has_letters {
        let ic = PatternArgs { ignore_case: true, ..p.clone() };
        if let Ok(mi) = Matcher::new(&ic) {
            let k = mi.probability() / prob;
            if k > 1.5 {
                levers.push(format!("--ignore-case   {:.0}x more likely - 1 in {}, 50% in ~{}",
                    k, group(1.0 / mi.probability()),
                    fmt_dur((0.5f64).ln() / (1.0 - mi.probability()).ln() / rate)));
            }
        }
    }
    if chain == Chain::Evm && has_letters {
        // the other way round on EVM: any case is the default, and --checksum is the
        // rarer ask - say what it costs, or what dropping it would give back
        let other = PatternArgs { checksum: !p.checksum, ignore_case: false, ..p.clone() };
        if let Ok(mo) = Matcher::new(&other) {
            let k = mo.probability() / prob;
            if p.checksum {
                levers.push(format!("without --checksum   {:.0}x more likely - 1 in {}, 50% in ~{}",
                    k, group(1.0 / mo.probability()), fmt_dur((0.5f64).ln() / (1.0 - mo.probability()).ln() / rate)));
            } else {
                levers.push(format!("--checksum   EIP-55 case too - 1 in {}, 50% in ~{}",
                    group(1.0 / mo.probability()), fmt_dur((0.5f64).ln() / (1.0 - mo.probability()).ln() / rate)));
            }
        }
    }
    if indices < 128 {
        let r2 = match measured {
            Some((mt, mi, mr)) => scale_rate(chain, mr, mt, mi, threads, 128),
            None => model_rate(chain, 128) * threads as f64,
        };
        if r2 / rate > 1.05 {
            levers.push(format!("--indices 128   ~{:.1}x the rate - match lands at a higher account index", r2 / rate));
        }
    }
    if !levers.is_empty() {
        println!("{}", ui::top("LEVERS", "what the flags would buy"));
        for l in levers { println!("{}", ui::note(&l)); }
        println!("{}", ui::bot(""));
    }
    println!();
}

fn cmd_bench(chain: Chain, threads: usize, indices: u32, seconds: u64) {
    ui::masthead("bench");
    println!("{}", ui::top("BENCH", &format!("{}{} threads · {} indices/mnemonic · {}s",
        if chain == Chain::Evm { "EVM · " } else { "" }, threads, indices, seconds)));
    println!("{}", ui::note("grinding a pattern that cannot match, counting candidates..."));
    let _ = std::io::stdout().flush();
    let p = PatternArgs {
        ends_with: vec![match chain { Chain::Sol => "zzzzzzzz".into(), Chain::Evm => "ffffffffffffffff".into() }],
        starts_with: vec![],
        ignore_case: false,
        path: PathStyle::Phantom,
        chain,
        checksum: false,
    };
    let m = Arc::new(Matcher::new(&p).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    std::thread::scope(|s| {
        for _ in 0..threads {
            let (m, stop, counter) = (Arc::clone(&m), Arc::clone(&stop), Arc::clone(&counter));
            s.spawn(move || match chain {
                Chain::Sol => grind_loop(&m, PathStyle::Phantom, indices, 32, "", &stop, &counter, &|_| {}),
                Chain::Evm => grind_loop_evm(&m, indices, 32, "", &stop, &counter, &|_| {}),
            });
        }
        std::thread::sleep(Duration::from_secs(seconds));
        stop.store(true, Ordering::SeqCst);
    });

    let n = counter.load(Ordering::Relaxed);
    let secs = start.elapsed().as_secs_f64();
    let rate = n as f64 / secs;
    println!("{}", ui::mid(""));
    println!("{}", ui::kv("candidates", &format!("{} in {:.1}s", group(n as f64), secs)));
    println!("{}", ui::kv_accent("rate", &format!("{}/sec total · {}/sec/thread", group(rate), group(rate / threads as f64))));
    match chain {
        Chain::Sol => {
            let x = rate / 13_600.0;
            println!("{}", ui::kv("baseline", &format!("{:.1}x the 13,600/sec of solana-keygen grind", x)));
            println!("{}", ui::mid(&format!("  {}{:<11}{}{}", ui::gry(), "", ui::r(), ui::bar((x / 40.0 * 100.0).min(100.0), 40))));
            println!("{}", ui::mid(""));
            println!("{}", ui::note("time to first 5-char suffix (1 in 656,356,768)"));
            quantiles(1.0 / 656_356_768.0, rate);
        }
        Chain::Evm => {
            // no baseline claim here: nothing measured to compare against yet
            println!("{}", ui::mid(""));
            println!("{}", ui::note("time to first 6-hex suffix, any case (1 in 16,777,216)"));
            quantiles(1.0 / 16_777_216.0, rate);
            println!("{}", ui::mid(""));
            println!("{}", ui::note("time to first 8-hex suffix, any case (1 in 4,294,967,296)"));
            quantiles(1.0 / 4_294_967_296.0, rate);
        }
    }
    save_rate(chain, threads, indices, rate);
    println!("{}", ui::bot(&format!("saved for estimate -> {}", rate_cache_path(chain).display())));
    println!();
}

/// Ask for the BIP39 passphrase on the terminal, hidden, twice. Empty is
/// refused (that is the default, and asking for it would only confuse the
/// file's "passphrase used" line); a mismatch asks again.
fn ask_passphrase() -> Zeroizing<String> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        eprintln!("--passphrase needs a terminal to type it into (it is never read from a file, a flag, or the environment)");
        std::process::exit(1);
    }
    println!();
    println!("{}", ui::top("PASSPHRASE", "BIP39, the \"25th word\""));
    println!("{}", ui::note("Typed twice, hidden. Never stored, never printed, never in the match file."));
    println!("{}", ui::note("The seed alone will NOT reach the address without it - the keys will."));
    println!("{}", ui::note("Most browser wallets have no passphrase field: import the KEY."));
    println!("{}", ui::bot("lose the passphrase and the seed is just twelve words"));
    loop {
        let a = match rpassword::prompt_password("  passphrase: ") {
            Ok(v) => Zeroizing::new(v),
            Err(e) => { eprintln!("could not read the passphrase: {}", e); std::process::exit(1); }
        };
        if a.is_empty() { println!("{}", ui::warn_line("empty - run without --passphrase for the standard, passphrase-free seed")); continue; }
        let b = match rpassword::prompt_password("  again:      ") {
            Ok(v) => Zeroizing::new(v),
            Err(e) => { eprintln!("could not read the passphrase: {}", e); std::process::exit(1); }
        };
        if *a != *b { println!("{}", ui::warn_line("they differ - again")); continue; }
        return a;
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_grind(
    p: PatternArgs, threads: usize, indices: u32, count: usize,
    words: usize, out: String, show_seed: bool, with_passphrase: bool,
) {
    let entropy_len = match words {
        12 => 16,
        24 => 32,
        _ => { eprintln!("--words must be 12 or 24"); std::process::exit(1); }
    };
    let m = match Matcher::new(&p) {
        Ok(m) => m,
        Err(e) => { eprintln!("error: {}", e); std::process::exit(1); }
    };
    let chain = p.chain;
    if m.needs_full && chain == Chain::Sol {
        eprintln!("note: prefix matching needs full base58 per candidate (slower than suffix)");
    }
    if indices > 16 && chain == Chain::Sol {
        eprintln!("note: --indices {} - the match may land at account index up to {}.", indices, indices - 1);
        eprintln!("      Fine for Solflare (custom path). Phantom needs that many 'add account'");
        eprintln!("      clicks; use --indices 8 if Phantom is the target.");
    }

    let prob = m.probability();
    let style = p.path;
    let m = Arc::new(m);
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    {
        let stop = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || {
            eprintln!("\ninterrupted -- finishing current batch");
            stop.store(true, Ordering::SeqCst);
        });
    }

    if let Some(d) = std::path::Path::new(&out).parent() {
        if !d.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(d) {
                eprintln!("cannot create {}: {}", d.display(), e); std::process::exit(1);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
            }
        }
    }
    // A running grind leaves <out>.grinding beside its file so `show` can
    // tell "not landed yet" from "never started" - and wait for the former.
    let lock = format!("{}.grinding", out);
    let _ = std::fs::write(&lock, std::process::id().to_string());
    struct Unlock(String);
    impl Drop for Unlock { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    let _unlock = Unlock(lock.clone());
    // The passphrase, if asked for: typed twice, hidden, held in memory for the
    // grind and zeroed after. Nothing writes it anywhere; the match file only
    // records THAT one was used.
    let passphrase: Arc<Zeroizing<String>> = Arc::new(if with_passphrase { ask_passphrase() } else { Zeroizing::new(String::new()) });
    ui::masthead("grind");
    println!("{}", ui::top("GRIND", "Ctrl-C stops after the current batch"));
    println!("{}", ui::kv("pattern", &pattern_line(&m, &p)));
    println!("{}", ui::kv("odds", &format!("1 in {}", group(1.0 / prob))));
    println!("{}", ui::kv("threads", &format!("{} · {} indices/mnemonic · {}-word seeds{}", threads, indices, words,
        if chain == Chain::Evm { " · m/44'/60'/0'/0/N" } else { "" })));
    println!("{}", ui::kv("matches ->", &format!("{}  (mode 0600)", out_link(&out))));
    println!("{}", ui::kv("stop after", &format!("{} match(es)", count)));
    if with_passphrase { println!("{}", ui::kv("passphrase", "used - not stored; the seed alone will not reach the address")); }
    if ui::links_on() { println!("{}", ui::note(ui::CLICK_HINT)); }
    println!("{}", ui::bot(&format!("in {}", ui::dir_link(&matches_dir()))));
    println!();

    {
        // A live line, not a log: rewritten in place every 2s from the first
        // seconds, so the operator sees rate and ETA immediately instead of
        // staring at nothing for 15s. Falls back to appended lines when
        // stdout is not a terminal (piped/logged runs).
        let (stop, counter) = (Arc::clone(&stop), Arc::clone(&counter));
        let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
        std::thread::spawn(move || {
            let mut tick = 0u64;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                tick += 1;
                if stop.load(Ordering::Relaxed) { break; }
                let every = if tty { 4 } else { 30 };
                if tick % every != 0 { continue; }
                let n = counter.load(Ordering::Relaxed);
                let secs = start.elapsed().as_secs_f64();
                let rate = if secs > 0.0 { n as f64 / secs } else { 0.0 };
                let median_n = (0.5f64).ln() / (1.0 - prob).ln();
                let p90_n = (0.1f64).ln() / (1.0 - prob).ln();
                let done = (n as f64 / median_n * 50.0).min(99.0);
                let left = if rate > 0.0 { median_n / rate - secs } else { f64::INFINITY };
                let left90 = if rate > 0.0 { p90_n / rate - secs } else { f64::INFINITY };
                let line = format!(
                    "  {:>14} tried | {:>8.0}/sec | {} | 50% in {} | 90% in {} | ~{:.0}% of the way to median",
                    n, rate, fmt_dur(secs),
                    if left > 0.0 { fmt_dur(left) } else { "overdue".into() },
                    if left90 > 0.0 { fmt_dur(left90) } else { "overdue".into() },
                    done);
                if tty {
                    print!("\r\x1b[2K{}{}{}", ui::gry(), line, ui::r());
                } else {
                    println!("{}", line);
                }
                let _ = std::io::stdout().flush();
            }
            if tty { print!("\r\x1b[2K"); let _ = std::io::stdout().flush(); }
        });
    }

    std::thread::scope(|s| {
        for _ in 0..threads {
            let (m, stop, counter, hits) =
                (Arc::clone(&m), Arc::clone(&stop), Arc::clone(&counter), Arc::clone(&hits));
            let out = out.clone();
            let pass = Arc::clone(&passphrase);
            s.spawn(move || {
                let on_hit = |h: Hit| {
                    if let Err(e) = write_hit(&out, &h, style) {
                        // Never the terminal. A seed on stdout on the one path
                        // where the operator has lost control of the sink is
                        // the leak this tool exists to avoid. Try a fallback
                        // 0600 file; if that fails too, keep the seed in
                        // memory, say so loudly, and stop.
                        let fb = format!("{}.recovered", out);
                        match write_hit(&fb, &h, style) {
                            Ok(()) => eprintln!("WRITE FAILED ({}) -- wrote {} instead", e, fb),
                            Err(e2) => {
                                eprintln!("WRITE FAILED twice ({}; {}) -- seed NOT written, NOT printed.", e, e2);
                                eprintln!("Fix the output path and re-run; this candidate is lost.");
                                stop.store(true, Ordering::SeqCst);
                                return;
                            }
                        }
                    }
                    print!("\r\x1b[2K");
                    println!("{}", ui::top("MATCH", &fmt_dur(start.elapsed().as_secs_f64())));
                    println!("{}", ui::kv_accent("address", &h.address));
                    println!("{}", ui::kv("path", &path_for(h.chain, style, h.index)));
                    if show_seed {
                        let w: Vec<&str> = h.mnemonic.split_whitespace().collect();
                        let mut first = true;
                        for chunk in w.chunks(8) {
                            println!("{}", ui::mid(&format!("  {}{:<11}{}{}{}{}", ui::gry(),
                                if first { "seed" } else { "" }, ui::r(), ui::wht(), chunk.join(" "), ui::r())));
                            first = false;
                        }
                    } else {
                        println!("{}", ui::kv("seed", &format!("-> {}   (--show-seed to print here)", out_link(&out))));
                    }
                    match h.chain {
                        Chain::Sol => {
                            println!("{}", ui::kv("keys", &format!("-> {}   base58 + JSON array (show --keys)", out_link(&out))));
                            println!("{}", ui::mid(""));
                            println!("{}", ui::note("Key:      Phantom: a wallet must exist first (any seed; it never sees"));
                            println!("{}", ui::note("          this key). Then: menu -> Add/Connect Wallet -> Import Private"));
                            println!("{}", ui::note("          Key -> paste the base58. Solflare: import the JSON keypair."));
                            println!("{}", ui::note("          -> this exact address, standalone, no clicks"));
                        }
                        Chain::Evm => {
                            println!("{}", ui::kv("key", &format!("-> {}   hex private key (show --keys)", out_link(&out))));
                            println!("{}", ui::mid(""));
                            println!("{}", ui::note("Key:      MetaMask/Rabby: a wallet must exist first (any seed; it never"));
                            println!("{}", ui::note("          sees this key). Then: account menu -> Import account ->"));
                            println!("{}", ui::note("          Private key -> paste the 0x hex: this address, every chain"));
                        }
                    }
                    for l in import_hint(h.chain, style, h.index) { println!("{}", ui::note(&l)); }
                    println!("{}", ui::note("the OTHER accounts on this seed are ordinary addresses"));
                    if h.passphrase { println!("{}", ui::warn_line("passphrase used - the seed alone will NOT reach this; the keys will")); }
                    if ui::links_on() { println!("{}", ui::note(ui::CLICK_HINT)); }
                    println!("{}", ui::bot("import and verify the address BEFORE funding"));
                    println!();
                    if hits.fetch_add(1, Ordering::SeqCst) + 1 >= count as u64 {
                        stop.store(true, Ordering::SeqCst);
                    }
                };
                match chain {
                    Chain::Sol => grind_loop(&m, style, indices, entropy_len, pass.as_str(), &stop, &counter, &on_hit),
                    Chain::Evm => grind_loop_evm(&m, indices, entropy_len, pass.as_str(), &stop, &counter, &on_hit),
                }
            });
        }
    });

    let n = hits.load(Ordering::Relaxed);
    print!("\r\x1b[2K");
    println!(" {}stopped · {} match(es) · {} candidates · {}{}",
        ui::gry(), n, group(counter.load(Ordering::Relaxed) as f64),
        fmt_dur(start.elapsed().as_secs_f64()), ui::r());
    if n > 0 {
        let stem = std::path::Path::new(&out).file_stem().map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| out.clone());
        let stem = if chain == Chain::Evm && std::path::Path::new(&out).starts_with(matches_dir_for(Chain::Evm)) { format!("evm/{}", stem) } else { stem };
        println!(" {}keyrx show {}   lists them · --seeds / --keys to reveal{}", ui::gry(), stem, ui::r());
    }
    println!();
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// The site's masthead shows a version; it must be this crate's. `site/` is not
    /// in the published tarball, so the check runs only in the repository - which is
    /// where the publish workflow runs `cargo test` before it publishes anything.
    #[test]
    fn the_site_shows_this_version() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/site/index.html");
        let Ok(site) = std::fs::read_to_string(path) else { return; };
        let want = format!("var VERSION='{}';", env!("CARGO_PKG_VERSION"));
        assert_eq!(site.matches(&want).count(), 1, "site/index.html must carry exactly one `{}`", want);
        assert_eq!(site.matches("masthead('v0.").count(), 0, "the site writes the version in one place only - masthead('v'+VERSION), never a literal");
    }

    /// The address solana-keygen derives for the [7u8; 32] test entropy at
    /// m/44'/501'/0'/0' -- cross-checked by hand on 2026-08-16 (`solana-keygen
    /// pubkey "prompt://?full-path=..."`, empty passphrase). This entropy is a
    /// public constant and the seed is worthless by construction; pinning the
    /// answer turns the one-time manual gate into a permanent regression lock.
    const XCHECK_PHANTOM: &str = "8zzKEAB4VqnUchbsmAor9QzyVWVQFanQGJYQw8UQPh1j";
    /// Same seed at m/44'/501'/0' (legacy style), same cross-check.
    const XCHECK_LEGACY: &str = "2Ju5fiKYKf4oEFdFWsg2M5RgDWpU5fLuBAghcZNjAnKo";

    fn addr_for(style: PathStyle, idx: u32) -> String {
        let mn = bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap();
        let seed = mn.to_seed("");
        let (k, c) = master_key(&seed);
        let (k, c) = derive_hardened(&k, &c, 44);
        let (k, c) = derive_hardened(&k, &c, 501);
        let (k, c) = derive_hardened(&k, &c, idx);
        let kf = match style {
            PathStyle::Phantom => derive_hardened(&k, &c, 0).0,
            PathStyle::Legacy => k,
        };
        bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string()
    }

    #[test]
    fn slip10_matches_solana_keygen_phantom_path() {
        assert_eq!(addr_for(PathStyle::Phantom, 0), XCHECK_PHANTOM);
    }

    #[test]
    fn slip10_matches_solana_keygen_legacy_path() {
        assert_eq!(addr_for(PathStyle::Legacy, 0), XCHECK_LEGACY);
    }

    #[test]
    fn grind_loop_derivation_equals_reference_derivation() {
        // The hot loop's derivation (prefix once, then walk idx) must equal the
        // straight-line derivation for every index it visits -- otherwise the
        // optimisation itself is the silent-wrong-address bug.
        let mn = bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap();
        let seed = Zeroizing::new(mn.to_seed(""));
        let (k, c) = master_key(seed.as_ref());
        let (k2, c2) = derive_hardened(&k, &c, 44);
        let (kp, cp) = derive_hardened(&k2, &c2, 501);
        for idx in 0..8u32 {
            let (ka, ca) = derive_hardened(&kp, &cp, idx);
            let kf = derive_hardened(&ka, &ca, 0).0;
            let fast = bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string();
            assert_eq!(fast, addr_for(PathStyle::Phantom, idx), "index {}", idx);
        }
    }

    #[test]
    fn b58_suffix_matches_full_encoding_50k() {
        let mut buf = [0u8; 16];
        let mut pk = [0u8; 32];
        for _ in 0..50_000 {
            OsRng.fill_bytes(&mut pk);
            let full = bs58::encode(pk).into_string();
            for n in 1..=10usize {
                if full.len() < n { continue; }
                b58_suffix(&pk, n, &mut buf);
                assert_eq!(&buf[..n], &full.as_bytes()[full.len() - n..]);
            }
        }
    }

    #[test]
    fn b58_suffix_handles_leading_zero_bytes() {
        // Leading zero bytes become leading '1's in the FULL string; the suffix
        // arithmetic must be unaffected. Also the all-zero and all-0xff edges.
        let mut buf = [0u8; 16];
        for pk in [[0u8; 32], [0xffu8; 32], {
            let mut p = [0u8; 32]; p[31] = 1; p
        }, {
            let mut p = [0xffu8; 32]; p[0] = 0; p[1] = 0; p
        }] {
            let full = bs58::encode(pk).into_string();
            for n in 1..=8usize {
                if full.len() < n { continue; }
                b58_suffix(&pk, n, &mut buf);
                assert_eq!(&buf[..n], &full.as_bytes()[full.len() - n..], "pk={:?} n={}", &pk[..4], n);
            }
        }
    }

    fn pat(ends: &[&str], starts: &[&str], ic: bool) -> PatternArgs {
        PatternArgs {
            ends_with: ends.iter().map(|s| s.to_string()).collect(),
            starts_with: starts.iter().map(|s| s.to_string()).collect(),
            ignore_case: ic,
            path: PathStyle::Phantom,
            chain: Chain::Sol,
            checksum: false,
        }
    }

    #[test]
    fn probability_plain_5_char_suffix() {
        let m = Matcher::new(&pat(&["abcde"], &[], false)).unwrap();
        let want = 1.0 / 58f64.powi(5);
        assert!((m.probability() - want).abs() < want * 1e-12);
    }

    #[test]
    fn probability_case_insensitive_gauge_is_32_over_58_pow_5() {
        // G,A,U,G,E each have two cases in base58 (none of them are o/i/L,
        // the letters that lost a case) -> 2^5 = 32 variants.
        let m = Matcher::new(&pat(&["GAUGE"], &[], true)).unwrap();
        let want = 32.0 / 58f64.powi(5);
        assert!((m.probability() - want).abs() < want * 1e-12, "{}", m.probability());
    }

    #[test]
    fn probability_case_insensitive_respects_single_case_letters() {
        // 'l' has no upper case in base58 (L exists, l does not) -> 1 variant;
        // 'o' likewise (O excluded). "lo" case-insensitive = 1*1 / 58^2... but
        // wait: 'l' is excluded and 'L' allowed; 'o' allowed and 'O' excluded.
        // So a pattern containing L matches only L; containing o matches only o.
        let m = Matcher::new(&pat(&["Lo"], &[], true)).unwrap();
        let want = 1.0 / 58f64.powi(2);
        assert!((m.probability() - want).abs() < want * 1e-12, "{}", m.probability());
    }

    #[test]
    fn matcher_rejects_non_base58_and_empty() {
        assert!(Matcher::new(&pat(&["0"], &[], false)).is_err());
        assert!(Matcher::new(&pat(&["O"], &[], false)).is_err());
        assert!(Matcher::new(&pat(&["I"], &[], false)).is_err());
        assert!(Matcher::new(&pat(&["l"], &[], false)).is_err());
        assert!(Matcher::new(&pat(&[""], &[], false)).is_err());
        assert!(Matcher::new(&pat(&[], &[], false)).is_err());
        assert!(Matcher::new(&pat(&["a".repeat(17).as_str()], &[], false)).is_err());
    }

    #[test]
    fn privkey_is_the_standard_64_byte_keypair_encoding() {
        // base58(secret32 || pubkey32): decoding must give 64 bytes whose
        // second half is the pubkey of the first half - the exact shape
        // Phantom's Import Private Key and solana-keygen's JSON array carry.
        let secret = [9u8; 32];
        let k = keypair_b58(&secret);
        let bytes = bs58::decode(k.as_str()).into_vec().unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[..32], &secret);
        let pk = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
        assert_eq!(&bytes[32..], &pk);
    }

    #[test]
    fn keypair_json_is_the_same_64_bytes() {
        let secret = [3u8; 32];
        let j = keypair_json(&secret);
        assert!(j.starts_with('[') && j.ends_with(']'));
        let bytes: Vec<u8> = j.trim_matches(&['[', ']'][..]).split(',')
            .map(|x| x.parse::<u8>().unwrap()).collect();
        assert_eq!(bytes.len(), 64);
        let b58 = bs58::decode(keypair_b58(&secret).as_str()).into_vec().unwrap();
        assert_eq!(bytes, b58, "JSON array and base58 must be the same bytes");
    }

    #[test]
    fn hit_privkey_matches_hit_address() {
        // End to end on a 2-char grind: the key written for a hit must
        // decode to a keypair whose public half IS the hit's address.
        let m = Matcher::new(&pat(&["ab"], &[], false)).unwrap();
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let found = std::sync::Mutex::new(None);
        grind_loop(&m, PathStyle::Phantom, 64, 16, "", &stop, &counter, &|h| {
            *found.lock().unwrap() = Some((h.address.clone(), h.privkey.to_string()));
            stop.store(true, Ordering::SeqCst);
        });
        let (addr, key) = found.into_inner().unwrap().expect("no hit");
        let bytes = bs58::decode(&key).into_vec().unwrap();
        assert_eq!(bytes.len(), 64);
        let pk = bs58::encode(&bytes[32..]).into_string();
        assert_eq!(pk, addr, "privkey's public half is not the hit address");
        let mut s = [0u8; 32]; s.copy_from_slice(&bytes[..32]);
        let re = bs58::encode(SigningKey::from_bytes(&s).verifying_key().to_bytes()).into_string();
        assert_eq!(re, addr, "secret half does not re-derive the address");
    }

    fn pat_evm(ends: &[&str], starts: &[&str], checksum: bool) -> PatternArgs {
        PatternArgs { chain: Chain::Evm, checksum, ..pat(ends, starts, false) }
    }

    #[test]
    fn evm_matcher_takes_hex_in_any_case_and_refuses_the_rest() {
        let m = Matcher::new(&pat_evm(&["DeAd"], &["0xC0ffee"], false)).unwrap();
        assert_eq!(m.suffixes, vec![b"dead".to_vec()], "stored lowercase: any case matches");
        assert_eq!(m.prefixes, vec![b"c0ffee".to_vec()], "0x dropped, lowercase");
        assert!(Matcher::new(&pat_evm(&["keyrx"], &[], false)).is_err(), "not hex");
        assert!(Matcher::new(&pat_evm(&["0xdead"], &[], false)).is_err(), "0x on a suffix");
        assert!(Matcher::new(&pat_evm(&[], &[], false)).is_err());
        assert!(Matcher::new(&PatternArgs { ignore_case: true, ..pat_evm(&["dead"], &[], true) }).is_err(), "checksum + ignore-case");
        assert!(Matcher::new(&PatternArgs { checksum: true, ..pat(&["KEYRX"], &[], false) }).is_err(), "checksum on sol");
        let c = Matcher::new(&pat_evm(&["DeAd"], &[], true)).unwrap();
        assert_eq!(c.suffixes, vec![b"DeAd".to_vec()], "checksum keeps the typed case");
    }

    #[test]
    fn evm_probability_is_sixteen_per_digit_and_two_per_letter_with_checksum() {
        let m = Matcher::new(&pat_evm(&["dead"], &[], false)).unwrap();
        let want = 1.0 / 16f64.powi(4);
        assert!((m.probability() - want).abs() < want * 1e-12);
        let c = Matcher::new(&pat_evm(&["dead"], &[], true)).unwrap();
        let want = 1.0 / 16f64.powi(4) / 2f64.powi(4);   // d, e, a, d: four letters
        assert!((c.probability() - want).abs() < want * 1e-12);
        let digits = Matcher::new(&pat_evm(&["1234"], &[], true)).unwrap();
        assert!((digits.probability() - 1.0 / 16f64.powi(4)).abs() < 1e-18, "digits have no case to match");
        let both = Matcher::new(&pat_evm(&["ab"], &["cd"], false)).unwrap();
        assert!((both.probability() - 2.0 / 256.0).abs() < 1e-15);
    }

    #[test]
    fn evm_hit_checks_any_case_then_eip55_when_asked() {
        // EIP-55 example 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed: ends "BeAed"
        let want = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let mut a = [0u8; 20];
        for i in 0..20 { a[i] = u8::from_str_radix(&want[2 + 2 * i..4 + 2 * i], 16).unwrap(); }
        let mut lower = [0u8; 40];
        evm::hex40(&a, &mut lower);
        assert!(Matcher::new(&pat_evm(&["beaed"], &[], false)).unwrap().evm_hit(&lower, &a));
        assert!(Matcher::new(&pat_evm(&["BEAED"], &[], false)).unwrap().evm_hit(&lower, &a), "any case without --checksum");
        assert!(Matcher::new(&pat_evm(&["BeAed"], &[], true)).unwrap().evm_hit(&lower, &a), "the real casing");
        assert!(!Matcher::new(&pat_evm(&["beaed"], &[], true)).unwrap().evm_hit(&lower, &a), "wrong casing under --checksum");
        assert!(Matcher::new(&pat_evm(&[], &["0x5aAeb6"], true)).unwrap().evm_hit(&lower, &a));
        assert!(!Matcher::new(&pat_evm(&[], &["0x5AAEB6"], true)).unwrap().evm_hit(&lower, &a));
        assert!(!Matcher::new(&pat_evm(&["dead"], &[], false)).unwrap().evm_hit(&lower, &a));
    }

    #[test]
    fn evm_default_out_lives_under_matches_evm() {
        let d = default_out(&pat_evm(&["DEAD"], &[], false));
        assert!(d.ends_with("/matches/evm/dead.txt"), "{}", d);
        let d = default_out(&pat_evm(&["DeAd"], &["0xC0ffee"], true));
        assert!(d.ends_with("/matches/evm/DeAd+C0ffee_.cs.txt"), "{}", d);
    }

    #[test]
    fn evm_grind_finds_a_hit_that_rederives_and_writes_four_lines() {
        // One hex digit: nothing valuable is ever generated. The hit must re-derive
        // from its own mnemonic at the stated index, its key must be the address's,
        // and the file must carry four lines and no keypair.
        let m = Matcher::new(&pat_evm(&["a"], &[], false)).unwrap();
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let found = std::sync::Mutex::new(None);
        grind_loop_evm(&m, 16, 16, "", &stop, &counter, &|h| {
            *found.lock().unwrap() = Some(h);
            stop.store(true, Ordering::SeqCst);
        });
        let h = found.into_inner().unwrap().expect("no hit");
        assert_eq!(h.chain, Chain::Evm);
        assert!(h.address.starts_with("0x") && h.address.len() == 42, "{}", h.address);
        assert!(h.address.to_ascii_lowercase().ends_with('a'));
        let seed = bip39::Mnemonic::parse_normalized(&h.mnemonic).unwrap().to_seed("");
        let b = evm::Branch::from_seed(&seed).unwrap();
        let k = b.key_at(h.index).unwrap();
        assert_eq!(evm::eip55(&evm::address_of(&k)), h.address, "hit does not re-derive from its own mnemonic");
        assert_eq!(evm::privkey_hex(&k).as_str(), h.privkey.as_str(), "the written key is not the address's key");
        assert!(h.keypair_json.is_empty());
        let dir = std::env::temp_dir().join(format!("keyrx-evm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("a.txt");
        write_hit(out.to_str().unwrap(), &h, PathStyle::Phantom).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(text.starts_with(&format!("address {}\npath    m/44'/60'/0'/0/{}\nseed    ", h.address, h.index)), "{}", text);
        assert!(text.contains(&format!("\nprivkey {}\n", h.privkey.as_str())));
        assert!(!text.contains("keypair"), "EVM has one key form");
        assert_eq!(text.lines().filter(|l| !l.is_empty()).count(), 4);
    }

    #[test]
    fn evm_checksum_grind_hit_carries_the_typed_case() {
        let m = Matcher::new(&pat_evm(&["A"], &[], true)).unwrap();
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let found = std::sync::Mutex::new(None);
        grind_loop_evm(&m, 16, 16, "", &stop, &counter, &|h| {
            *found.lock().unwrap() = Some(h.address.clone());
            stop.store(true, Ordering::SeqCst);
        });
        let addr = found.into_inner().unwrap().expect("no hit");
        assert!(addr.ends_with('A'), "EIP-55 case must be the typed one: {}", addr);
    }

    #[test]
    fn the_network_table_is_well_formed() {
        // one entry per chain id, https everywhere, and the one chain we ship is the one checked
        let mut ids: Vec<u64> = NETWORKS.iter().map(|n| n.chain_id).collect();
        ids.sort(); ids.dedup();
        assert_eq!(ids.len(), NETWORKS.len());
        for n in NETWORKS {
            assert!(n.rpc.starts_with("https://") && n.explorer.starts_with("https://"), "{}", n.name);
            assert!(!n.name.is_empty() && !n.symbol.is_empty() && !n.checked.is_empty());
        }
        let rh = NETWORKS.iter().find(|n| n.name == "Robinhood Chain").expect("Robinhood Chain");
        assert_eq!(rh.chain_id, 4663);
        assert_eq!(rh.rpc, "https://rpc.mainnet.chain.robinhood.com");
    }

    #[test]
    fn the_evm_self_test_is_green() {
        for (what, ok) in evm::self_test() { assert!(ok, "{}", what); }
    }

    #[test]
    fn default_out_names_the_file_after_the_pattern() {
        let d = default_out(&pat(&["KEYRX"], &[], false));
        assert!(d.ends_with("/matches/KEYRX.txt"), "{}", d);
        let d = default_out(&pat(&["KEYRX"], &["Ab"], true));
        assert!(d.ends_with("/matches/KEYRX+Ab_.ic.txt"), "{}", d);
    }

    #[test]
    fn grind_finds_a_two_char_suffix_and_the_hit_derives() {
        // Two-character target only: nothing valuable is ever generated.
        // The hit's address must re-derive from its own mnemonic at the
        // stated path -- the end-to-end promise, checked in-process.
        let m = Matcher::new(&pat(&["ab"], &[], false)).unwrap();
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let found = std::sync::Mutex::new(None);
        grind_loop(&m, PathStyle::Phantom, 64, 32, "", &stop, &counter, &|h| {
            *found.lock().unwrap() = Some((h.index, h.address.clone(), h.mnemonic.to_string()));
            stop.store(true, Ordering::SeqCst);
        });
        let (idx, addr, mn) = found.into_inner().unwrap().expect("no hit");
        assert!(addr.ends_with("ab"), "{}", addr);
        let mnemonic = bip39::Mnemonic::parse_normalized(&mn).unwrap();
        let seed = mnemonic.to_seed("");
        let (k, c) = master_key(&seed);
        let (k, c) = derive_hardened(&k, &c, 44);
        let (k, c) = derive_hardened(&k, &c, 501);
        let (k, c) = derive_hardened(&k, &c, idx);
        let kf = derive_hardened(&k, &c, 0).0;
        let re = bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string();
        assert_eq!(re, addr, "hit does not re-derive from its own mnemonic");
    }

    #[test]
    fn the_bip39_passphrase_vector_holds_and_a_passphrase_changes_the_tree() {
        assert!(bip39_passphrase_vector_holds());
        let mn = bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap();
        let addr_for = |pass: &str| {
            let seed = mn.to_seed(pass);
            let (k, c) = master_key(&seed);
            let (k, c) = derive_hardened(&k, &c, 44);
            let (k, c) = derive_hardened(&k, &c, 501);
            let (k, c) = derive_hardened(&k, &c, 0);
            let kf = derive_hardened(&k, &c, 0).0;
            bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string()
        };
        assert_eq!(addr_for(""), "8zzKEAB4VqnUchbsmAor9QzyVWVQFanQGJYQw8UQPh1j", "the pinned passphrase-free answer");
        assert_ne!(addr_for("x"), addr_for(""), "a passphrase must change the tree");
        assert_eq!(addr_for("x"), addr_for("x"), "and deterministically");
    }

    #[test]
    fn a_passphrase_grind_derives_with_the_passphrase_and_the_file_says_so() {
        // The loop is handed a passphrase; the hit must re-derive ONLY with it,
        // the Hit must carry the fact, and the match file must record the fact
        // and nothing more - never the passphrase itself.
        let m = Matcher::new(&pat(&["a"], &[], false)).unwrap();
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let found = std::sync::Mutex::new(None);
        grind_loop(&m, PathStyle::Phantom, 64, 16, "correct horse", &stop, &counter, &|h| {
            *found.lock().unwrap() = Some(h);
            stop.store(true, Ordering::SeqCst);
        });
        let h = found.into_inner().unwrap().expect("no hit");
        assert!(h.passphrase);
        let mnemonic = bip39::Mnemonic::parse_normalized(&h.mnemonic).unwrap();
        let addr_for = |pass: &str| {
            let seed = mnemonic.to_seed(pass);
            let (k, c) = master_key(&seed);
            let (k, c) = derive_hardened(&k, &c, 44);
            let (k, c) = derive_hardened(&k, &c, 501);
            let (k, c) = derive_hardened(&k, &c, h.index);
            let kf = derive_hardened(&k, &c, 0).0;
            bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string()
        };
        assert_eq!(addr_for("correct horse"), h.address, "the hit must derive WITH the passphrase");
        assert_ne!(addr_for(""), h.address, "and the seed alone must NOT reach it");
        let dir = std::env::temp_dir().join(format!("keyrx-pass-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("a.txt");
        write_hit(out.to_str().unwrap(), &h, PathStyle::Phantom).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(text.contains("\npassphrase used - NOT stored"), "{}", text);
        assert!(!text.contains("correct horse"), "the passphrase must never be written");
        assert!(text.contains(&format!("address {}", h.address)));
    }
}
