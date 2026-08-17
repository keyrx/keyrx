// keyrx -- Solana vanity address grinder
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
//   keyrx estimate --ends-with MINT
//   keyrx grind --ends-with MINT --indices 128
//   keyrx show MINT --keys

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
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ---------------------------------------------------------------- CLI

#[derive(Parser)]
#[command(name = "keyrx", version, about = "Solana BIP39 vanity address grinder")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Self-test the base58 and derivation code. Run before trusting a result.
    Verify,

    /// Show expected time for a pattern without grinding.
    Estimate {
        #[command(flatten)]
        pattern: PatternArgs,
        #[arg(long, default_value_t = num_threads())]
        threads: usize,
        #[arg(long, default_value_t = 64)]
        indices: u32,
    },

    /// Measure actual throughput on this machine.
    Bench {
        #[arg(long, default_value_t = num_threads())]
        threads: usize,
        #[arg(long, default_value_t = 64)]
        indices: u32,
        #[arg(long, default_value_t = 15)]
        seconds: u64,
    },

    /// List matches - addresses and paths; seeds and keys withheld by default.
    /// With no FILE, lists every match file in the matches directory.
    Show {
        /// A match file, or a bare pattern name (MINT -> matches/MINT.txt).
        file: Option<String>,
        /// Also print the seed phrases. Off by default.
        #[arg(long)]
        seeds: bool,
        /// Also print the private keys (Phantom "Import Private Key"). Off by default.
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
        /// after the pattern in the matches directory - MINT -> .../matches/MINT.txt
        #[arg(long)]
        out: Option<String>,
        /// Also print the seed phrase to stdout. Off by default so seeds stay
        /// out of scrollback, tmux buffers, and anything reading your terminal.
        #[arg(long)]
        show_seed: bool,
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
    /// Case-insensitive matching. Roughly 2^letters more likely: MINT goes from
    /// 1 in 11.3M to 1 in 707K.
    #[arg(long)]
    ignore_case: bool,
    /// Derivation path style. phantom = m/44'/501'/N'/0' (Phantom, Solflare
    /// default); legacy = m/44'/501'/N' (Solflare custom). Pick the wallet you
    /// will import into.
    #[arg(long, value_enum, default_value_t = PathStyle::Phantom)]
    path: PathStyle,
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
    suffixes: Vec<Vec<u8>>,
    prefixes: Vec<Vec<u8>>,
    ignore_case: bool,
    max_suffix: usize,
    needs_full: bool,
}

impl Matcher {
    fn new(p: &PatternArgs) -> Result<Self, String> {
        if p.ends_with.is_empty() && p.starts_with.is_empty() {
            return Err("need at least one --ends-with or --starts-with".into());
        }
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
            needs_full: !prefixes.is_empty(),
            max_suffix,
            suffixes,
            prefixes,
            ignore_case: p.ignore_case,
        })
    }

    #[inline]
    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.ignore_case { a.eq_ignore_ascii_case(b) } else { a == b }
    }

    /// Per-candidate hit probability.
    fn probability(&self) -> f64 {
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
    index: u32,
    address: String,
    mnemonic: Zeroizing<String>,
    /// The wallet-import form: base58 of the 64-byte keypair (32-byte secret
    /// followed by the 32-byte public key) - what Phantom's "Import Private
    /// Key" pastes.
    privkey: Zeroizing<String>,
    /// The same 64 bytes as a JSON array - `[12,34,...]` - what Solflare's
    /// keypair import and solana-keygen read.
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
        let seed = Zeroizing::new(mnemonic.to_seed(""));

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
                    index: idx,
                    address: bs58::encode(pk).into_string(),
                    mnemonic: Zeroizing::new(mnemonic.to_string()),
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

// ---------------------------------------------------------------- rate cache

/// `bench` writes the measured rate here; `estimate` reads it. The
/// theoretical model (1.2ms/indices + 21us) ran 2.6x optimistic on the
/// first machine it met -- an estimate should come from what THIS box
/// measured, not from a formula.
fn rate_cache_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("keyrx").join("bench.txt")
}

/// Where matches live by default: `<XDG_DATA_HOME or ~/.local/share>/keyrx/matches/`.
/// A home of its own, never the current directory, because a file that holds
/// seed phrases should not land wherever the shell happens to be.
fn matches_dir() -> std::path::PathBuf {
    rate_cache_path().parent().map(|p| p.join("matches"))
        .unwrap_or_else(|| std::path::PathBuf::from("matches"))
}

/// The pattern names the file: --ends-with MINT -> MINT.txt; several patterns
/// join with '+'; prefixes carry a trailing '_' so MINT_ (prefix) and MINT
/// (suffix) do not collide; case-insensitive adds '.ic'.
fn default_out(p: &PatternArgs) -> String {
    let mut parts: Vec<String> = Vec::new();
    for s in &p.ends_with { parts.push(s.clone()); }
    for s in &p.starts_with { parts.push(format!("{}_", s)); }
    let mut name = if parts.is_empty() { "matches".to_string() } else { parts.join("+") };
    if p.ignore_case { name.push_str(".ic"); }
    name.push_str(".txt");
    matches_dir().join(name).to_string_lossy().into_owned()
}

/// A path for the eye: files under the tool's own data dir print as
/// `matches/MINT.txt`; anything else prints whole. The full path is always
/// in the foot of the panel that names the file.
fn short_path(p: &str) -> String {
    let dir = matches_dir();
    if let Ok(rel) = std::path::Path::new(p).strip_prefix(&dir) {
        return format!("matches/{}", rel.display());
    }
    p.to_string()
}

fn save_rate(threads: usize, indices: u32, rate: f64) {
    let p = rate_cache_path();
    if let Some(d) = p.parent() { let _ = std::fs::create_dir_all(d); }
    let _ = std::fs::write(&p, format!("{} {} {:.0}\n", threads, indices, rate));
}

/// (threads, indices, rate) from the last bench, if any.
fn load_rate() -> Option<(usize, u32, f64)> {
    let s = std::fs::read_to_string(rate_cache_path()).ok()?;
    let mut it = s.split_whitespace();
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Scale a measured rate to other settings using the model's SHAPE (the
/// PBKDF2 amortisation curve), anchored to the real number.
fn scale_rate(measured: f64, m_threads: usize, m_idx: u32, threads: usize, indices: u32) -> f64 {
    let model = |i: u32| 1.0 / (1.2e-3 / i as f64 + 21e-6);
    measured / m_threads as f64 * threads as f64 * model(indices) / model(m_idx)
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

/// How to get this address into a wallet, said once, at the moment it
/// matters. One short line per wallet so nothing is ever clipped by the frame.
fn import_hint(style: PathStyle, idx: u32) -> Vec<String> {
    match style {
        PathStyle::Phantom => {
            if idx == 0 {
                vec!["Seed:     Phantom or Solflare - this is the FIRST account".to_string()]
            } else {
                vec![
                    format!("Seed:     Solflare custom path {}", path_str(style, idx)),
                    format!("          Phantom via seed = 'add account' {} time(s) (account #{})", idx, idx + 1),
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
            // a bare pattern name: MINT -> matches/MINT.txt
            let cand = matches_dir().join(format!("{}.txt", f.trim_end_matches(".txt")));
            if cand.exists() { cand.to_string_lossy().into_owned() }
            else { eprintln!("no such file: {} (nor {})", f, cand.display()); std::process::exit(1); }
        }
        None => {
            let dir = matches_dir();
            println!("{}", ui::top("MATCH FILES", &dir.to_string_lossy()));
            let mut names: Vec<String> = std::fs::read_dir(&dir).map(|rd| rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".txt")).collect()).unwrap_or_default();
            names.sort();
            if names.is_empty() {
                println!("{}", ui::note("no match files yet - grind writes them here, named after the pattern"));
            }
            for n in &names {
                let cnt = std::fs::read_to_string(dir.join(n))
                    .map(|t| t.split("\n\n").filter(|b| b.contains("address ")).count()).unwrap_or(0);
                let stem = n.trim_end_matches(".txt");
                println!("{}", ui::kv(stem, &format!("{} match(es)   keyrx show {}", cnt, stem)));
            }
            println!("{}", ui::bot("every file is mode 0600 · seeds and keys inside"));
            println!();
            return;
        }
    };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => { eprintln!("cannot read {}: {}", file, e); std::process::exit(1); }
    };
    println!("{}", ui::top("MATCHES", &file));
    let mut n = 0;
    for block in text.split("\n\n") {
        let mut addr = None; let mut path = None; let mut seed = None; let mut key = None; let mut kp = None;
        for line in block.lines() {
            if let Some(v) = line.strip_prefix("address ") { addr = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("path ") { path = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("seed ") { seed = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("privkey ") { key = Some(v.trim()); }
            else if let Some(v) = line.strip_prefix("keypair ") { kp = Some(v.trim()); }
        }
        if let (Some(a), Some(p)) = (addr, path) {
            n += 1;
            println!("{}", ui::mid(&format!("  {}{:>2}.{} {}{}{}  {}{}{}", ui::gry(), n, ui::r(), ui::wht(), a, ui::r(), ui::accent(), p, ui::r())));
            if with_seed {
                let s = seed.unwrap_or("(missing)");
                let w: Vec<&str> = s.split_whitespace().collect();
                for chunk in w.chunks(8) {
                    println!("{}", ui::mid(&format!("      {}{}{}", ui::gry(), chunk.join(" "), ui::r())));
                }
            }
            if with_key {
                let k = key.unwrap_or("(missing)");
                // 88 base58 chars: two rows so the frame never clips a key
                let (a1, a2) = k.split_at(k.len().min(60));
                println!("{}", ui::mid(&format!("      {}base58  {}{}", ui::gry(), a1, ui::r())));
                if !a2.is_empty() { println!("{}", ui::mid(&format!("              {}{}{}", ui::gry(), a2, ui::r()))); }
                // the JSON array is ~250 chars: wrap on the commas, never mid-number
                let j = kp.unwrap_or("(missing)");
                let mut line = String::new();
                let mut first = true;
                for piece in j.split_inclusive(',') {
                    if line.len() + piece.len() > 56 {
                        println!("{}", ui::mid(&format!("      {}{}{}{}", ui::gry(),
                            if first { "json    " } else { "        " }, line, ui::r())));
                        first = false; line.clear();
                    }
                    line.push_str(piece);
                }
                if !line.is_empty() {
                    println!("{}", ui::mid(&format!("      {}{}{}{}", ui::gry(),
                        if first { "json    " } else { "        " }, line, ui::r())));
                }
            }
        }
    }
    if n == 0 {
        println!("{}", ui::note("no matches in this file"));
    }
    let foot = match (with_seed, with_key) {
        (false, false) => "seeds and keys withheld · --seeds / --keys to print them",
        _ => "secrets shown - clear your scrollback when done",
    };
    println!("{}", ui::bot(foot));
    println!();
}

fn write_hit(out: &str, h: &Hit, style: PathStyle) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(out)?;
    writeln!(
        f,
        "address {}\npath    {}\nseed    {}\nprivkey {}\nkeypair {}\n",
        h.address,
        path_str(style, h.index),
        h.mnemonic.as_str(),
        h.privkey.as_str(),
        h.keypair_json.as_str()
    )
}

/// Time-to-first-match rows, framed. The 50% line carries the accent: it is
/// the number the operator plans around.
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
    let cmd = match Cli::parse().cmd {
        Some(c) => c,
        None => { cmd_start(); return; }
    };
    match cmd {
        Cmd::Verify => cmd_verify(),
        Cmd::Estimate { pattern, threads, indices } => cmd_estimate(pattern, threads, indices),
        Cmd::Bench { threads, indices, seconds } => cmd_bench(threads, indices, seconds),
        Cmd::Show { file, seeds, keys } => cmd_show(file, seeds, keys),
        Cmd::Grind { pattern, threads, indices, count, words, out, show_seed } => {
            let out = out.unwrap_or_else(|| default_out(&pattern));
            cmd_grind(pattern, threads, indices, count, words, out, show_seed)
        }
    }
}

/// The start screen: `keyrx` with no arguments. Every command, every flag,
/// and the two ideas you need - what a path index is, and why --indices
/// trades speed for where the match lands.
fn cmd_start() {
    ui::masthead(&format!("v{}", env!("CARGO_PKG_VERSION")));
    let n = ui::note;
    let kvw = ui::kvw;
    let cont = ui::cont;
    let blank = || println!("{}", ui::mid(""));
    let head = |t: &str| println!("{}", ui::mid(&format!("  {}{}{}{}", ui::b(), ui::wht(), t, ui::r())));

    println!("{}", ui::top("WHAT THIS IS", "one seed, unlimited addresses, keys for every wallet"));
    println!("{}", n("Grinds Solana vanity addresses - an address that ends (or starts)"));
    println!("{}", n("with the letters you choose - and hands you everything a wallet"));
    println!("{}", n("needs to hold it: seed phrase, derivation path, and the keypair in"));
    println!("{}", n("both import forms (base58 for Phantom, JSON array for Solflare)."));
    blank();
    println!("{}", n("Fast because `solana-keygen grind` pays 2048 rounds of PBKDF2 (~1.2 ms)"));
    println!("{}", n("to test ONE address; keyrx pays it once per seed, then walks that"));
    println!("{}", n("seed's account indices at ~21 us each: 20-60x the throughput."));
    blank();
    println!("{}", n("Standalone. No daemon, no service, no network. Secrets go to a"));
    println!("{}", n("mode-0600 file in a directory of their own, never to the screen"));
    println!("{}", n("unless you ask."));
    println!("{}", ui::bot("verify -> bench -> estimate -> grind -> show"));

    println!("{}", ui::top("COMMANDS", "in the order you use them"));
    println!("{}", kvw("verify", "self-test: base58, derivation, and the pinned"));
    println!("{}", cont("solana-keygen answer. Prints the ONE manual"));
    println!("{}", cont("cross-check command. Run first, always."));
    blank();
    println!("{}", kvw("bench", "measures this machine's real rate and SAVES it"));
    println!("{}", cont("for estimate.   --indices N  --threads N  --seconds N"));
    blank();
    println!("{}", kvw("estimate", "odds and time-to-match for a pattern, from the"));
    println!("{}", cont("measured rate. Also states what --ignore-case and"));
    println!("{}", cont("--indices 128 would buy."));
    blank();
    println!("{}", kvw("grind", "the real thing. Same pattern flags as estimate,"));
    println!("{}", cont("plus output. Ctrl-C stops after the current batch."));
    blank();
    println!("{}", kvw("show", "lists matches from the file: address + path,"));
    println!("{}", cont("seeds withheld. --seeds prints them too."));
    println!("{}", ui::bot("every command takes --help"));

    println!("{}", ui::top("PATTERN FLAGS", "estimate and grind"));
    println!("{}", kvw("--ends-with S", "suffix. Repeatable. Cheap: only the last N base58"));
    println!("{}", cont("characters are computed per candidate."));
    blank();
    println!("{}", kvw("--starts-with P", "prefix. Repeatable. Slower: needs the full address."));
    blank();
    println!("{}", kvw("--ignore-case", "match either case. ~2^letters more likely:"));
    println!("{}", cont("MINT goes from 1 in 11.3M to 1 in 707K."));
    blank();
    println!("{}", kvw("--path phantom", "m/44'/501'/N'/0'   Phantom, Solflare default"));
    println!("{}", kvw("--path legacy", "m/44'/501'/N'      Solflare custom path"));
    blank();
    println!("{}", n("base58 has no 0 O I l - patterns using them are rejected."));
    println!("{}", ui::bot("suffixes are the fast lane"));

    println!("{}", ui::top("GRIND FLAGS", ""));
    println!("{}", kvw("--out FILE", "where matches go. Created mode 0600. Default: a file"));
    println!("{}", cont("named after the pattern - MINT -> matches/MINT.txt"));
    blank();
    println!("{}", kvw("--count N", "stop after N matches. Default 1. May return a"));
    println!("{}", cont("couple more when threads hit at once - all valid."));
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
    println!("{}", n("and Phantom's 'Import Private Key' lands on the address in one"));
    println!("{}", n("paste, standalone. Then the index never matters - grind wide."));
    blank();
    head("Private key: --indices 128  ·  Seed into Phantom: --indices 8");
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
    println!("{}", kvw("file", &format!("{}", matches_dir().display())));
    println!("{}", cont("named after the pattern: MINT.txt / MINT.ic.txt"));
    println!("{}", ui::bot("keyrx show            lists the files · keyrx show MINT reads one"));

    println!("{}", ui::top("RECIPES", "pick the wallet you will import into"));
    let cmd = |c: &str| println!("{}", ui::mid(&format!("    {}{}{}", ui::accent(), c, ui::r())));
    let sub = |t: &str| println!("{}", ui::mid(&format!("    {}{}{}", ui::gry(), t, ui::r())));
    let wal = |w: &str, t: &str| println!("{}", ui::mid(&format!("  {}{}{}{}  {}{}{}",
        ui::b(), ui::wht(), w, ui::r(), ui::gry(), t, ui::r())));
    wal("Any wallet", "key import - the simplest route, exact address");
    cmd("keyrx grind --ends-with MINT --indices 128");
    sub("keyrx show MINT --keys: base58 for Phantom, JSON array for");
    sub("Solflare. Standalone; keep the file - a seed will not recover it.");
    blank();
    wal("Phantom", "by seed - the address inside a recoverable HD wallet");
    cmd("keyrx grind --ends-with MINT --words 12 --indices 8");
    sub("import the 12 words, then 'add account' until the address shows");
    sub("(0-7 clicks). Slower to find: about 4x the wide grind.");
    blank();
    wal("Solflare", "by seed - takes a custom path, so the grind runs wide");
    cmd("keyrx grind --ends-with MINT --indices 128");
    sub("import the words, choose the exact path the match printed.");
    blank();
    wal("Either", "case-insensitive: 16x more likely for MINT");
    cmd("keyrx grind --ends-with MINT --ignore-case --indices 8");
    sub("matches mint, Mint, MINT, mInT... - only an exact-case grind");
    sub("guarantees the letters print exactly MINT.");
    println!("{}", ui::bot("estimate first: it prints the odds for THIS machine"));

    println!("{}", ui::top("A TYPICAL SESSION", ""));
    cmd("keyrx verify");
    cmd("keyrx bench --indices 128");
    cmd("keyrx estimate --ends-with MINT");
    cmd("keyrx grind --ends-with MINT --indices 128");
    cmd("keyrx show MINT --keys");
    blank();
    println!("{}", ui::warn_line("import and verify the address BEFORE funding."));
    println!("{}", ui::warn_line("the match file holds seed and keys. Treat it like a key - it is one."));
    println!("{}", ui::bot("keyrx <command> --help · keyrx.tech · MIT"));
    println!();
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
    // The pinned solana-keygen answer for this public test entropy - checked
    // by hand on 2026-08-16 and locked as a test. If it ever moves, STOP.
    const XCHECK: &str = "8zzKEAB4VqnUchbsmAor9QzyVWVQFanQGJYQw8UQPh1j";
    if addr == XCHECK {
        println!("{}", ui::ok_line("SLIP-0010 matches solana-keygen  (pinned cross-check)"));
    } else {
        println!("{}", ui::crit_line("SLIP-0010 does NOT match the pinned solana-keygen answer"));
    }
    println!("{}", ui::bot(if addr == XCHECK { "all green" } else { "STOP - do not fund anything from this build" }));

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
    println!("{}", ui::bot("if they differ, STOP"));
    println!();
}

fn cmd_estimate(p: PatternArgs, threads: usize, indices: u32) {
    let m = match Matcher::new(&p) {
        Ok(m) => m,
        Err(e) => { eprintln!("error: {}", e); std::process::exit(1); }
    };
    let prob = m.probability();
    let measured = load_rate();
    let (rate, basis) = match measured {
        Some((mt, mi, mr)) => (scale_rate(mr, mt, mi, threads, indices),
                               format!("measured here ({} threads, {} idx), scaled", mt, mi)),
        None => {
            let per_core = 1.0 / (1.2e-3 / indices as f64 + 21e-6);
            (per_core * threads as f64, "THEORETICAL - run `keyrx bench` first".to_string())
        }
    };
    ui::masthead("estimate");
    println!("{}", ui::top("ODDS", "before you grind"));
    let pats: Vec<String> = m.suffixes.iter().map(|s| format!("*{}", String::from_utf8_lossy(s)))
        .chain(m.prefixes.iter().map(|s| format!("{}*", String::from_utf8_lossy(s)))).collect();
    println!("{}", ui::kv("pattern", &format!("{}{}", pats.join("  "),
        if p.ignore_case { "   (case-insensitive)" } else { "" })));
    println!("{}", ui::kv("odds", &format!("1 in {}", group(1.0 / prob))));
    println!("{}", ui::kv("rate", &format!("{}/sec  ({} threads, {} indices/mnemonic)", group(rate), threads, indices)));
    println!("{}", if measured.is_some() { ui::note(&format!("basis      {}", basis)) }
                   else { ui::warn_line(&format!("basis    {}", basis)) });
    println!("{}", ui::mid(""));
    println!("{}", ui::note("time to first match"));
    quantiles(prob, rate);
    println!("{}", ui::bot(if measured.is_some() { "from this machine's own bench" } else { "theoretical - ran 2.6x optimistic on real hardware" }));

    // The levers, as numbers.
    let mut levers: Vec<String> = Vec::new();
    if !p.ignore_case && m.suffixes.iter().chain(m.prefixes.iter())
        .any(|s| s.iter().any(|c| c.is_ascii_alphabetic())) {
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
    if indices < 128 {
        let r2 = match measured {
            Some((mt, mi, mr)) => scale_rate(mr, mt, mi, threads, 128),
            None => (1.0 / (1.2e-3 / 128.0 + 21e-6)) * threads as f64,
        };
        levers.push(format!("--indices 128   ~{:.1}x the rate - match lands at a higher account index", r2 / rate));
    }
    if !levers.is_empty() {
        println!("{}", ui::top("LEVERS", "what the flags would buy"));
        for l in levers { println!("{}", ui::note(&l)); }
        println!("{}", ui::bot(""));
    }
    println!();
}

fn cmd_bench(threads: usize, indices: u32, seconds: u64) {
    ui::masthead("bench");
    println!("{}", ui::top("BENCH", &format!("{} threads · {} indices/mnemonic · {}s", threads, indices, seconds)));
    println!("{}", ui::note("grinding a pattern that cannot match, counting candidates..."));
    let _ = std::io::stdout().flush();
    let p = PatternArgs {
        ends_with: vec!["zzzzzzzz".into()],
        starts_with: vec![],
        ignore_case: false,
        path: PathStyle::Phantom,
    };
    let m = Arc::new(Matcher::new(&p).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    std::thread::scope(|s| {
        for _ in 0..threads {
            let (m, stop, counter) = (Arc::clone(&m), Arc::clone(&stop), Arc::clone(&counter));
            s.spawn(move || grind_loop(&m, PathStyle::Phantom, indices, 32, &stop, &counter, &|_| {}));
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
    let x = rate / 13_600.0;
    println!("{}", ui::kv("vs baseline", &format!("{:.1}x the 13,600/sec of solana-keygen grind", x)));
    println!("{}", ui::mid(&format!("  {}{:<11}{}{}", ui::gry(), "", ui::r(), ui::bar((x / 40.0 * 100.0).min(100.0), 40))));
    println!("{}", ui::mid(""));
    println!("{}", ui::note("time to first 5-char suffix (1 in 656,356,768)"));
    quantiles(1.0 / 656_356_768.0, rate);
    save_rate(threads, indices, rate);
    println!("{}", ui::bot(&format!("saved for estimate -> {}", rate_cache_path().display())));
    println!();
}

#[allow(clippy::too_many_arguments)]
fn cmd_grind(
    p: PatternArgs, threads: usize, indices: u32, count: usize,
    words: usize, out: String, show_seed: bool,
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
    if m.needs_full {
        eprintln!("note: prefix matching needs full base58 per candidate (slower than suffix)");
    }
    if indices > 16 {
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
    ui::masthead("grind");
    println!("{}", ui::top("GRIND", "Ctrl-C stops after the current batch"));
    let pats: Vec<String> = m.suffixes.iter().map(|s| format!("*{}", String::from_utf8_lossy(s)))
        .chain(m.prefixes.iter().map(|s| format!("{}*", String::from_utf8_lossy(s)))).collect();
    println!("{}", ui::kv("pattern", &format!("{}{}", pats.join("  "), if p.ignore_case { "   (case-insensitive)" } else { "" })));
    println!("{}", ui::kv("odds", &format!("1 in {}", group(1.0 / prob))));
    println!("{}", ui::kv("threads", &format!("{} · {} indices/mnemonic · {}-word seeds", threads, indices, words)));
    println!("{}", ui::kv("matches ->", &format!("{}  (mode 0600)", short_path(&out))));
    println!("{}", ui::kv("stop after", &format!("{} match(es)", count)));
    println!("{}", ui::bot(&format!("in {}", matches_dir().display())));
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
                if !tick.is_multiple_of(every) { continue; }
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
            s.spawn(move || {
                grind_loop(&m, style, indices, entropy_len, &stop, &counter, &|h| {
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
                    println!("{}", ui::kv("path", &path_str(style, h.index)));
                    if show_seed {
                        let w: Vec<&str> = h.mnemonic.split_whitespace().collect();
                        let mut first = true;
                        for chunk in w.chunks(8) {
                            println!("{}", ui::mid(&format!("  {}{:<11}{}{}{}{}", ui::gry(),
                                if first { "seed" } else { "" }, ui::r(), ui::wht(), chunk.join(" "), ui::r())));
                            first = false;
                        }
                    } else {
                        println!("{}", ui::kv("seed", &format!("-> {}   (--show-seed to print here)", short_path(&out))));
                    }
                    println!("{}", ui::kv("keys", &format!("-> {}   base58 + JSON array (show --keys)", short_path(&out))));
                    println!("{}", ui::mid(""));
                    println!("{}", ui::note("Key:      Phantom pastes the base58 · Solflare imports the JSON array"));
                    println!("{}", ui::note("          -> this exact address, standalone, no clicks"));
                    for l in import_hint(style, h.index) { println!("{}", ui::note(&l)); }
                    println!("{}", ui::note("the OTHER accounts on this seed are ordinary addresses"));
                    println!("{}", ui::bot("import and verify the address BEFORE funding"));
                    println!();
                    if hits.fetch_add(1, Ordering::SeqCst) + 1 >= count as u64 {
                        stop.store(true, Ordering::SeqCst);
                    }
                });
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
        println!(" {}keyrx show {}   lists them · --seeds / --keys to reveal{}", ui::gry(), stem, ui::r());
    }
    println!();
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

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
        grind_loop(&m, PathStyle::Phantom, 64, 16, &stop, &counter, &|h| {
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

    #[test]
    fn default_out_names_the_file_after_the_pattern() {
        let d = default_out(&pat(&["MINT"], &[], false));
        assert!(d.ends_with("/matches/MINT.txt"), "{}", d);
        let d = default_out(&pat(&["MINT"], &["Ab"], true));
        assert!(d.ends_with("/matches/MINT+Ab_.ic.txt"), "{}", d);
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
        grind_loop(&m, PathStyle::Phantom, 64, 32, &stop, &counter, &|h| {
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
}
