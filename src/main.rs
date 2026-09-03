// keyRX -- Solana and EVM vanity address grinder
//
// Standalone terminal tool. No daemon or service. Grinding and local inspection
// are offline; the explicit --update command invokes Cargo's networked install.
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
// forms -- base58 for the current Phantom and Solflare private-key import
// flows, and the JSON byte array for solana-keygen. A key import lands on the
// exact address in one
// paste, standalone; the account index only matters if you import the SEED
// (wallet/version/path discovery varies; always verify before funding).
//
//   keyrx                                  <- start screen: everything explained
//   keyrx verify                           <- run this first, always
//   keyrx bench --indices 128
//   keyrx estimate --ends-with KEYRX --indices 128
//   keyrx grind --ends-with KEYRX --indices 128
//   keyrx show                            <- list every exact recovery record

mod evm;
mod ui;

use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x8000_0000;
/// The donation address. ONE place - the CLI panel reads it, and the site
/// carries the same string in its own DONATE_SOL const; change both
/// together. The address is set; an empty value remains a supported build-time
/// state and makes the panel say that no donation address is configured.
const DONATE_SOL: &str = "2pSgpgA6TqdynuAdVpFEZbyVRrKi5oTyvxGL9gjKEYRX";
/// The EVM donation address - one address for every EVM chain - ground with this tool's
/// `--chain evm`. Same rule as DONATE_SOL: ONE place here, the same string in the site's
/// DONATE_EVM const, change both together. It is set; an empty value would make
/// the panel show Solana alone.
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
    explorer: "https://robinhoodchain.blockscout.com",
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
        let t = match i {
            1 => ui::ABOUT[0].to_string(),
            2 => ui::ABOUT[1].to_string(),
            3 => ui::ABOUT[2].to_string(),
            5 => ui::ABOUT[3].to_string(),
            7 => format!("{}  ·  {}", ui::SITE, ui::CONTACT),
            _ => String::new(),
        };
        out.push_str(&format!(
            "\n {}{}{}",
            line,
            if t.is_empty() { "" } else { "  " },
            t
        ));
    }
    out
}

#[derive(Parser)]
#[command(name = "keyrx", version, about = "The keyRX CLI: Solana and EVM BIP39 vanity address grinder", before_help = help_seal())]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Update: `cargo install --locked keyrx`, then clear, then keyrx.
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
        /// Mnemonic length whose measured benchmark lane to use: 12 or 24.
        #[arg(long, default_value_t = 12)]
        words: usize,
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
        /// Solana derivation lane to measure. EVM always uses its fixed BIP44 path.
        #[arg(long, value_enum, default_value_t = PathStyle::Phantom)]
        path: PathStyle,
        /// Mnemonic length to measure: 12 or 24.
        #[arg(long, default_value_t = 12)]
        words: usize,
    },

    /// Optional, and it changes nothing: MIT, no paid tier, nothing gated.
    Donate,

    /// EVM networks a wallet does not list by default (Robinhood Chain): the add-a-network
    /// steps for MetaMask/Rabby and the five values, printed bare for pasting.
    Networks,

    /// List matches - addresses and paths; seeds and keys withheld by default.
    /// With no FILE, lists every match file in the matches directory (EVM files as evm/NAME).
    Show {
        /// A match file, or an exact listed name. Legacy .txt files remain readable.
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
        /// lands at a higher account index. Private-key import lands on the
        /// exact address; seed recovery is wallet/version/path-discovery
        /// dependent, so use a small value unless that path is proven.
        #[arg(long, default_value_t = 64)]
        indices: u32,
        /// Stop after this many matches.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Mnemonic length: 12 or 24. Default 12 - what Phantom generates and
        /// what most people are used to. BIP39 defines both lengths; confirm
        /// the receiving wallet supports the one you choose.
        #[arg(long, default_value_t = 12)]
        words: usize,
        /// Explicit aggregate output file (Unix: created/narrowed to mode 0600). Without --out,
        /// every match gets its own Markdown file under the managed matches directory.
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
    /// Suffix to match. Repeatable: any one may hit. Given --starts-with too,
    /// an address must match a suffix AND a prefix.
    #[arg(long = "ends-with")]
    ends_with: Vec<String>,
    /// Prefix to match. Repeatable: any one may hit. Costs more than a suffix.
    /// Given --ends-with too, both ends must match.
    #[arg(long = "starts-with")]
    starts_with: Vec<String>,
    /// Case-insensitive matching. Roughly 2^letters more likely: KEYRX goes from
    /// 1 in 656M to 1 in 20.5M.
    #[arg(long)]
    ignore_case: bool,
    /// Derivation path style. phantom = m/44'/501'/N'/0'; legacy =
    /// m/44'/501'/N'. Confirm the receiving wallet/version can discover the
    /// printed path. Solana only: EVM is always m/44'/60'/0'/0/N.
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

#[derive(Copy, Clone, ValueEnum, PartialEq, Debug)]
enum PathStyle {
    /// m/44'/501'/N'/0'  -- two-level Solana account path
    Phantom,
    /// m/44'/501'/N'     -- legacy one-level Solana account path
    Legacy,
}

fn available_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
}

fn max_threads_for(available: usize) -> usize {
    available.max(1).saturating_mul(4).clamp(32, 512)
}

fn default_threads_for(available: usize) -> usize {
    available.max(1).min(max_threads_for(available))
}

fn num_threads() -> usize {
    default_threads_for(available_threads())
}

fn validate_work_args(threads: usize, indices: u32, count: usize) -> Result<(), String> {
    if threads == 0 {
        return Err("--threads must be at least 1".into());
    }
    let max_threads = max_threads_for(available_threads());
    if threads > max_threads {
        return Err(format!(
            "--threads must be at most {} on this machine (four times available parallelism, capped at 512)",
            max_threads
        ));
    }
    if indices == 0 {
        return Err("--indices must be at least 1".into());
    }
    if indices > HARDENED {
        return Err(format!(
            "--indices must be at most {} so every derived index stays below 2^31",
            HARDENED
        ));
    }
    if count == 0 {
        return Err("--count must be at least 1".into());
    }
    Ok(())
}

fn validate_bench_args(threads: usize, indices: u32, seconds: u64) -> Result<(), String> {
    validate_work_args(threads, indices, 1)?;
    if seconds == 0 {
        return Err("--seconds must be at least 1".into());
    }
    Ok(())
}

// ---------------------------------------------------------------- crypto

fn master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(seed);
    let mut digest = mac.finalize().into_bytes();
    let result = split(digest.as_slice());
    digest.zeroize();
    result
}

/// SLIP-0010 hardened derivation. Ed25519 supports hardened only.
/// data = 0x00 || parent_key || ser32(index | 0x80000000)
fn derive_hardened(key: &[u8; 32], chain: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(chain).unwrap();
    mac.update(&[0u8]);
    mac.update(key);
    mac.update(&(index | HARDENED).to_be_bytes());
    let mut digest = mac.finalize().into_bytes();
    let result = split(digest.as_slice());
    digest.zeroize();
    result
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
    /// Per-candidate probability derived once from the same feasible edge
    /// pairs the constructor accepted. Impossible alternatives never survive
    /// into this value.
    probability: f64,
    probability_approximate: bool,
}

/// Remove duplicate alternatives and any narrower alternative already covered by
/// a broader one. This makes the OR lanes disjoint before their probabilities are
/// added: `ab OR ab` is one pattern, and suffix `ab OR cab` is still just `ab`.
fn canonical_patterns(mut values: Vec<Vec<u8>>, prefix: bool, ignore_case: bool) -> Vec<Vec<u8>> {
    values.sort_by_key(|v| v.len());
    let mut out: Vec<Vec<u8>> = Vec::new();
    'candidate: for value in values {
        for broad in &out {
            if broad.len() > value.len() {
                continue;
            }
            let edge = if prefix {
                &value[..broad.len()]
            } else {
                &value[value.len() - broad.len()..]
            };
            let equal = if ignore_case {
                edge.eq_ignore_ascii_case(broad)
            } else {
                edge == broad
            };
            if equal {
                continue 'candidate;
            }
        }
        out.push(value);
    }
    out
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Wide([u64; 5]);

impl Wide {
    fn zero() -> Self {
        Self([0; 5])
    }

    fn from_base58(text: &[u8]) -> Self {
        let mut value = Self::zero();
        for byte in text {
            let digit = B58
                .iter()
                .position(|candidate| candidate == byte)
                .expect("pattern bytes were validated as base58") as u64;
            value.mul_small(58);
            value.add_u128(digit as u128);
        }
        value
    }

    fn mul_small(&mut self, factor: u64) {
        let mut carry = 0u128;
        for limb in &mut self.0 {
            let product = (*limb as u128) * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        assert_eq!(
            carry, 0,
            "44 base58 digits fit the 320-bit feasibility lane"
        );
    }

    fn add_u128(&mut self, value: u128) {
        let (low, carry0) = self.0[0].overflowing_add(value as u64);
        self.0[0] = low;
        let high = (value >> 64) as u64;
        let (mid, carry1) = self.0[1].overflowing_add(high);
        let (mid, carry2) = mid.overflowing_add(carry0 as u64);
        self.0[1] = mid;
        let mut carry = carry1 || carry2;
        for limb in &mut self.0[2..] {
            if !carry {
                break;
            }
            let (next, overflow) = limb.overflowing_add(1);
            *limb = next;
            carry = overflow;
        }
        assert!(!carry, "feasibility addition fits the 320-bit lane");
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for index in (0..self.0.len()).rev() {
            match self.0[index].cmp(&other.0[index]) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }

    fn rem_u128(&self, modulus: u128) -> u128 {
        let mut remainder = 0u128;
        for limb in self.0.iter().rev() {
            for bit in (0..64).rev() {
                remainder = (remainder << 1) | ((limb >> bit) & 1) as u128;
                if remainder >= modulus {
                    remainder -= modulus;
                }
            }
        }
        remainder
    }

    fn pow2(bit: usize) -> Self {
        let mut value = Self::zero();
        value.0[bit / 64] = 1u64 << (bit % 64);
        value
    }

    fn low_bits_set(bits: usize) -> Self {
        let mut value = Self::zero();
        for bit in 0..bits {
            value.0[bit / 64] |= 1u64 << (bit % 64);
        }
        value
    }
}

fn exact_sol_text_is_canonical(text: &[u8]) -> bool {
    bs58::decode(text)
        .into_vec()
        .ok()
        .filter(|decoded| decoded.len() == 32)
        .filter(|decoded| bs58::encode(decoded).into_vec() == text)
        .is_some()
}

fn enumerate_canonical_sol_gap(
    gap_start: usize,
    gap: usize,
    position: usize,
    candidate: &mut [u8],
) -> bool {
    if position == gap {
        return exact_sol_text_is_canonical(candidate);
    }
    for byte in B58 {
        candidate[gap_start + position] = *byte;
        if enumerate_canonical_sol_gap(gap_start, gap, position + 1, candidate) {
            return true;
        }
    }
    false
}

fn base58_progression_hits_32_bytes(
    low: &[u8],
    high: &[u8],
    leading_ones: usize,
    suffix_len: usize,
) -> bool {
    if leading_ones >= 32 {
        return false;
    }
    let low = Wide::from_base58(low);
    let high = Wide::from_base58(high);
    let target_low = Wide::pow2(8 * (31 - leading_ones));
    let target_high = Wide::low_bits_set(8 * (32 - leading_ones));
    let intersection_low = if low.cmp(&target_low).is_lt() {
        target_low
    } else {
        low
    };
    let intersection_high = if high.cmp(&target_high).is_gt() {
        target_high
    } else {
        high
    };
    if intersection_low.cmp(&intersection_high).is_gt() {
        return false;
    }
    let step = 58u128.pow(suffix_len as u32);
    let low_residue = low.rem_u128(step);
    let intersection_residue = intersection_low.rem_u128(step);
    let delta = (low_residue + step - intersection_residue) % step;
    let mut first = intersection_low;
    first.add_u128(delta);
    !first.cmp(&intersection_high).is_gt()
}

/// Determine whether two Solana edge constraints leave at least one possible
/// canonical 32-byte base58 address. Solana address text is variable length
/// (32..=44), so prefix/suffix edges may overlap. A free middle is an exact
/// base58 arithmetic progression, checked against the byte-length interval;
/// it is not treated as automatically feasible.
const MAX_SOL_CANONICAL_ENUMERATIONS: usize = 1_000_000;

fn sol_edges_possible(
    prefix: &[u8],
    suffix: &[u8],
    ignore_case: bool,
    enumeration_budget: &mut usize,
) -> Result<bool, String> {
    let mut uncertain_case_only = false;
    let mut unprovable_near_complete = false;
    for len in 32usize.max(prefix.len()).max(suffix.len())..=44 {
        let Some(merged) = merged_edges(len, prefix, suffix, ignore_case) else {
            continue;
        };
        let gap_start = merged.iter().position(Option::is_none);
        let gap_end = merged.iter().rposition(Option::is_none);
        let Some(gap_start) = gap_start else {
            let full: Vec<u8> = merged.into_iter().map(Option::unwrap).collect();
            if exact_sol_text_is_canonical(&full) {
                // An Ed25519 signing key maps a clamped scalar into only a
                // subset of otherwise valid point encodings. Proving whether
                // arbitrary full address text has such a preimage requires a
                // witness, not merely curve decoding. Do not promise a hunt
                // that may have no solution.
                unprovable_near_complete = true;
            }
            if ignore_case {
                uncertain_case_only = true;
            }
            continue;
        };
        let gap_end = gap_end.expect("a first gap has a last gap");
        if merged[gap_start..=gap_end].iter().any(Option::is_some) {
            return Err(
                "internal error: Solana edge constraints did not leave one contiguous middle"
                    .into(),
            );
        }
        let gap = gap_end - gap_start + 1;
        let fixed_prefix: Vec<u8> = merged[..gap_start].iter().map(|v| v.unwrap()).collect();
        let fixed_suffix: Vec<u8> = merged[gap_end + 1..].iter().map(|v| v.unwrap()).collect();
        // Up to three free base58 characters is still only 195,112 point
        // encodings, but point membership cannot prove a SigningKey preimage.
        // Refuse this near-complete lane unless another possible address length
        // leaves a wider search space whose feasibility is honestly modeled.
        if gap <= 3 {
            let work = 58usize.pow(gap as u32);
            if work > *enumeration_budget {
                return Err(format!(
                    "Solana canonical feasibility needs more than {} candidates; reduce the near-complete alternatives",
                    MAX_SOL_CANONICAL_ENUMERATIONS
                ));
            }
            *enumeration_budget -= work;
            let mut candidate: Vec<u8> =
                merged.iter().map(|value| value.unwrap_or(B58[0])).collect();
            if enumerate_canonical_sol_gap(gap_start, gap, 0, &mut candidate) {
                unprovable_near_complete = true;
            }
            continue;
        }
        let fixed_has_nonzero = fixed_prefix.iter().any(|byte| *byte != b'1');
        if fixed_has_nonzero {
            let leading_ones = fixed_prefix
                .iter()
                .take_while(|byte| **byte == b'1')
                .count();
            let mut low = fixed_prefix.clone();
            low.extend(std::iter::repeat_n(b'1', gap));
            low.extend_from_slice(&fixed_suffix);
            let mut high = fixed_prefix;
            high.extend(std::iter::repeat_n(b'z', gap));
            high.extend_from_slice(&fixed_suffix);
            if base58_progression_hits_32_bytes(&low, &high, leading_ones, fixed_suffix.len()) {
                return Ok(true);
            }
        } else {
            // The free middle may extend the leading-zero run. Partition by
            // the first non-'1' free digit; each partition remains one exact
            // arithmetic progression.
            for leading_free_ones in 0..gap {
                let leading_ones = fixed_prefix.len() + leading_free_ones;
                let remaining = gap - leading_free_ones - 1;
                let mut low = fixed_prefix.clone();
                low.extend(std::iter::repeat_n(b'1', leading_free_ones));
                low.push(b'2');
                low.extend(std::iter::repeat_n(b'1', remaining));
                low.extend_from_slice(&fixed_suffix);
                let mut high = fixed_prefix.clone();
                high.extend(std::iter::repeat_n(b'1', leading_free_ones));
                high.extend(std::iter::repeat_n(b'z', remaining + 1));
                high.extend_from_slice(&fixed_suffix);
                if base58_progression_hits_32_bytes(&low, &high, leading_ones, fixed_suffix.len()) {
                    return Ok(true);
                }
            }
            let mut all_zero = fixed_prefix;
            all_zero.extend(std::iter::repeat_n(b'1', gap));
            all_zero.extend_from_slice(&fixed_suffix);
            if exact_sol_text_is_canonical(&all_zero) {
                return Ok(true);
            }
        }
        if ignore_case {
            uncertain_case_only = true;
        }
    }
    if unprovable_near_complete {
        Err(
            "a full or near-complete Solana address cannot be proven reachable from address text; shorten the combined edges to leave at least four free characters"
                .into(),
        )
    } else if uncertain_case_only {
        Err(
            "a case-insensitive Solana edge constraint cannot be proven feasible; use exact case"
                .into(),
        )
    } else {
        Ok(false)
    }
}

fn merged_edges(
    len: usize,
    prefix: &[u8],
    suffix: &[u8],
    ignore_case: bool,
) -> Option<Vec<Option<u8>>> {
    if prefix.len() > len || suffix.len() > len {
        return None;
    }
    let mut candidate = vec![None; len];
    for (position, byte) in prefix.iter().copied().enumerate() {
        candidate[position] = Some(byte);
    }
    let suffix_start = len - suffix.len();
    for (offset, byte) in suffix.iter().copied().enumerate() {
        let position = suffix_start + offset;
        if let Some(existing) = candidate[position] {
            let equal = if ignore_case {
                existing.eq_ignore_ascii_case(&byte)
            } else {
                existing == byte
            };
            if !equal {
                return None;
            }
        } else {
            candidate[position] = Some(byte);
        }
    }
    Some(candidate)
}

struct EvmEdgeAnalysis {
    probability: f64,
    approximate: bool,
}

const MAX_EVM_CHECKSUM_ENUMERATIONS: usize = 1_048_576;

/// Merge and measure one EVM edge pair. If every free nibble fits the bounded
/// budget, EIP-55 feasibility and probability are exhaustive. Larger checksum
/// lanes retain the traditional independent-case probability estimate, label
/// it approximate, and are admitted only after a concrete completion witnesses
/// feasibility. The global budget prevents many alternatives from turning
/// input validation into an unbounded computation.
fn analyze_evm_edges(
    prefix: &[u8],
    suffix: &[u8],
    checksum: bool,
    enumeration_budget: &mut usize,
) -> Result<Option<EvmEdgeAnalysis>, String> {
    let Some(merged) = merged_edges(40, prefix, suffix, !checksum) else {
        return Ok(None);
    };
    let constrained = merged.iter().filter(|value| value.is_some()).count();
    if !checksum {
        return Ok(Some(EvmEdgeAnalysis {
            probability: 1.0 / 16f64.powi(constrained as i32),
            approximate: false,
        }));
    }
    let unknown = 40 - constrained;
    let free: Vec<usize> = merged
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.is_none().then_some(index))
        .collect();
    let mut lower: Vec<u8> = merged
        .iter()
        .map(|value| value.unwrap_or(b'0').to_ascii_lowercase())
        .collect();
    let exact_work = 16usize.checked_pow(unknown as u32);
    let exhaustive = exact_work.is_some_and(|work| work <= *enumeration_budget);
    let varied: &[usize] = if exhaustive {
        &free
    } else {
        // One fully enumerated five-nibble slice gives a deterministic bounded
        // feasibility witness without pretending to measure the whole space.
        // All remaining free nibbles stay at zero for this proof slice.
        &free[..free.len().min(5)]
    };
    let requested_work = if exhaustive {
        exact_work.expect("checked above")
    } else {
        16usize.pow(varied.len() as u32)
    };
    let work = requested_work.min(*enumeration_budget);
    if work == 0 {
        return Err(format!(
            "EIP-55 feasibility needs more than {} checksum candidates; reduce the checksum alternatives",
            MAX_EVM_CHECKSUM_ENUMERATIONS
        ));
    }
    let mut valid = 0usize;
    let mut checked = 0usize;
    for mut value in 0..work {
        for index in varied.iter().rev() {
            lower[*index] = b"0123456789abcdef"[value & 0xf];
            value >>= 4;
        }
        let mut raw = [0u8; 20];
        for (index, pair) in lower.chunks_exact(2).enumerate() {
            raw[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("enumerated bytes are hex");
        }
        let checksummed = evm::eip55(&raw);
        let checksummed = &checksummed.as_bytes()[2..];
        if merged
            .iter()
            .enumerate()
            .all(|(index, expected)| expected.is_none_or(|expected| checksummed[index] == expected))
        {
            valid += 1;
            if !exhaustive {
                checked += 1;
                break;
            }
        }
        checked += 1;
    }
    *enumeration_budget -= checked;
    if valid == 0 {
        if exhaustive {
            return Ok(None);
        }
        return Err(format!(
            "EIP-55 feasibility was not proven within {} checksum candidates; reduce or change the checksum pattern",
            checked
        ));
    }
    if exhaustive {
        Ok(Some(EvmEdgeAnalysis {
            probability: valid as f64 / 16f64.powi(40),
            approximate: false,
        }))
    } else {
        let case_letters = merged
            .iter()
            .flatten()
            .filter(|byte| byte.is_ascii_alphabetic())
            .count();
        Ok(Some(EvmEdgeAnalysis {
            probability: 1.0 / 16f64.powi(constrained as i32) / 2f64.powi(case_letters as i32),
            approximate: true,
        }))
    }
}

fn edge_probability(text: &[u8], ignore_case: bool) -> f64 {
    let variants = text.iter().fold(1.0f64, |variants, byte| {
        if ignore_case && byte.is_ascii_alphabetic() {
            variants
                * B58
                    .iter()
                    .filter(|candidate| candidate.eq_ignore_ascii_case(byte))
                    .count() as f64
        } else {
            variants
        }
    });
    variants / 58f64.powi(text.len() as i32)
}

/// A conservative, explicitly approximate Solana prefix-pair model. Suffix-
/// only lanes preserve the historical exact base58-modulus model. Prefixes
/// are non-uniform, so a prefix lane is always labelled approximate; when its
/// suffix overlaps, the shared characters are counted once rather than as an
/// independent second event.
fn sol_pair_probability(prefix: &[u8], suffix: &[u8], ignore_case: bool) -> f64 {
    if prefix.is_empty() {
        return edge_probability(suffix, ignore_case);
    }
    if suffix.is_empty() {
        return edge_probability(prefix, ignore_case);
    }
    (32usize.max(prefix.len()).max(suffix.len())..=44)
        .filter_map(|len| merged_edges(len, prefix, suffix, ignore_case))
        .map(|merged| {
            let constrained: Vec<u8> = merged.into_iter().flatten().collect();
            edge_probability(&constrained, ignore_case)
        })
        .fold(0.0f64, f64::max)
}

impl Matcher {
    fn new(p: &PatternArgs) -> Result<Self, String> {
        if p.ends_with.is_empty() && p.starts_with.is_empty() {
            return Err("need at least one --ends-with or --starts-with".into());
        }
        if p.chain == Chain::Evm {
            return Self::new_evm(p);
        }
        if p.checksum {
            return Err("--checksum is EIP-55, an EVM thing - add --chain evm".into());
        }
        let check = |s: &String| -> Result<Vec<u8>, String> {
            if s.is_empty() {
                return Err("empty pattern".into());
            }
            if s.chars().any(unsafe_terminal_char) {
                return Err("pattern contains a control or bidi character".into());
            }
            for (position, c) in s.bytes().enumerate() {
                if !B58.contains(&c) {
                    return Err(format!(
                        "pattern byte {} is not base58 (0 O I l are excluded)",
                        position + 1
                    ));
                }
            }
            Ok(s.clone().into_bytes())
        };
        let suffixes = canonical_patterns(
            p.ends_with.iter().map(check).collect::<Result<_, _>>()?,
            false,
            p.ignore_case,
        );
        let prefixes = canonical_patterns(
            p.starts_with.iter().map(check).collect::<Result<_, _>>()?,
            true,
            p.ignore_case,
        );
        let max_suffix = suffixes.iter().map(|s| s.len()).max().unwrap_or(0);
        if max_suffix > 16 {
            return Err("suffix longer than 16 chars".into());
        }
        if prefixes.iter().any(|p| p.len() > 44) {
            return Err("prefix longer than Solana's maximum 44-character address".into());
        }
        if prefixes.iter().any(|prefix| {
            let leading_zero_bytes = prefix.iter().take_while(|digit| **digit == b'1').count();
            leading_zero_bytes > 32 || (leading_zero_bytes == 32 && prefix.len() > 32)
        }) {
            return Err(
                "Solana prefix requires more leading zero bytes than a 32-byte address can hold"
                    .into(),
            );
        }
        let prefix_choices: Vec<&[u8]> = if prefixes.is_empty() {
            vec![b""]
        } else {
            prefixes.iter().map(Vec::as_slice).collect()
        };
        let suffix_choices: Vec<&[u8]> = if suffixes.is_empty() {
            vec![b""]
        } else {
            suffixes.iter().map(Vec::as_slice).collect()
        };
        let mut possible = false;
        let mut probability = 0.0f64;
        let mut enumeration_budget = MAX_SOL_CANONICAL_ENUMERATIONS;
        for prefix in &prefix_choices {
            for suffix in &suffix_choices {
                match sol_edges_possible(prefix, suffix, p.ignore_case, &mut enumeration_budget) {
                    Ok(true) => {
                        possible = true;
                        probability += sol_pair_probability(prefix, suffix, p.ignore_case);
                    }
                    Ok(false) => {}
                    // An unprovable requested alternative may still match at
                    // runtime, so accepting the other alternatives would make
                    // the stored probability and the actual matcher disagree.
                    // Fail the complete request rather than retain a lane we
                    // cannot honestly measure.
                    Err(error) => return Err(error),
                }
            }
        }
        if !possible {
            return Err(
                "Solana edge constraints cannot form a canonical 32-byte address at any encoded length"
                    .into(),
            );
        }
        Ok(Matcher {
            chain: Chain::Sol,
            needs_full: !prefixes.is_empty(),
            max_suffix,
            suffixes,
            prefixes,
            ignore_case: p.ignore_case,
            checksum: false,
            probability: probability.min(1.0),
            probability_approximate: true,
        })
    }

    /// EVM patterns: hex digits, `0x` allowed only at the front of a prefix. Stored
    /// lowercase unless --checksum, when the typed case is the thing being asked for.
    fn new_evm(p: &PatternArgs) -> Result<Self, String> {
        if p.path == PathStyle::Legacy {
            return Err("--path legacy is Solana-only; EVM always uses m/44'/60'/0'/0/N".into());
        }
        if p.checksum && p.ignore_case {
            return Err(
                "--checksum binds the typed case to EIP-55; --ignore-case frees it - pick one"
                    .into(),
            );
        }
        let keep = p.checksum;
        let check = |s: &String, is_prefix: bool| -> Result<Vec<u8>, String> {
            let body = evm::check_pattern(s, is_prefix)?;
            if body.len() > 40 {
                return Err("longer than an address (40 hex digits)".into());
            }
            Ok(if keep {
                body.into_bytes()
            } else {
                body.to_ascii_lowercase().into_bytes()
            })
        };
        let suffixes = canonical_patterns(
            p.ends_with
                .iter()
                .map(|s| check(s, false))
                .collect::<Result<_, _>>()?,
            false,
            !p.checksum,
        );
        let prefixes = canonical_patterns(
            p.starts_with
                .iter()
                .map(|s| check(s, true))
                .collect::<Result<_, _>>()?,
            true,
            !p.checksum,
        );
        let max_suffix = suffixes.iter().map(|s| s.len()).max().unwrap_or(0);
        if max_suffix > 16 {
            return Err("suffix longer than 16 chars".into());
        }
        let prefix_choices: Vec<&[u8]> = if prefixes.is_empty() {
            vec![b""]
        } else {
            prefixes.iter().map(Vec::as_slice).collect()
        };
        let suffix_choices: Vec<&[u8]> = if suffixes.is_empty() {
            vec![b""]
        } else {
            suffixes.iter().map(Vec::as_slice).collect()
        };
        let mut possible_pairs = 0usize;
        let mut probability = 0.0f64;
        let mut probability_approximate = false;
        let mut enumeration_budget = MAX_EVM_CHECKSUM_ENUMERATIONS;
        for prefix in &prefix_choices {
            for suffix in &suffix_choices {
                if let Some(analysis) =
                    analyze_evm_edges(prefix, suffix, p.checksum, &mut enumeration_budget)?
                {
                    possible_pairs += 1;
                    probability += analysis.probability;
                    probability_approximate |= analysis.approximate;
                }
            }
        }
        if possible_pairs == 0 {
            return Err(if p.checksum {
                "EVM edge constraints conflict or cannot form any address with the requested EIP-55 checksum case".into()
            } else {
                "EVM prefix and suffix constraints conflict where they overlap".into()
            });
        }
        Ok(Matcher {
            chain: Chain::Evm,
            needs_full: !prefixes.is_empty(),
            max_suffix,
            suffixes,
            prefixes,
            ignore_case: !p.checksum,
            checksum: p.checksum,
            probability: probability.min(1.0),
            probability_approximate,
        })
    }

    #[inline]
    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.ignore_case {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    }

    fn address_hit(&self, address: &str) -> bool {
        match self.chain {
            Chain::Sol => {
                let address = address.as_bytes();
                let suffix_ok = self.suffixes.is_empty()
                    || self.suffixes.iter().any(|suffix| {
                        address.len() >= suffix.len()
                            && self.eq(&address[address.len() - suffix.len()..], suffix)
                    });
                let prefix_ok = self.prefixes.is_empty()
                    || self.prefixes.iter().any(|prefix| {
                        address.len() >= prefix.len() && self.eq(&address[..prefix.len()], prefix)
                    });
                suffix_ok && prefix_ok
            }
            Chain::Evm => {
                let Some(hex) = address.strip_prefix("0x") else {
                    return false;
                };
                if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return false;
                }
                let mut lower = [0u8; 40];
                lower.copy_from_slice(hex.to_ascii_lowercase().as_bytes());
                let mut raw = [0u8; 20];
                for (index, pair) in lower.chunks_exact(2).enumerate() {
                    let Ok(pair) = std::str::from_utf8(pair) else {
                        return false;
                    };
                    let Ok(byte) = u8::from_str_radix(pair, 16) else {
                        return false;
                    };
                    raw[index] = byte;
                }
                self.evm_hit(&lower, &raw)
            }
        }
    }

    /// The exact address text that satisfied this matcher, for the managed
    /// per-match filename.  The requested pattern names the lane; this value
    /// preserves the case that actually landed.  Canonicalized alternatives
    /// are disjoint, so the first matching edge is deterministic.
    fn realized_filename_edge(&self, address: &str) -> std::io::Result<String> {
        let body = match self.chain {
            Chain::Sol => address,
            Chain::Evm => address.strip_prefix("0x").ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "EVM match address has no 0x prefix",
                )
            })?,
        };
        let bytes = body.as_bytes();
        let prefix = self.prefixes.iter().find_map(|pattern| {
            (bytes.len() >= pattern.len() && self.eq(&bytes[..pattern.len()], pattern))
                .then(|| &body[..pattern.len()])
        });
        let suffix = self.suffixes.iter().find_map(|pattern| {
            (bytes.len() >= pattern.len()
                && self.eq(&bytes[bytes.len() - pattern.len()..], pattern))
            .then(|| &body[body.len() - pattern.len()..])
        });
        let edge = match (prefix, suffix) {
            (Some(prefix), Some(suffix)) => format!("{prefix}...{suffix}"),
            (Some(prefix), None) => prefix.to_string(),
            (None, Some(suffix)) => suffix.to_string(),
            (None, None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "match address does not satisfy its filename lane",
                ))
            }
        };
        if edge.is_empty()
            || !edge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "match filename edge is not safe ASCII",
            ));
        }
        Ok(edge)
    }

    fn max_realized_filename_edge_len(&self) -> usize {
        let prefix = self.prefixes.iter().map(Vec::len).max().unwrap_or(0);
        let suffix = self.suffixes.iter().map(Vec::len).max().unwrap_or(0);
        prefix + suffix + usize::from(prefix > 0 && suffix > 0) * 3
    }

    /// EVM: does this address match? `lower` is its forty lowercase hex digits. The
    /// any-case test is the cheap one and runs first; only a candidate that passes it
    /// pays for the EIP-55 casing, and only when --checksum asked for it.
    #[inline]
    fn evm_hit(&self, lower: &[u8; 40], addr: &[u8; 20]) -> bool {
        // OR within a kind, AND across kinds - same grammar as Solana.
        let s_any = self.suffixes.is_empty()
            || self
                .suffixes
                .iter()
                .any(|s| lower[40 - s.len()..].eq_ignore_ascii_case(s));
        if !s_any {
            return false;
        }
        let p_any = self.prefixes.is_empty()
            || self
                .prefixes
                .iter()
                .any(|p| lower[..p.len()].eq_ignore_ascii_case(p));
        if !p_any {
            return false;
        }
        if !self.checksum {
            return true;
        }
        let cs = evm::eip55(addr);
        let cs = &cs.as_bytes()[2..];
        (self.suffixes.is_empty()
            || self
                .suffixes
                .iter()
                .any(|s| &cs[40 - s.len()..] == s.as_slice()))
            && (self.prefixes.is_empty()
                || self.prefixes.iter().any(|p| &cs[..p.len()] == p.as_slice()))
    }

    /// Per-candidate hit probability.
    fn probability(&self) -> f64 {
        self.probability
    }

    fn probability_is_approximate(&self) -> bool {
        self.probability_approximate
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
    /// followed by the 32-byte public key) - what the current Phantom and
    /// Solflare private-key import flows paste.
    privkey: Zeroizing<String>,
    /// The same 64 bytes as a JSON array - `[12,34,...]` - what
    /// solana-keygen reads. Empty for EVM, which has one
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

/// The same 64 bytes as the JSON byte array solana-keygen writes:
/// `[12,34,...]`, no spaces.
fn keypair_json(secret: &[u8; 32]) -> Zeroizing<String> {
    let kp = keypair_bytes(secret);
    let mut body = Zeroizing::new(String::with_capacity(257));
    body.push('[');
    for (i, b) in kp.iter().enumerate() {
        if i != 0 {
            body.push(',');
        }
        write!(&mut *body, "{}", b).expect("writing to a String cannot fail");
    }
    body.push(']');
    body
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
        let (kp, cp) = (Zeroizing::new(kp), Zeroizing::new(cp));
        k.zeroize();
        c.zeroize();
        k2.zeroize();
        c2.zeroize();

        for idx in 0..indices {
            let (mut ka, mut ca) = derive_hardened(&kp, &cp, idx);
            let mut kf = if path == PathStyle::Phantom {
                let (key, mut chain) = derive_hardened(&ka, &ca, 0);
                chain.zeroize();
                key
            } else {
                ka
            };
            let pk = SigningKey::from_bytes(&kf).verifying_key().to_bytes();
            kf.zeroize();
            ka.zeroize();
            ca.zeroize();

            local += 1;
            if local >= 4096 {
                counter.fetch_add(local, Ordering::Relaxed);
                local = 0;
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }

            // OR within a kind, AND across kinds. Several suffixes are alternatives,
            // several prefixes are alternatives, but a run given BOTH kinds wants one
            // address satisfying both ends - `--starts-with cMaiL --ends-with gg` is
            // one address, not two hunts. 0.4.11 pooled every pattern into one OR and
            // stopped on the first *gg; the help had promised the conjunction all along.
            let mut suffix_ok = m.suffixes.is_empty();
            if !suffix_ok {
                b58_suffix(&pk, m.max_suffix, &mut suffix);
                for s in &m.suffixes {
                    if m.eq(&suffix[m.max_suffix - s.len()..m.max_suffix], s) {
                        suffix_ok = true;
                        break;
                    }
                }
            }
            // A candidate that failed every suffix is dead before paying for the full
            // encoding, whatever the prefixes say.
            let hit = suffix_ok
                && (!m.needs_full || {
                    let full = bs58::encode(pk).into_string();
                    m.prefixes
                        .iter()
                        .any(|p| full.len() >= p.len() && m.eq(&full.as_bytes()[..p.len()], p))
                });

            if hit {
                counter.fetch_add(local, Ordering::Relaxed);
                local = 0;
                // The secret was zeroized before the match test (kept alive
                // for no candidate that loses). Re-derive it for the winner:
                // two HMACs, on the one path in ~10 million that needs it.
                let (mut ka2, mut ca2) = derive_hardened(&kp, &cp, idx);
                let mut secret = if path == PathStyle::Phantom {
                    let (key, mut chain) = derive_hardened(&ka2, &ca2, 0);
                    chain.zeroize();
                    key
                } else {
                    ka2
                };
                let privkey = keypair_b58(&secret);
                let keypair_json = keypair_json(&secret);
                secret.zeroize();
                ka2.zeroize();
                ca2.zeroize();
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
        let Some(branch) = evm::Branch::from_seed(seed.as_ref()) else {
            continue;
        };

        for idx in 0..indices {
            let Some(addr) = branch.address_at(idx) else {
                continue;
            };

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
                let Some(mut k) = branch.key_at(idx) else {
                    continue;
                };
                let privkey = evm::privkey_hex(&k);
                k.zeroize();
                on_hit(Hit {
                    chain: Chain::Evm,
                    index: idx,
                    address: evm::eip55(&addr),
                    mnemonic: Zeroizing::new(mnemonic.to_string()),
                    passphrase: !passphrase.is_empty(),
                    privkey,
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
fn per_candidate_cost(chain: Chain, path: PathStyle) -> f64 {
    match (chain, path) {
        (Chain::Sol, PathStyle::Phantom) => 21e-6,
        // Legacy omits the final hardened child. This remains a rough fallback;
        // `bench --path legacy` is the authoritative local lane.
        (Chain::Sol, PathStyle::Legacy) => 12e-6,
        (Chain::Evm, _) => EVM_PER_CANDIDATE,
    }
}
/// Measured on the development machine, 2026-08-20, release build: the number
/// the model is anchored to until `bench --chain evm` replaces it with yours.
const EVM_PER_CANDIDATE: f64 = 65e-6;

/// Candidates per second per thread the model predicts at `indices` per mnemonic.
fn model_rate(chain: Chain, path: PathStyle, indices: u32) -> f64 {
    1.0 / (1.2e-3 / indices as f64 + per_candidate_cost(chain, path))
}

// ---------------------------------------------------------------- rate cache

/// `bench` writes the measured rate here; `estimate` reads it. The
/// theoretical model (1.2ms/indices + 21us) ran 2.6x optimistic on the
/// first machine it met -- an estimate should come from what THIS box
/// measured, not from a formula.
/// `<XDG_DATA_HOME or ~/.local/share>/keyrx/` - the tool's own directory.
fn detected_data_dir() -> Option<std::path::PathBuf> {
    let env_path = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let base = env_path("XDG_DATA_HOME")
        .or_else(|| env_path("HOME").map(|h| h.join(".local/share")))
        .or_else(|| env_path("LOCALAPPDATA"))
        .or_else(|| env_path("APPDATA"))
        .or_else(|| env_path("USERPROFILE").map(|h| h.join("AppData/Local")))?;
    Some(base.join("keyrx"))
}

fn data_dir() -> std::path::PathBuf {
    detected_data_dir().unwrap_or_else(|| {
        eprintln!(
            "cannot locate a private data directory: set XDG_DATA_HOME or HOME, or use --out"
        );
        std::process::exit(1);
    })
}

/// One measured rate per chain: `bench.txt` for Solana (the file the first
/// releases wrote), `bench-evm.txt` for EVM. The two loops cost nothing alike.
fn rate_cache_path(chain: Chain, path: PathStyle, words: usize) -> Option<std::path::PathBuf> {
    let lane = rate_lane_id(chain, path);
    detected_data_dir().map(|dir| dir.join(format!("bench-{}-{}w.txt", lane, words)))
}

fn rate_lane_id(chain: Chain, path: PathStyle) -> &'static str {
    match (chain, path) {
        (Chain::Sol, PathStyle::Phantom) => "sol-phantom",
        (Chain::Sol, PathStyle::Legacy) => "sol-legacy",
        (Chain::Evm, _) => "evm-bip44",
    }
}

/// The matcher shape whose candidate throughput `bench` actually measures.
/// A saved rate is exact only for this whole workload, not merely for its
/// chain, derivation path, thread count, and index count.
#[derive(Copy, Clone, Debug, PartialEq)]
enum BenchWorkload {
    SolSuffix5CaseSensitive,
    EvmSuffix16AnyCase,
}

impl BenchWorkload {
    fn for_chain(chain: Chain) -> Self {
        match chain {
            Chain::Sol => Self::SolSuffix5CaseSensitive,
            Chain::Evm => Self::EvmSuffix16AnyCase,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::SolSuffix5CaseSensitive => "sol-suffix5-case",
            Self::EvmSuffix16AnyCase => "evm-suffix16-anycase",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "sol-suffix5-case" => Some(Self::SolSuffix5CaseSensitive),
            "evm-suffix16-anycase" => Some(Self::EvmSuffix16AnyCase),
            _ => None,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::SolSuffix5CaseSensitive => "one case-sensitive 5-char Solana suffix",
            Self::EvmSuffix16AnyCase => "one any-case 16-hex EVM suffix",
        }
    }

    fn is_exact_for(self, matcher: &Matcher) -> bool {
        match self {
            Self::SolSuffix5CaseSensitive => {
                matcher.chain == Chain::Sol
                    && matcher.prefixes.is_empty()
                    && matcher.suffixes.len() == 1
                    && matcher.suffixes[0].len() == 5
                    && !matcher.ignore_case
            }
            Self::EvmSuffix16AnyCase => {
                matcher.chain == Chain::Evm
                    && matcher.prefixes.is_empty()
                    && matcher.suffixes.len() == 1
                    && matcher.suffixes[0].len() == 16
                    && !matcher.checksum
            }
        }
    }
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
    match chain {
        Chain::Sol => matches_dir(),
        Chain::Evm => matches_dir().join("evm"),
    }
}

/// The pattern names a managed output lane. Each hit adds its realized address
/// edge and `.md`; the retained `.txt` suffix exists only to keep the lane and
/// marker identity compatible with earlier default-output coordination.
/// Alternatives join with '+'; prefixes carry a trailing `_`; both kinds join
/// as PREFIX_...SUFFIX. Case-insensitive adds `.ic`; EVM uses `.cs` for checksum.
fn default_out(p: &PatternArgs) -> std::path::PathBuf {
    let strip = |s: &String| -> String {
        if p.chain == Chain::Evm {
            s.strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s)
                .to_string()
        } else {
            s.clone()
        }
    };
    let suff: Vec<String> = p.ends_with.iter().map(&strip).collect();
    let pref: Vec<String> = p
        .starts_with
        .iter()
        .map(|s| format!("{}_", strip(s)))
        .collect();
    let mut name = match (pref.is_empty(), suff.is_empty()) {
        (true, true) => "matches".to_string(),
        (false, false) => format!("{}...{}", pref.join("+"), suff.join("+")),
        _ => {
            let mut v = suff;
            v.extend(pref);
            v.join("+")
        }
    };
    match p.chain {
        Chain::Sol => {
            if p.ignore_case {
                name.push_str(".ic");
            }
        }
        Chain::Evm => {
            if p.checksum {
                name.push_str(".cs");
            } else {
                name = name.to_ascii_lowercase();
            }
        }
    }
    name.push_str(".txt");
    matches_dir_for(p.chain).join(name)
}

/// A path for the eye: files under the tool's own data dir print as
/// `matches/KEYRX.KEYRX.md`; anything else prints whole. The full path is always
/// in the foot of the panel that names the file.
fn short_path(p: &std::path::Path) -> String {
    if let Some(dir) = detected_data_dir().map(|d| d.join("matches")) {
        if let Ok(rel) = p.strip_prefix(&dir) {
            return format!("matches/{}", ui::path_text(rel));
        }
    }
    ui::path_text(p)
}

fn output_protection() -> &'static str {
    if cfg!(unix) {
        "mode 0600"
    } else {
        "secret commands refuse until an owner-only ACL is implemented"
    }
}

#[cfg(unix)]
fn sync_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(parent)?.sync_all()
}

fn private_create_new(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn cache_stage_path(path: &std::path::Path, label: &str) -> std::path::PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "cache".into());
    // A PID-only stage name can collide with a stale file after PID reuse. An
    // unpredictable nonce makes every attempt a new create-new operation; a
    // collision still refuses rather than truncating somebody else's bytes.
    let nonce = OsRng.next_u64();
    path.with_file_name(format!(
        ".{}.{}.{}.{:016x}",
        name,
        label,
        std::process::id(),
        nonce
    ))
}

fn append_path_suffix(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    std::path::PathBuf::from(value)
}

fn rate_cache_receipt_path(path: &std::path::Path) -> std::path::PathBuf {
    append_path_suffix(path, ".valid")
}

fn rate_cache_lock_path(path: &std::path::Path) -> std::path::PathBuf {
    append_path_suffix(path, ".bench.lock")
}

fn rate_cache_guard_path(path: &std::path::Path) -> std::path::PathBuf {
    append_path_suffix(path, ".bench.guard")
}

#[cfg(unix)]
fn private_file_identity(meta: &std::fs::Metadata) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o777 != 0o600
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "benchmark ceremony file is not a private single-link regular file",
        ));
    }
    Ok((meta.dev(), meta.ino()))
}

#[cfg(unix)]
fn path_is_inode(path: &std::path::Path, dev: u64, ino: u64) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    Ok(meta.is_file() && meta.dev() == dev && meta.ino() == ino)
}

/// A fixed, advisory-locked marker excludes another benchmark for the same
/// final cache. The pathname remains present for the whole ceremony, so a
/// failed ceremony poisons cache reads. A later benchmark can reclaim it only
/// after proving no process still owns the exact inode.
struct RateCacheCeremonyLock {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    #[cfg(unix)]
    _guard: std::fs::File,
    released: bool,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl RateCacheCeremonyLock {
    #[cfg(unix)]
    fn try_lock(file: &std::fs::File) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Ok(())
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "another benchmark already owns this cache lane",
                ))
            } else {
                Err(error)
            }
        }
    }

    #[cfg(unix)]
    fn open_guard(final_path: &std::path::Path, exclusive: bool) -> std::io::Result<std::fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let path = rate_cache_guard_path(final_path);
        let file = match private_create_new(&path) {
            Ok(file) => {
                file.sync_all()?;
                sync_parent_dir(&path)?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut options = std::fs::OpenOptions::new();
                options
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
                options.open(&path)?
            }
            Err(error) => return Err(error),
        };
        let (dev, ino) = private_file_identity(&file.metadata()?)?;
        let operation = if exclusive {
            libc::LOCK_EX | libc::LOCK_NB
        } else {
            libc::LOCK_SH | libc::LOCK_NB
        };
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "benchmark cache lane is in use",
                ))
            } else {
                Err(error)
            };
        }
        if !path_is_inode(&path, dev, ino)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "benchmark guard identity changed while it was acquired",
            ));
        }
        Ok(file)
    }

    #[cfg(unix)]
    fn open_existing(path: &std::path::Path) -> std::io::Result<(std::fs::File, u64, u64)> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let file = options.open(path)?;
        let (dev, ino) = private_file_identity(&file.metadata()?)?;
        Self::try_lock(&file)?;
        if !path_is_inode(path, dev, ino)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "benchmark ceremony marker identity changed while it was acquired",
            ));
        }
        Ok((file, dev, ino))
    }

    #[cfg(unix)]
    fn invalidate_receipt(final_path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let receipt = rate_cache_receipt_path(final_path);
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let file = match options.open(&receipt) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let (dev, ino) = private_file_identity(&file.metadata()?)?;
        if !path_is_inode(&receipt, dev, ino)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "benchmark validity receipt identity changed before invalidation",
            ));
        }
        std::fs::remove_file(&receipt)?;
        sync_parent_dir(&receipt)
    }

    fn acquire(final_path: &std::path::Path) -> std::io::Result<Self> {
        prepare_output_parent(final_path, true)?;
        #[cfg(unix)]
        let guard = Self::open_guard(final_path, true)?;
        let path = rate_cache_lock_path(final_path);
        #[cfg(unix)]
        {
            for attempt in 0..2 {
                match private_create_new(&path) {
                    Ok(mut file) => {
                        let (dev, ino) = private_file_identity(&file.metadata()?)?;
                        Self::try_lock(&file)?;
                        let nonce = OsRng.next_u64();
                        writeln!(
                            file,
                            "keyrx-bench-lock-v1 {} {:016x}",
                            std::process::id(),
                            nonce
                        )?;
                        file.sync_all()?;
                        if !path_is_inode(&path, dev, ino)? {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "benchmark ceremony marker identity changed before timing",
                            ));
                        }
                        sync_parent_dir(&path)?;
                        let lock = Self {
                            path,
                            file: Some(file),
                            _guard: guard,
                            released: false,
                            dev,
                            ino,
                        };
                        // A cache is acceptable only with its receipt. Remove the old
                        // receipt while this lane is exclusively held, before timing.
                        Self::invalidate_receipt(final_path)?;
                        return Ok(lock);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let (file, dev, ino) = Self::open_existing(&path).map_err(|error| {
                            if error.kind() == std::io::ErrorKind::WouldBlock {
                                std::io::Error::new(
                                    error.kind(),
                                    "another benchmark already owns this cache lane",
                                )
                            } else {
                                error
                            }
                        })?;
                        // The inode is unlocked, so its owner is gone. Invalidate any
                        // old receipt before reclaiming this exact stale marker.
                        Self::invalidate_receipt(final_path)?;
                        if !path_is_inode(&path, dev, ino)? {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "stale benchmark marker identity changed before recovery",
                            ));
                        }
                        std::fs::remove_file(&path)?;
                        sync_parent_dir(&path)?;
                        drop(file);
                        if attempt == 1 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "benchmark marker was recreated during stale recovery",
                            ));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            unreachable!("two-attempt benchmark marker loop always returns")
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "benchmark ceremony locking is not implemented on this platform",
            ))
        }
    }

    fn release_success(&mut self) -> std::io::Result<()> {
        if self.released {
            return Ok(());
        }
        #[cfg(unix)]
        {
            if !path_is_inode(&self.path, self.dev, self.ino)? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "benchmark ceremony marker identity changed before release",
                ));
            }
            std::fs::remove_file(&self.path)?;
            self.released = true;
            // The cache and its receipt were durably committed before this point.
            // If flushing the unlink fails, either crash outcome is safe: a
            // surviving marker rejects the cache; an absent marker exposes the
            // already-durable, digest-bound pair.
            let _ = sync_parent_dir(&self.path);
            self.file.take();
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "benchmark ceremony locking is not implemented on this platform",
            ))
        }
    }
}

/// A unique, held staging inode. It removes only its own still-named inode on
/// failure; an installed inode is deliberately left for the validity protocol.
struct HeldCacheStage {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    installed: bool,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl HeldCacheStage {
    fn create(final_path: &std::path::Path, label: &str) -> std::io::Result<Self> {
        let path = cache_stage_path(final_path, label);
        let file = private_create_new(&path)?;
        let meta = file.metadata()?;
        #[cfg(unix)]
        {
            let (dev, ino) = private_file_identity(&meta)?;
            Ok(Self {
                path,
                file: Some(file),
                installed: false,
                dev,
                ino,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                path,
                file: Some(file),
                installed: false,
            })
        }
    }

    fn identity_is_held(&self) -> std::io::Result<bool> {
        #[cfg(unix)]
        {
            path_is_inode(&self.path, self.dev, self.ino)
        }
        #[cfg(not(unix))]
        {
            Ok(std::fs::symlink_metadata(&self.path)?.is_file())
        }
    }

    fn write_synced(&mut self, body: &[u8]) -> std::io::Result<()> {
        let file = self.file.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "benchmark cache stage is no longer held",
            )
        })?;
        file.write_all(body)?;
        file.sync_all()?;
        if !self.identity_is_held()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "benchmark cache stage identity changed before commit",
            ));
        }
        Ok(())
    }

    fn install(&mut self, final_path: &std::path::Path) -> std::io::Result<()> {
        if !self.identity_is_held()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "benchmark cache stage identity changed before installation",
            ));
        }
        drop(self.file.take());
        std::fs::rename(&self.path, final_path)?;
        self.installed = true;
        Ok(())
    }
}

impl Drop for HeldCacheStage {
    fn drop(&mut self) {
        if !self.installed && self.identity_is_held().unwrap_or(false) {
            let _ = std::fs::remove_file(&self.path);
            #[cfg(unix)]
            let _ = sync_parent_dir(&self.path);
        }
    }
}

struct RateCacheStage {
    final_path: std::path::PathBuf,
    receipt_path: std::path::PathBuf,
    cache: HeldCacheStage,
    receipt: HeldCacheStage,
    ceremony: RateCacheCeremonyLock,
}

impl RateCacheStage {
    fn acquire(final_path: &std::path::Path) -> std::io::Result<Self> {
        let ceremony = RateCacheCeremonyLock::acquire(final_path)?;
        let receipt_path = rate_cache_receipt_path(final_path);
        let cache = HeldCacheStage::create(final_path, "stage")?;
        let receipt = HeldCacheStage::create(&receipt_path, "stage")?;
        Ok(Self {
            final_path: final_path.to_path_buf(),
            receipt_path,
            cache,
            receipt,
            ceremony,
        })
    }

    fn commit(mut self, body: &[u8]) -> std::io::Result<std::path::PathBuf> {
        let digest = format!("{:x}", Sha256::digest(body));
        let receipt = format!("keyrx-rate-valid-v1 {}\n", digest);
        self.cache.write_synced(body)?;
        self.receipt.write_synced(receipt.as_bytes())?;
        self.cache.install(&self.final_path)?;
        #[cfg(unix)]
        sync_parent_dir(&self.final_path)?;
        self.receipt.install(&self.receipt_path)?;
        #[cfg(unix)]
        sync_parent_dir(&self.receipt_path)?;
        // Any failure before this release leaves the exact ceremony marker in
        // place. `load_rate` refuses while that poison marker exists.
        self.ceremony.release_success()?;
        Ok(self.final_path.clone())
    }
}

/// The match file as `short_path` prints it, clickable: the click opens the
/// FOLDER it sits in, never the file - a seed is read with `show --keys`, on
/// purpose, not by a stray click into whatever the desktop opens the file with.
fn out_link(path: &std::path::Path) -> String {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let abs = std::fs::canonicalize(&dir)
        .unwrap_or_else(|_| std::env::current_dir().map(|c| c.join(&dir)).unwrap_or(dir));
    ui::link(&ui::file_url(&abs), &short_path(path))
}

#[cfg(unix)]
fn executable_fingerprint() -> std::io::Result<String> {
    const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    let mut file = std::fs::File::open("/proc/self/exe")?;
    #[cfg(not(target_os = "linux"))]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::current_exe()?;
        let before = std::fs::symlink_metadata(&path)?;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(&path)?;
        use std::os::unix::fs::MetadataExt;
        let held = file.metadata()?;
        let after = std::fs::symlink_metadata(&path)?;
        if !held.is_file()
            || before.dev() != held.dev()
            || before.ino() != held.ino()
            || after.dev() != held.dev()
            || after.ino() != held.ino()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "running executable identity changed while it was opened",
            ));
        }
        file
    };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_EXECUTABLE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "running executable is not a bounded regular file",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read = read.saturating_add(n as u64);
        if read > MAX_EXECUTABLE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "running executable grew beyond the fingerprint bound",
            ));
        }
        hasher.update(&buf[..n]);
    }
    if read != meta.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "running executable changed while it was fingerprinted",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(not(unix))]
fn executable_fingerprint() -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "running-executable fingerprinting is not implemented on this platform",
    ))
}

#[allow(clippy::too_many_arguments)]
fn rate_cache_body(
    chain: Chain,
    path: PathStyle,
    words: usize,
    threads: usize,
    indices: u32,
    rate: f64,
    executable: &str,
    workload: BenchWorkload,
) -> String {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    format!(
        "keyrx-rate-v4 {} {} {} {} {} {} {} {} {} {} {:.17}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        profile,
        executable,
        rate_lane_id(chain, path),
        words,
        threads,
        indices,
        workload.id(),
        rate,
    )
}

#[allow(clippy::too_many_arguments)]
fn save_rate(
    stage: RateCacheStage,
    chain: Chain,
    path: PathStyle,
    words: usize,
    threads: usize,
    indices: u32,
    rate: f64,
    executable: &str,
) -> std::io::Result<std::path::PathBuf> {
    let workload = BenchWorkload::for_chain(chain);
    stage.commit(
        rate_cache_body(
            chain, path, words, threads, indices, rate, executable, workload,
        )
        .as_bytes(),
    )
}

fn read_rate_cache(path: &std::path::Path) -> std::io::Result<String> {
    const MAX_RATE_CACHE_BYTES: u64 = 512;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_RATE_CACHE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "benchmark cache is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
            || meta.permissions().mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "benchmark cache is not an owner-private single-link file",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    (&mut file)
        .take(MAX_RATE_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != meta.len() || bytes.len() as u64 > MAX_RATE_CACHE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "benchmark cache changed while it was read",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "benchmark cache is not UTF-8",
        )
    })
}

#[derive(Copy, Clone)]
struct MeasuredRate {
    threads: usize,
    indices: u32,
    rate: f64,
    workload: BenchWorkload,
}

fn cache_lane_is_unlocked(path: &std::path::Path) -> bool {
    matches!(
        std::fs::symlink_metadata(rate_cache_lock_path(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// The last digest-bound benchmark for this exact executable and derivation
/// lane. A marker means a ceremony is running or failed, and either state
/// invalidates the cache until a later benchmark safely reclaims the lane.
#[cfg(unix)]
fn load_rate(chain: Chain, path: PathStyle, words: usize) -> Option<MeasuredRate> {
    let cache_path = rate_cache_path(chain, path, words)?;
    // The persistent guard is the atomic boundary the old double marker check
    // lacked. A benchmark holds it exclusively from before invalidation until
    // after commit; an estimate holds it shared through every read, parse and
    // executable-identity decision below.
    std::fs::symlink_metadata(&cache_path).ok()?;
    let _guard = RateCacheCeremonyLock::open_guard(&cache_path, false).ok()?;
    if !cache_lane_is_unlocked(&cache_path) {
        return None;
    }
    let s = read_rate_cache(&cache_path).ok()?;
    let receipt = read_rate_cache(&rate_cache_receipt_path(&cache_path)).ok()?;
    let expected_receipt = format!("keyrx-rate-valid-v1 {:x}\n", Sha256::digest(s.as_bytes()));
    if receipt != expected_receipt || !cache_lane_is_unlocked(&cache_path) {
        return None;
    }
    let executable = executable_fingerprint().ok()?;
    let mut it = s.split_whitespace();
    if it.next()? != "keyrx-rate-v4"
        || it.next()? != env!("CARGO_PKG_VERSION")
        || it.next()? != std::env::consts::OS
        || it.next()? != std::env::consts::ARCH
        || it.next()?
            != if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        || it.next()? != executable
        || it.next()? != rate_lane_id(chain, path)
        || it.next()?.parse::<usize>().ok()? != words
    {
        return None;
    }
    let threads: usize = it.next()?.parse().ok()?;
    let indices: u32 = it.next()?.parse().ok()?;
    let workload = BenchWorkload::parse(it.next()?)?;
    let rate: f64 = it.next()?.parse().ok()?;
    if it.next().is_some()
        || threads == 0
        || indices == 0
        || !rate.is_finite()
        || rate <= 0.0
        || workload != BenchWorkload::for_chain(chain)
    {
        return None;
    }
    if s != rate_cache_body(
        chain,
        path,
        words,
        threads,
        indices,
        rate,
        &executable,
        workload,
    ) {
        return None;
    }
    Some(MeasuredRate {
        threads,
        indices,
        rate,
        workload,
    })
}

#[cfg(not(unix))]
fn load_rate(chain: Chain, path: PathStyle, words: usize) -> Option<MeasuredRate> {
    let _ = (chain, path, words);
    None
}

// ---------------------------------------------------------------- output

/// 656356768 -> "656,356,768". Whole numbers only; the callers round first.
fn group(v: f64) -> String {
    let s = format!("{:.0}", v);
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s.as_str()),
    };
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    if neg {
        format!("-{}", out)
    } else {
        out
    }
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
/// m/44'/60'/0'/0/N, the software-wallet account path keyRX derives.
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
        return vec![
            "Seed:     use only in a wallet that supports the exact printed path".to_string(),
            format!("          (index {idx}); verify the address before funding"),
        ];
    }
    match style {
        PathStyle::Phantom => {
            if idx == 0 {
                vec![
                    "Seed:     printed path is account #1 in the supported path family".to_string(),
                    "          wallet/version support varies; verify before funding".to_string(),
                ]
            } else {
                vec![
                    format!("Seed:     printed recovery path {}", path_str(style, idx)),
                    "          wallet/version discovery varies; private-key import is exact"
                        .to_string(),
                ]
            }
        }
        PathStyle::Legacy => vec![
            format!("Seed:     printed legacy path {}", path_str(style, idx)),
            "          use only where the wallet/version supports that exact path".to_string(),
        ],
    }
}

const MATCH_FILE_HEADER_VERSION: &str = "keyrx-match-v1";
const MATCH_FILE_RECIPE_LABEL: &str =
    "creation recipe (count, output, display, and worker settings omitted):";
const MAX_MATCH_FILE_HEADER_BYTES: usize = 64 * 1024;

/// The saved recipe preserves everything that decides what addresses and
/// derivation lane are searched. Quantity, destination, terminal display and
/// worker count are intentionally left to the next run. Pattern values are
/// restricted to ASCII base58 or hex, so each is one safe shell word.
fn grind_creation_recipe(
    pattern: &PatternArgs,
    indices: u32,
    words: usize,
    with_passphrase: bool,
) -> Result<String, String> {
    let pattern_word = |value: &str| -> Result<String, String> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err("a creation-recipe pattern is not one safe ASCII word".into());
        }
        Ok(value.to_string())
    };
    let mut parts = vec![
        "keyrx".to_string(),
        "grind".to_string(),
        "--chain".to_string(),
        match pattern.chain {
            Chain::Sol => "sol",
            Chain::Evm => "evm",
        }
        .to_string(),
    ];
    for value in &pattern.ends_with {
        parts.push("--ends-with".into());
        parts.push(pattern_word(value)?);
    }
    for value in &pattern.starts_with {
        parts.push("--starts-with".into());
        parts.push(pattern_word(value)?);
    }
    if pattern.ignore_case {
        parts.push("--ignore-case".into());
    }
    if pattern.checksum {
        parts.push("--checksum".into());
    }
    if pattern.chain == Chain::Sol {
        parts.push("--path".into());
        parts.push(
            match pattern.path {
                PathStyle::Phantom => "phantom",
                PathStyle::Legacy => "legacy",
            }
            .into(),
        );
    }
    parts.push("--indices".into());
    parts.push(indices.to_string());
    parts.push("--words".into());
    parts.push(words.to_string());
    if with_passphrase {
        parts.push("--passphrase".into());
    }
    Ok(parts.join(" "))
}

// These rows are part of the keyrx-match-v1 on-disk format. Do not edit them
// under the same version: old private files must remain readable byte for byte.
fn match_header_rows(chain: Chain) -> &'static [&'static str] {
    match chain {
        Chain::Sol => &[
            "KEY IMPORT · exact address, standalone",
            "Phantom/Solflare: Import Private Key -> paste the base58 privkey.",
            "The existing wallet seed does not contain or recover an imported key.",
            "keypair is the same key as JSON for solana-keygen-compatible tools.",
            "",
            "SEED IMPORT · the whole deterministic wallet",
            "Use seed only with the exact path printed on each match.",
            "If Phantom walks m/44'/501'/N'/0', N=89 is account #90:",
            "89 Add Account steps after #1. Do not assume your version does.",
            "Wallet/version path discovery varies; the printed path is authoritative.",
            "Other accounts on this seed are not guaranteed vanity addresses.",
            "",
            "Verify the imported address before funding. Keep this 0600 file private.",
            "Ctrl/Cmd-click keyRX's printed output path in a supported terminal.",
        ],
        Chain::Evm => &[
            "KEY IMPORT · exact address, standalone across EVM networks",
            "MetaMask/Rabby: Import account -> Private key -> paste 0x hex privkey.",
            "The existing wallet seed does not contain or recover an imported key.",
            "",
            "SEED IMPORT · the whole deterministic wallet",
            "Use seed only where the wallet supports the exact path on each match:",
            "m/44'/60'/0'/0/N. Wallet/version path discovery varies.",
            "Other accounts on this seed are not guaranteed vanity addresses.",
            "",
            "Verify the imported address before funding. Keep this 0600 file private.",
            "Ctrl/Cmd-click keyRX's printed output path in a supported terminal.",
        ],
    }
}

fn push_match_header_row(out: &mut String, text: &str) -> std::io::Result<()> {
    let visible = text.chars().count();
    let width = ui::W
        .checked_sub(4)
        .ok_or_else(|| std::io::Error::other("match header frame width underflow"))?;
    if visible > width {
        return Err(std::io::Error::other(
            "match header copy exceeds the fixed frame width",
        ));
    }
    writeln!(out, "║  {}{}║", text, " ".repeat(width - visible))
        .expect("writing a match header row to a String cannot fail");
    Ok(())
}

#[derive(Clone)]
struct MatchFileHeader {
    chain: Chain,
    bytes: String,
    recipe: String,
}

fn format_match_file_header(chain: Chain, recipe: &str) -> std::io::Result<MatchFileHeader> {
    if recipe.is_empty()
        || recipe.len() > MAX_MATCH_FILE_HEADER_BYTES
        || recipe.chars().any(unsafe_terminal_char)
        || !recipe.is_ascii()
        || recipe
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            != recipe
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match header has an invalid creation recipe",
        ));
    }
    let title = match chain {
        Chain::Sol => "keyRX · SOLANA PRIVATE MATCH FILE",
        Chain::Evm => "keyRX · EVM PRIVATE MATCH FILE",
    };
    let mut bytes = String::new();
    let lead = format!("╔═ {} ", title);
    let lead_width = lead.chars().count();
    let fill = ui::W
        .checked_sub(lead_width + 1)
        .ok_or_else(|| std::io::Error::other("match header title exceeds its frame"))?;
    writeln!(&mut bytes, "{}{}╗", lead, "═".repeat(fill))
        .expect("writing a match header title to a String cannot fail");
    push_match_header_row(&mut bytes, MATCH_FILE_HEADER_VERSION)?;
    push_match_header_row(&mut bytes, "")?;
    for row in match_header_rows(chain) {
        push_match_header_row(&mut bytes, row)?;
    }
    writeln!(&mut bytes, "╚{}╝", "═".repeat(ui::W - 2))
        .expect("writing a match header foot to a String cannot fail");
    writeln!(&mut bytes, "{}", MATCH_FILE_RECIPE_LABEL)
        .expect("writing a match header label to a String cannot fail");
    writeln!(&mut bytes, "{}", recipe)
        .expect("writing a match header recipe to a String cannot fail");
    bytes.push('\n');
    if bytes.len() > MAX_MATCH_FILE_HEADER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match header exceeds its supported size",
        ));
    }
    Ok(MatchFileHeader {
        chain,
        bytes,
        recipe: recipe.to_string(),
    })
}

fn build_match_file_header(
    pattern: &PatternArgs,
    indices: u32,
    words: usize,
    with_passphrase: bool,
) -> std::io::Result<MatchFileHeader> {
    let recipe = grind_creation_recipe(pattern, indices, words, with_passphrase)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    format_match_file_header(pattern.chain, &recipe)
}

const MARKDOWN_MATCH_VERSION: &str = "keyrx-match-md-v1";
const MAX_MARKDOWN_MATCH_BYTES: usize = 64 * 1024;
const MARKDOWN_PRIVATE_WARNING: &str = "> **PRIVATE KEY MATERIAL:** This mode-0600 file controls the address recorded in it. Keep it private, keep a safe backup, and verify the address before funding.";
const MARKDOWN_SOL_GUIDANCE: &str = "- **Private-key import:** In Phantom or Solflare, choose Import Private Key and paste the base58 private key above. This imported account is standalone; an existing wallet seed does not contain it.\n- **JSON keypair:** The JSON array is the same key for solana-keygen-compatible tools.\n- **Seed recovery:** Use the seed only with the exact path above in a wallet/version that supports it. Path discovery varies. If a Phantom version walks `m/44'/501'/N'/0'`, index 89 is account #90, reached after 89 Add Account steps from account #1; do not assume every version does.\n- Other accounts from this seed are not guaranteed vanity addresses. Verify the exact address before funding.";
const MARKDOWN_EVM_GUIDANCE: &str = "- **Private-key import:** In MetaMask or Rabby, choose Import account, then Private key, and paste the 0x private key above. The imported account is the same standalone address across EVM networks; an existing wallet seed does not contain it.\n- **Seed recovery:** Use the seed only with the exact `m/44'/60'/0'/0/N` path above in a wallet/version that supports it. Path discovery varies.\n- Other accounts from this seed are not guaranteed vanity addresses. Verify the exact address before funding.";

fn markdown_match_title(chain: Chain) -> &'static str {
    match chain {
        Chain::Sol => "# keyRX · SOLANA PRIVATE MATCH",
        Chain::Evm => "# keyRX · EVM PRIVATE MATCH",
    }
}

fn markdown_match_guidance(chain: Chain) -> &'static str {
    match chain {
        Chain::Sol => MARKDOWN_SOL_GUIDANCE,
        Chain::Evm => MARKDOWN_EVM_GUIDANCE,
    }
}

fn markdown_private_key_heading(chain: Chain) -> &'static str {
    match chain {
        Chain::Sol => "PRIVATE KEY (BASE58)",
        Chain::Evm => "PRIVATE KEY (HEX)",
    }
}

/// One managed match is one complete Markdown document.  The allocation is
/// zeroized on drop; the fixed capacity prevents secret-bearing reallocations.
fn format_markdown_match_file(
    hit: &Hit,
    style: PathStyle,
    header: &MatchFileHeader,
) -> std::io::Result<Zeroizing<String>> {
    if hit.chain != header.chain {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Markdown match chain does not match its creation recipe",
        ));
    }
    let mut out = Zeroizing::new(String::with_capacity(MAX_MARKDOWN_MATCH_BYTES));
    let reserved = out.capacity();
    write!(
        &mut *out,
        "{}\n\nFormat: `{}`\n\n{}\n\n## ADDRESS\n\n{}\n\n## PATH\n\n{}\n\n## SEED\n\n{}\n\n## PASSPHRASE\n\n{}\n\n## {}\n\n{}\n\n",
        markdown_match_title(hit.chain),
        MARKDOWN_MATCH_VERSION,
        MARKDOWN_PRIVATE_WARNING,
        hit.address,
        path_for(hit.chain, style, hit.index),
        hit.mnemonic.as_str(),
        if hit.passphrase {
            "used - value not stored; the seed alone will not reach this address"
        } else {
            "not used"
        },
        markdown_private_key_heading(hit.chain),
        hit.privkey.as_str(),
    )
    .expect("writing a bounded Markdown match to a String cannot fail");
    if hit.chain == Chain::Sol {
        write!(
            &mut *out,
            "## KEYPAIR (JSON)\n\n{}\n\n",
            hit.keypair_json.as_str()
        )
        .expect("writing a bounded Markdown match to a String cannot fail");
    }
    write!(
        &mut *out,
        "## IMPORT AND RECOVERY\n\n{}\n\n## CREATION RECIPE\n\n`{}`\n",
        markdown_match_guidance(hit.chain),
        header.recipe,
    )
    .expect("writing a bounded Markdown match to a String cannot fail");
    if out.len() > MAX_MARKDOWN_MATCH_BYTES || out.capacity() != reserved {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match exceeds its fixed secret-buffer capacity",
        ));
    }
    Ok(out)
}

fn seed_display_rows(mnemonic: &str) -> Vec<String> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    words
        .chunks(6)
        .enumerate()
        .map(|(index, chunk)| {
            ui::mid(&format!(
                "  {}{:<11}{}{}{}{}",
                ui::gry(),
                if index == 0 { "seed" } else { "" },
                ui::r(),
                ui::wht(),
                chunk.join(" "),
                ui::r()
            ))
        })
        .collect()
}

/// Match files are intentionally bounded before any secret-bearing allocation.
/// 64 MiB holds more than 65,000 worst-case records while refusing a sparse or
/// malicious file that would otherwise make `show` or append allocate without
/// limit. A larger legitimate archive can be split into separate match files.
const MAX_PRIVATE_MATCH_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Read exactly the length reported by the already-held regular-file
/// descriptor. The vector has its final length and capacity before the first
/// secret byte is read, so it cannot leave an abandoned secret allocation via
/// growth. A short read, an extra byte, or a changed descriptor length is a
/// refusal rather than a partial snapshot.
fn read_held_private_bytes(
    file: &mut std::fs::File,
    meta: &std::fs::Metadata,
    path: &std::path::Path,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let held_len = meta.len();
    if held_len > MAX_PRIVATE_MATCH_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "private file is {} bytes; the supported maximum is {} bytes: {}",
                held_len,
                MAX_PRIVATE_MATCH_FILE_BYTES,
                ui::path_text(path)
            ),
        ));
    }
    let expected = usize::try_from(held_len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "private file length cannot fit in memory: {}",
                ui::path_text(path)
            ),
        )
    })?;
    let mut bytes = Zeroizing::new(vec![0u8; expected]);
    let reserved = bytes.capacity();
    if reserved != expected {
        return Err(std::io::Error::other(
            "private read buffer did not acquire the exact held length",
        ));
    }
    if let Err(error) = file.read_exact(bytes.as_mut_slice()) {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "private file changed length while its descriptor was held: {}",
                    ui::path_text(path)
                ),
            ));
        }
        return Err(error);
    }
    let mut extra = Zeroizing::new([0u8; 1]);
    let extra_read = file.read(extra.as_mut_slice())?;
    let after_len = file.metadata()?.len();
    if extra_read != 0 || after_len != held_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "private file changed length while its descriptor was held: {}",
                ui::path_text(path)
            ),
        ));
    }
    if bytes.len() != expected || bytes.capacity() != reserved {
        return Err(std::io::Error::other(
            "private read buffer changed allocation after custody began",
        ));
    }
    Ok(bytes)
}

/// `keyrx show`: list matches in the file WITHOUT the seeds. Address and path
/// are safe to read aloud, paste, and verify; the seed stays in the 0600 file.
fn read_private_text(path: &std::path::Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("private file is a symlink: {}", ui::path_text(path)),
        ));
    }
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "private path is not a regular file: {}",
                ui::path_text(path)
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "private file is not owned by this user: {}",
                    ui::path_text(path)
                ),
            ));
        }
        if meta.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "private file has {} hard links; refusing aliases: {}",
                    meta.nlink(),
                    ui::path_text(path)
                ),
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            let quoted = path
                .to_str()
                .map(shell_quote_posix)
                .unwrap_or_else(|| "<non-UTF-8 path>".to_string());
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "private file mode is {:03o}; run chmod 600 -- {} before reading it",
                    mode, quoted
                ),
            ));
        }
    }
    read_held_private_bytes(&mut file, &meta, path)
}

fn unsafe_terminal_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Paths supplied on the command line are later printed in status and error
/// messages. Refuse bytes that cannot be represented faithfully, and refuse
/// terminal controls/bidi overrides instead of letting a filename rewrite the
/// operator's screen or logs.
fn validate_operator_path(path: &std::path::Path) -> std::io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is empty",
        ));
    }
    let text = path.as_os_str().to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "path is not valid UTF-8 and cannot be displayed safely",
        )
    })?;
    if text.chars().any(unsafe_terminal_char) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "path contains a control or bidi character and cannot be displayed safely",
        ));
    }
    Ok(())
}

fn shell_quote_posix(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn list_match_names(dir: &std::path::Path) -> std::io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "match directory contains a non-UTF-8 filename",
            )
        })?;
        if name.chars().any(unsafe_terminal_char) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "match directory contains a control or bidi filename",
            ));
        }
        let kind = entry.file_type()?;
        if name.ends_with(".txt") || name.ends_with(".md") {
            if !kind.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a match entry is not a regular file",
                ));
            }
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn match_name_stem(name: &str) -> &str {
    name.strip_suffix(".md")
        .or_else(|| name.strip_suffix(".txt"))
        .unwrap_or(name)
}

fn show_command(stem: &str) -> String {
    format!("keyrx show -- {}", shell_quote_posix(stem))
}

fn match_summary_rows(number: usize, address: &str, path: &str) -> [String; 2] {
    [
        ui::mid(&format!(
            "  {}{}.{} {}{}{}",
            ui::gry(),
            number,
            ui::r(),
            ui::wht(),
            address,
            ui::r()
        )),
        ui::mid(&format!("      {}path {}{}", ui::accent(), path, ui::r())),
    ]
}

fn cmd_show(file: Option<String>, with_seed: bool, with_key: bool) {
    #[cfg(not(unix))]
    {
        let _ = (file, with_seed, with_key);
        eprintln!("show refuses on this platform because a private-file ACL is not yet verified; use a Unix host or WSL");
        std::process::exit(1);
    }
    if let Some(ref supplied) = file {
        if let Err(e) = validate_operator_path(std::path::Path::new(supplied)) {
            eprintln!("cannot use show path: {}", e);
            std::process::exit(1);
        }
    }
    ui::masthead("show");
    let file = match file {
        Some(f) if std::path::Path::new(&f).exists() => f,
        Some(f) => {
            // A bare name resolves both the legacy aggregate .txt format and
            // the one-hit managed .md format.  EVM remains explicitly namespaced.
            let requested_format = if f.ends_with(".md") {
                Some("md")
            } else if f.ends_with(".txt") {
                Some("txt")
            } else {
                None
            };
            let stem = match_name_stem(&f);
            let evm_requested = stem.starts_with("evm/");
            let chain_stem = stem.trim_start_matches("evm/");
            let dir = if evm_requested {
                matches_dir_for(Chain::Evm)
            } else {
                matches_dir()
            };
            let legacy = dir.join(format!("{chain_stem}.txt"));
            let markdown = dir.join(format!("{chain_stem}.md"));
            let cand = match requested_format {
                Some("md") => markdown,
                Some("txt") => legacy,
                _ if legacy.exists() => legacy,
                _ if markdown.exists() => markdown,
                _ => {
                    // Keep the old lane name for its in-progress marker. Managed
                    // outputs acquire that lane but do not create the .txt file.
                    legacy
                }
            };
            if !cand.exists() {
                let marker = grind_marker_path(&cand);
                if marker.exists() {
                    println!("{}", ui::top("GRIND MARKER", &ui::path_text(&cand)));
                    println!(
                        "{}",
                        ui::note("a marker exists, but a PID alone cannot prove process identity.")
                    );
                    println!(
                        "{}",
                        ui::note("inspect the process before removing a stale marker, then retry.")
                    );
                    println!("{}", ui::bot(&ui::path_text(&marker)));
                } else {
                    println!("{}", ui::top("NO MATCHES", &ui::path_text(&cand)));
                    println!("{}", ui::note("no match file exists for this pattern."));
                    println!(
                        "{}",
                        ui::note("start one:  keyrx grind --ends-with <pattern>")
                    );
                    println!("{}", ui::bot("`keyrx show` alone lists what exists"));
                }
                println!();
                std::process::exit(1);
            }
            cand.to_string_lossy().into_owned()
        }
        None => {
            let dir = matches_dir();
            println!("{}", ui::top("MATCH FILES", &ui::dir_link(&dir)));
            let sol_names = match list_match_names(&dir) {
                Ok(names) => names,
                Err(e) => {
                    eprintln!("cannot enumerate {}: {}", ui::path_text(&dir), e);
                    std::process::exit(1);
                }
            };
            let mut names: Vec<(std::path::PathBuf, String)> =
                sol_names.into_iter().map(|n| (dir.join(&n), n)).collect();
            let evm_dir = matches_dir_for(Chain::Evm);
            let evm_names = match list_match_names(&evm_dir) {
                Ok(names) => names,
                Err(e) => {
                    eprintln!("cannot enumerate {}: {}", ui::path_text(&evm_dir), e);
                    std::process::exit(1);
                }
            };
            names.extend(
                evm_names
                    .into_iter()
                    .map(|n| (evm_dir.join(&n), format!("evm/{n}"))),
            );
            if names.is_empty() {
                println!(
                    "{}",
                    ui::note(
                        "no match files yet - grind writes them here, named after the pattern"
                    )
                );
            }
            let mut refused = false;
            let mut commands = Vec::new();
            for (path, stem) in &names {
                match read_private_text(path).and_then(|text| parse_match_bytes(text.as_slice())) {
                    Ok(records) => {
                        println!("{}", ui::kv("file", stem));
                        println!("{}", ui::cont(&format!("{} match(es)", records.len())));
                        println!("{}", ui::cont("complete command printed below"));
                        commands.push(show_command(stem));
                    }
                    Err(e) => {
                        refused = true;
                        eprintln!("REFUSED {}: {}", ui::path_text(path), e);
                    }
                }
            }
            if ui::links_on() {
                println!("{}", ui::mid(""));
                println!(
                    "{}",
                    ui::note(&format!("{} (the path in the title)", ui::CLICK_HINT))
                );
            }
            println!(
                "{}",
                ui::bot(&format!(
                    "every file: {} · seeds and keys inside",
                    output_protection()
                ))
            );
            for command in commands {
                println!("{command}");
            }
            println!();
            if refused {
                std::process::exit(1);
            }
            return;
        }
    };
    let path = std::path::Path::new(&file);
    let text = match read_private_text(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {}", file, e);
            std::process::exit(1);
        }
    };
    let records = match parse_match_bytes(text.as_slice()) {
        Ok(records) => records,
        Err(e) => {
            drop(text);
            eprintln!("cannot parse {}: {}", file, e);
            std::process::exit(1);
        }
    };
    drop(text);
    if records.is_empty() {
        let marker = grind_marker_path(path);
        if marker.exists() {
            eprintln!(
                "no complete matches yet; {} exists, but its process identity is not proven",
                ui::path_text(&marker)
            );
            std::process::exit(1);
        }
    }
    println!(
        "{}",
        ui::top("MATCHES", &{
            let d = std::path::Path::new(&file)
                .parent()
                .map(|d| d.to_path_buf())
                .unwrap_or_default();
            let abs = std::fs::canonicalize(&d).unwrap_or(d);
            ui::link(
                &ui::file_url(&abs),
                &ui::path_text(std::path::Path::new(&file)),
            )
        })
    );
    let mut n = 0;
    type Secret = (
        usize,
        String,
        Option<Zeroizing<String>>,
        Option<Zeroizing<String>>,
        Option<Zeroizing<String>>,
    );
    let mut secrets: Vec<Secret> = Vec::new();
    for record in records {
        n += 1;
        let ParsedMatch {
            chain: _,
            address: a,
            path: p,
            seed,
            privkey: key,
            keypair: kp,
            passphrase: pass,
        } = record;
        for row in match_summary_rows(n, &a, &p) {
            println!("{row}");
        }
        if pass {
            println!(
                "{}",
                ui::mid(&format!(
                    "      {}+ passphrase - the seed alone will not reach it; the keys will{}",
                    ui::warn(),
                    ui::r()
                ))
            );
            println!(
                "{}",
                ui::mid(&format!(
                    "      {}key/address verified; seed/path needs the absent passphrase{}",
                    ui::gry(),
                    ui::r()
                ))
            );
        }
        if with_seed || with_key {
            secrets.push((n, a, Some(seed), Some(key), kp));
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
            println!(
                "{}",
                seed.as_ref().map(|v| v.as_str()).unwrap_or("(missing)")
            );
        }
        if with_key {
            if a.starts_with("0x") {
                // an EVM match: one key form supported by MetaMask and Rabby
                println!(
                    " {}privkey  hex - MetaMask/Rabby: Import account -> Private key{}",
                    ui::gry(),
                    ui::r()
                );
                println!(
                    "{}",
                    key.as_ref().map(|v| v.as_str()).unwrap_or("(missing)")
                );
            } else {
                println!(
                    " {}privkey  base58 - Phantom/Solflare: Import Private Key{}",
                    ui::gry(),
                    ui::r()
                );
                println!(
                    "{}",
                    key.as_ref().map(|v| v.as_str()).unwrap_or("(missing)")
                );
                println!(
                    " {}keypair  JSON array - solana-keygen{}",
                    ui::gry(),
                    ui::r()
                );
                println!("{}", kp.as_ref().map(|v| v.as_str()).unwrap_or("(missing)"));
            }
        }
    }
    println!();
}

/// Written under the seed when a passphrase was used - the fact, never the passphrase.
const PASSPHRASE_LINE: &str =
    "\npassphrase used - NOT stored: the seed alone will not reach this address; the keys will";

struct ParsedMatch {
    chain: Chain,
    address: String,
    path: String,
    seed: Zeroizing<String>,
    privkey: Zeroizing<String>,
    keypair: Option<Zeroizing<String>>,
    passphrase: bool,
}

#[derive(Clone, Copy)]
enum ParsedPath {
    Sol(PathStyle, u32),
    Evm(u32),
}

fn parse_record_path(value: &str) -> Option<ParsedPath> {
    if let Some(index) = value
        .strip_prefix("m/44'/60'/0'/0/")
        .and_then(|v| (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).then_some(v))
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|index| *index < HARDENED)
    {
        return Some(ParsedPath::Evm(index));
    }
    let rest = value.strip_prefix("m/44'/501'/")?;
    if let Some(index) = rest
        .strip_suffix("'/0'")
        .and_then(|v| (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).then_some(v))
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|index| *index < HARDENED)
    {
        return Some(ParsedPath::Sol(PathStyle::Phantom, index));
    }
    rest.strip_suffix('\'')
        .and_then(|v| (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).then_some(v))
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|index| *index < HARDENED)
        .map(|index| ParsedPath::Sol(PathStyle::Legacy, index))
}

fn sol_secret_from_seed(seed: &[u8], style: PathStyle, index: u32) -> Zeroizing<[u8; 32]> {
    let (mut key, mut chain) = master_key(seed);
    let (mut next_key, mut next_chain) = derive_hardened(&key, &chain, 44);
    key.zeroize();
    chain.zeroize();
    let (mut branch_key, mut branch_chain) = derive_hardened(&next_key, &next_chain, 501);
    next_key.zeroize();
    next_chain.zeroize();
    let (mut account_key, mut account_chain) = derive_hardened(&branch_key, &branch_chain, index);
    branch_key.zeroize();
    branch_chain.zeroize();
    let secret = if style == PathStyle::Phantom {
        let (result, mut final_chain) = derive_hardened(&account_key, &account_chain, 0);
        final_chain.zeroize();
        account_key.zeroize();
        result
    } else {
        account_key
    };
    account_chain.zeroize();
    Zeroizing::new(secret)
}

struct MatchHeaderSpec {
    chain: Chain,
    matcher: Matcher,
    path: PathStyle,
    indices: u32,
    words: usize,
    passphrase: bool,
}

fn split_match_file_header(text: &str) -> std::io::Result<(Option<MatchHeaderSpec>, &str)> {
    if !text.starts_with('╔') {
        return Ok((None, text));
    }
    let Some(candidate_len) = text.find("\n\n") else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file ends inside its header",
        ));
    };
    let framed_len = candidate_len
        .checked_add(2)
        .ok_or_else(|| std::io::Error::other("match header length overflow"))?;
    if framed_len > MAX_MATCH_FILE_HEADER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header exceeds its supported size",
        ));
    }
    let candidate = &text[..candidate_len];
    let body = &text[framed_len..];
    let title = candidate.lines().next().unwrap_or_default();
    let chain = if title.contains("· SOLANA PRIVATE MATCH FILE ") {
        Chain::Sol
    } else if title.contains("· EVM PRIVATE MATCH FILE ") {
        Chain::Evm
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file has an unknown header",
        ));
    };
    let recipe = candidate.lines().last().unwrap_or_default();
    let expected = format_match_file_header(chain, recipe)?;
    if &text.as_bytes()[..framed_len] != expected.bytes.as_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file has a malformed header",
        ));
    }
    let parsed = Cli::try_parse_from(recipe.split_ascii_whitespace()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has an invalid creation recipe",
        )
    })?;
    if parsed.update
        || recipe
            .split_ascii_whitespace()
            .any(|word| matches!(word, "--count" | "--out" | "--threads" | "--show-seed"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has a noncanonical creation recipe",
        ));
    }
    let Some(Cmd::Grind {
        pattern,
        threads: _,
        indices,
        count,
        words,
        out,
        show_seed,
        passphrase,
    }) = parsed.cmd
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header recipe is not a grind command",
        ));
    };
    if count != 1 || out.is_some() || show_seed || pattern.chain != chain {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has a noncanonical creation recipe",
        ));
    }
    let matcher = Matcher::new(&pattern).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has an invalid creation recipe",
        )
    })?;
    if !matches!(words, 12 | 24) || indices == 0 || indices > HARDENED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has an invalid creation recipe",
        ));
    }
    let canonical = grind_creation_recipe(&pattern, indices, words, passphrase).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has an invalid creation recipe",
        )
    })?;
    if canonical != recipe {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file header has a noncanonical creation recipe",
        ));
    }
    Ok((
        Some(MatchHeaderSpec {
            chain,
            matcher,
            path: pattern.path,
            indices,
            words,
            passphrase,
        }),
        body,
    ))
}

struct ParsedMatchFile {
    header_chain: Option<Chain>,
    records: Vec<ParsedMatch>,
}

/// One strict parser owns append validation, listing, and direct `show`. A
/// damaged header or record is never treated as an empty or shorter valid file.
/// Headerless files from every earlier keyRX release remain valid.
fn parse_legacy_match_file_bytes(bytes: &[u8]) -> std::io::Result<ParsedMatchFile> {
    if bytes.is_empty() {
        return Ok(ParsedMatchFile {
            header_chain: None,
            records: Vec::new(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "match file is not UTF-8")
    })?;
    let (header_spec, text) = split_match_file_header(text)?;
    let header_chain = header_spec.as_ref().map(|spec| spec.chain);
    if text.is_empty() {
        return Ok(ParsedMatchFile {
            header_chain,
            records: Vec::new(),
        });
    }
    let Some(body) = text.strip_suffix("\n\n") else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file ends inside a record",
        ));
    };
    let mut records = Vec::new();
    for (number, block) in body.split("\n\n").enumerate() {
        let lines: Vec<&str> = block.lines().collect();
        let fail = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("match file has a malformed record at #{}", number + 1),
            )
        };
        let exact = |line: Option<&&str>, prefix: &str| -> std::io::Result<String> {
            let value = line
                .and_then(|line| line.strip_prefix(prefix))
                .ok_or_else(fail)?;
            if value.is_empty() || value.trim() != value {
                return Err(fail());
            }
            Ok(value.to_string())
        };
        let address = exact(lines.first(), "address ")?;
        let path = exact(lines.get(1), "path    ")?;
        let seed = Zeroizing::new(exact(lines.get(2), "seed    ")?);
        let seed_words = seed.split_whitespace().count();
        if !matches!(seed_words, 12 | 24) {
            return Err(fail());
        }
        let mnemonic = bip39::Mnemonic::parse_normalized(seed.as_str()).map_err(|_| fail())?;
        let canonical_seed = Zeroizing::new(mnemonic.to_string());
        if canonical_seed.as_str() != seed.as_str() {
            return Err(fail());
        }
        let mut at = 3;
        let passphrase = lines
            .get(at)
            .is_some_and(|line| *line == PASSPHRASE_LINE.trim_start_matches('\n'));
        if passphrase {
            at += 1;
        }
        let privkey = Zeroizing::new(exact(lines.get(at), "privkey ")?);
        at += 1;
        let parsed_path = parse_record_path(&path).ok_or_else(fail)?;
        let canonical_path = match parsed_path {
            ParsedPath::Sol(style, index) => path_for(Chain::Sol, style, index),
            ParsedPath::Evm(index) => path_for(Chain::Evm, PathStyle::Phantom, index),
        };
        if path != canonical_path {
            return Err(fail());
        }
        let evm = matches!(parsed_path, ParsedPath::Evm(_));
        if header_chain.is_some_and(|chain| (chain == Chain::Evm) != evm) {
            return Err(fail());
        }
        if evm != address.starts_with("0x") {
            return Err(fail());
        }
        if let Some(spec) = header_spec.as_ref() {
            let (record_chain, record_path, record_index) = match parsed_path {
                ParsedPath::Sol(path, index) => (Chain::Sol, Some(path), index),
                ParsedPath::Evm(index) => (Chain::Evm, None, index),
            };
            if record_chain != spec.chain
                || !spec.matcher.address_hit(&address)
                || record_index >= spec.indices
                || seed_words != spec.words
                || passphrase != spec.passphrase
                || (record_chain == Chain::Sol && record_path != Some(spec.path))
            {
                return Err(fail());
            }
        }
        let keypair = if evm {
            if address.len() != 42
                || !address[2..].bytes().all(|b| b.is_ascii_hexdigit())
                || privkey.len() != 66
                || !privkey.starts_with("0x")
                || !privkey[2..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(fail());
            }
            if evm::address_from_privkey_hex(privkey.as_str()).as_deref() != Ok(address.as_str()) {
                return Err(fail());
            }
            if !passphrase {
                let ParsedPath::Evm(index) = parsed_path else {
                    return Err(fail());
                };
                let bip39_seed = Zeroizing::new(mnemonic.to_seed(""));
                let branch = evm::Branch::from_seed(bip39_seed.as_ref()).ok_or_else(fail)?;
                let mut key = branch.key_at(index).ok_or_else(fail)?;
                let derived = evm::privkey_hex(&key);
                key.zeroize();
                if derived.as_str() != privkey.as_str() {
                    return Err(fail());
                }
            }
            None
        } else {
            let public = bs58::decode(&address).into_vec().map_err(|_| fail())?;
            let private = Zeroizing::new(
                bs58::decode(privkey.as_str())
                    .into_vec()
                    .map_err(|_| fail())?,
            );
            if public.len() != 32
                || private.len() != 64
                || bs58::encode(private.as_slice()).into_string() != privkey.as_str()
            {
                return Err(fail());
            }
            let keypair = Zeroizing::new(exact(lines.get(at), "keypair ")?);
            at += 1;
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&private[..32]);
            let derived = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
            let canonical_keypair = keypair_json(&secret);
            secret.zeroize();
            if keypair.as_str() != canonical_keypair.as_str()
                || private[32..] != derived
                || public.as_slice() != derived
            {
                return Err(fail());
            }
            if !passphrase {
                let ParsedPath::Sol(style, index) = parsed_path else {
                    return Err(fail());
                };
                let bip39_seed = Zeroizing::new(mnemonic.to_seed(""));
                let derived_secret = sol_secret_from_seed(bip39_seed.as_ref(), style, index);
                if derived_secret.as_slice() != &private[..32] {
                    return Err(fail());
                }
            }
            Some(keypair)
        };
        if at != lines.len() {
            return Err(fail());
        }
        records.push(ParsedMatch {
            chain: if evm { Chain::Evm } else { Chain::Sol },
            address,
            path,
            seed,
            privkey,
            keypair,
            passphrase,
        });
    }
    Ok(ParsedMatchFile {
        header_chain,
        records,
    })
}

fn take_markdown_value<'a>(rest: &mut &'a str, heading: &str) -> std::io::Result<&'a str> {
    let prefix = format!("## {heading}\n\n");
    *rest = rest.strip_prefix(&prefix).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Markdown match is missing its {heading} heading"),
        )
    })?;
    let (value, tail) = rest.split_once("\n\n").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Markdown match ends inside its {heading} value"),
        )
    })?;
    if value.is_empty()
        || value.trim() != value
        || value.contains('\n')
        || value.chars().any(unsafe_terminal_char)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Markdown match has a malformed {heading} value"),
        ));
    }
    *rest = tail;
    Ok(value)
}

/// Strictly parse the one-hit Markdown format, then hand its values to the
/// legacy parser.  That one parser remains the authority for mnemonic,
/// derivation, private-key/address, path, matcher, and recipe consistency.
fn parse_markdown_match_file_bytes(bytes: &[u8]) -> std::io::Result<ParsedMatchFile> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match file is not UTF-8",
        )
    })?;
    let (chain, mut rest) = if let Some(rest) = text.strip_prefix(&format!(
        "{}\n\nFormat: `{}`\n\n{}\n\n",
        markdown_match_title(Chain::Sol),
        MARKDOWN_MATCH_VERSION,
        MARKDOWN_PRIVATE_WARNING
    )) {
        (Chain::Sol, rest)
    } else if let Some(rest) = text.strip_prefix(&format!(
        "{}\n\nFormat: `{}`\n\n{}\n\n",
        markdown_match_title(Chain::Evm),
        MARKDOWN_MATCH_VERSION,
        MARKDOWN_PRIVATE_WARNING
    )) {
        (Chain::Evm, rest)
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match has an unknown title or format version",
        ));
    };
    let address = take_markdown_value(&mut rest, "ADDRESS")?;
    let path = take_markdown_value(&mut rest, "PATH")?;
    let seed = take_markdown_value(&mut rest, "SEED")?;
    let passphrase_status = take_markdown_value(&mut rest, "PASSPHRASE")?;
    let passphrase = match passphrase_status {
        "not used" => false,
        "used - value not stored; the seed alone will not reach this address" => true,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Markdown match has a malformed PASSPHRASE value",
            ))
        }
    };
    let privkey = take_markdown_value(&mut rest, markdown_private_key_heading(chain))?;
    let keypair = if chain == Chain::Sol {
        Some(take_markdown_value(&mut rest, "KEYPAIR (JSON)")?)
    } else {
        None
    };
    let guidance_prefix = "## IMPORT AND RECOVERY\n\n";
    rest = rest.strip_prefix(guidance_prefix).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match is missing its IMPORT AND RECOVERY heading",
        )
    })?;
    let recipe_boundary = "\n\n## CREATION RECIPE\n\n`";
    let (guidance, recipe_tail) = rest.split_once(recipe_boundary).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match is missing its creation recipe",
        )
    })?;
    if guidance != markdown_match_guidance(chain) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match has noncanonical import or recovery guidance",
        ));
    }
    let recipe = recipe_tail.strip_suffix("`\n").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match has a malformed creation recipe",
        )
    })?;
    if recipe.contains('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match creation recipe spans more than one line",
        ));
    }

    let header = format_match_file_header(chain, recipe)?;
    let mut legacy = Zeroizing::new(String::with_capacity(MAX_MARKDOWN_MATCH_BYTES));
    legacy.push_str(&header.bytes);
    write!(
        &mut *legacy,
        "address {address}\npath    {path}\nseed    {seed}{}\nprivkey {privkey}\n",
        if passphrase { PASSPHRASE_LINE } else { "" }
    )
    .expect("writing a bounded compatibility record to a String cannot fail");
    if let Some(keypair) = keypair {
        writeln!(&mut *legacy, "keypair {keypair}")
            .expect("writing a bounded compatibility record to a String cannot fail");
        legacy.push('\n');
    } else {
        legacy.push('\n');
    }
    if legacy.len() > MAX_MARKDOWN_MATCH_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match exceeds its supported size",
        ));
    }
    let parsed = parse_legacy_match_file_bytes(legacy.as_bytes())?;
    if parsed.records.len() != 1 || parsed.header_chain != Some(chain) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Markdown match does not contain exactly one canonical record",
        ));
    }
    Ok(parsed)
}

fn parse_match_file_bytes(bytes: &[u8]) -> std::io::Result<ParsedMatchFile> {
    if bytes.starts_with(b"# keyRX \xc2\xb7 ") {
        parse_markdown_match_file_bytes(bytes)
    } else {
        parse_legacy_match_file_bytes(bytes)
    }
}

fn parse_match_bytes(bytes: &[u8]) -> std::io::Result<Vec<ParsedMatch>> {
    parse_match_file_bytes(bytes).map(|file| file.records)
}

/// Create only missing output directories. A caller-owned `--out` parent keeps its
/// permissions; the tool's own matches directory is private every time it is used.
fn prepare_output_parent(out: &std::path::Path, managed: bool) -> std::io::Result<()> {
    let parent = out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "output parent is not a real directory: {}",
                    ui::path_text(parent)
                ),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
        Err(e) => return Err(e),
    }
    if managed {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(parent)?;
        let mode = meta.permissions().mode() & 0o777;
        if meta.uid() != unsafe { libc::geteuid() } || mode & 0o022 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "output parent must be owned by this user and not group/world-writable (mode {:03o}): {}",
                    mode,
                    ui::path_text(parent)
                ),
            ));
        }
    }
    Ok(())
}

fn recovery_output_path(requested: &std::path::Path) -> std::path::PathBuf {
    let Some(name) = requested.file_name() else {
        let mut fallback = requested.as_os_str().to_os_string();
        fallback.push(".recovered");
        return std::path::PathBuf::from(fallback);
    };
    let mut recovered = requested.file_stem().unwrap_or(name).to_os_string();
    recovered.push(".recovered");
    if let Some(extension) = requested.extension() {
        recovered.push(".");
        recovered.push(extension);
    }
    requested.with_file_name(recovered)
}

/// Append the marker suffix to filesystem bytes, never to rendered path text.
/// `ui::path_text` is deliberately escaped terminal output and must never be
/// fed back into a filesystem lookup.
fn grind_marker_path(out: &std::path::Path) -> std::path::PathBuf {
    let mut marker = out.as_os_str().to_os_string();
    marker.push(".grinding");
    std::path::PathBuf::from(marker)
}

/// Open one held append descriptor for the entire grind. On Unix the final path
/// may not be a symlink or other special file, hard-linked aliases are refused,
/// and permissions are narrowed on the descriptor before any secret is written.
fn validate_existing_match_bytes(
    bytes: &[u8],
    expected_header: &MatchFileHeader,
) -> std::io::Result<()> {
    let parsed = parse_match_file_bytes(bytes)?;
    if parsed
        .records
        .iter()
        .any(|record| record.chain != expected_header.chain)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file already contains records from the other chain",
        ));
    }
    if let Some(chain) = parsed.header_chain {
        if chain != expected_header.chain {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "match file header belongs to the other chain",
            ));
        }
        if !bytes.starts_with(expected_header.bytes.as_bytes()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "match file header belongs to another creation recipe",
            ));
        }
    }
    Ok(())
}

fn open_match_file(
    out: &std::path::Path,
    expected_header: &MatchFileHeader,
) -> std::io::Result<std::fs::File> {
    let options = |create_new: bool| {
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true)
            .write(true)
            .read(true)
            .create_new(create_new);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        opts
    };
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(out)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("output path is a symlink: {}", ui::path_text(out)),
        ));
    }
    let (mut f, created) = match options(true).open(out) {
        Ok(file) => (file, true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            (options(false).open(out)?, false)
        }
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("output is not a regular file: {}", ui::path_text(out)),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("output is not owned by this user: {}", ui::path_text(out)),
            ));
        }
        if meta.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "output has {} hard links; refusing aliases: {}",
                    meta.nlink(),
                    ui::path_text(out)
                ),
            ));
        }
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mode = f.metadata()?.mode() & 0o777;
        if mode != 0o600 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "output mode is {:03o}, expected 600: {}",
                    mode,
                    ui::path_text(out)
                ),
            ));
        }
    }
    let existing = read_held_private_bytes(&mut f, &meta, out)?;
    validate_existing_match_bytes(&existing, expected_header)?;
    // `sync_all` covers file data plus mode metadata. A newly-created name also
    // needs its parent directory flushed before a match may be reported.
    f.sync_all()?;
    if created {
        let parent = out
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut parent_opts = std::fs::OpenOptions::new();
            parent_opts
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            parent_opts.open(parent)?.sync_all()?;
        }
    }
    Ok(f)
}

#[cfg(unix)]
fn validate_grind_output_descriptor(file: &std::fs::File) -> std::io::Result<std::fs::Metadata> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = file.metadata()?;
    let mode = meta.permissions().mode() & 0o777;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || mode != 0o600
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "held output custody changed (regular={}, owner={}, mode={:03o}, links={})",
                meta.is_file(),
                meta.uid(),
                mode,
                meta.nlink()
            ),
        ));
    }
    Ok(meta)
}

#[cfg(unix)]
fn validate_grind_output_path(file: &std::fs::File, path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let held = validate_grind_output_descriptor(file)?;
    let named = std::fs::symlink_metadata(path)?;
    if !named.is_file() || named.dev() != held.dev() || named.ino() != held.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "output pathname no longer names the held private file: {}",
                ui::path_text(path)
            ),
        ));
    }
    Ok(())
}

/// The running marker is an exclusive file, not a pathname we truncate. Holding
/// it prevents two grinds from claiming the same output. Its parent has already
/// been required to be caller-owned and not group/world-writable. Drop checks
/// identity before its best-effort removal; the check and unlink are not atomic.
struct GrindLock {
    path: std::path::PathBuf,
    released: bool,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
    pid: String,
}

impl GrindLock {
    fn acquire(out: &std::path::Path) -> std::io::Result<Self> {
        Self::acquire_with_metadata(out, std::fs::File::metadata)
    }

    /// The metadata callback is a test seam for the one post-create failure
    /// that cannot be induced portably. Production passes `File::metadata`.
    fn acquire_with_metadata<F>(out: &std::path::Path, metadata: F) -> std::io::Result<Self>
    where
        F: FnOnce(&std::fs::File) -> std::io::Result<std::fs::Metadata>,
    {
        let path = grind_marker_path(out);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                std::io::Error::new(e.kind(), format!(
                    "another grind (or a stale marker) owns {}; verify no grind is running before removing it",
                    ui::path_text(&path)))
            } else { e }
        })?;
        let meta = match metadata(&file) {
            Ok(meta) => meta,
            Err(cause) => {
                drop(file);
                let cleanup = std::fs::remove_file(&path).and_then(|_| {
                    #[cfg(unix)]
                    sync_parent_dir(&path)?;
                    Ok(())
                });
                return match cleanup {
                    Ok(()) => Err(cause),
                    Err(cleanup) => Err(std::io::Error::new(
                        cleanup.kind(),
                        format!(
                            "cannot inspect new grind marker ({cause}); cleanup also failed: {cleanup}"
                        ),
                    )),
                };
            }
        };
        let pid = std::process::id().to_string();
        #[cfg(unix)]
        let lock = {
            use std::os::unix::fs::MetadataExt;
            Self {
                path,
                released: false,
                dev: meta.dev(),
                ino: meta.ino(),
            }
        };
        #[cfg(not(unix))]
        let lock = Self {
            path,
            released: false,
            pid: pid.clone(),
        };
        if let Err(e) = file
            .write_all(pid.as_bytes())
            .and_then(|_| file.sync_data())
        {
            drop(file);
            drop(lock);
            return Err(e);
        }
        Ok(lock)
    }

    fn release(&mut self) -> std::io::Result<()> {
        if self.released {
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(&self.path)?;
            if !meta.is_file() || meta.dev() != self.dev || meta.ino() != self.ino {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "grind marker identity changed before release",
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let current = std::fs::read_to_string(&self.path)?;
            if current != self.pid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "grind marker identity changed before release",
                ));
            }
        }
        std::fs::remove_file(&self.path)?;
        self.released = true;
        #[cfg(unix)]
        sync_parent_dir(&self.path)?;
        Ok(())
    }
}

impl Drop for GrindLock {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// One supported match record is comfortably below 1 KiB even with a 24-word
/// mnemonic, the longest Solana address/path/import forms, and the passphrase
/// notice. Reserve twice that before any seed or key is formatted; the checked
/// length and capacity make an unexpected format expansion a refusal.
const HIT_RECORD_CAPACITY: usize = 2048;

fn format_hit_record(h: &Hit, style: PathStyle) -> std::io::Result<(Zeroizing<String>, usize)> {
    let path = path_for(h.chain, style, h.index);
    let passphrase = if h.passphrase { PASSPHRASE_LINE } else { "" };
    let required = match h.chain {
        Chain::Sol => 8usize
            .checked_add(h.address.len())
            .and_then(|n| n.checked_add(9 + path.len()))
            .and_then(|n| n.checked_add(9 + h.mnemonic.len()))
            .and_then(|n| n.checked_add(passphrase.len()))
            .and_then(|n| n.checked_add(9 + h.privkey.len()))
            .and_then(|n| n.checked_add(9 + h.keypair_json.len()))
            .and_then(|n| n.checked_add(2)),
        Chain::Evm => 8usize
            .checked_add(h.address.len())
            .and_then(|n| n.checked_add(9 + path.len()))
            .and_then(|n| n.checked_add(9 + h.mnemonic.len()))
            .and_then(|n| n.checked_add(passphrase.len()))
            .and_then(|n| n.checked_add(9 + h.privkey.len()))
            .and_then(|n| n.checked_add(2)),
    }
    .ok_or_else(|| std::io::Error::other("match record length overflow"))?;
    if required > HIT_RECORD_CAPACITY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match record exceeds the fixed secret-buffer capacity",
        ));
    }
    let mut record = Zeroizing::new(String::with_capacity(HIT_RECORD_CAPACITY));
    let reserved = record.capacity();
    match h.chain {
        Chain::Sol => writeln!(
            &mut *record,
            "address {}\npath    {}\nseed    {}{}\nprivkey {}\nkeypair {}\n",
            h.address,
            path,
            h.mnemonic.as_str(),
            passphrase,
            h.privkey.as_str(),
            h.keypair_json.as_str()
        ),
        // EVM has one import form - the hex private key - so four lines, no keypair
        Chain::Evm => writeln!(
            &mut *record,
            "address {}\npath    {}\nseed    {}{}\nprivkey {}\n",
            h.address,
            path,
            h.mnemonic.as_str(),
            passphrase,
            h.privkey.as_str()
        ),
    }
    .expect("writing a preflighted record to a String cannot fail");
    if record.len() != required || record.capacity() != reserved {
        return Err(std::io::Error::other(
            "match record changed allocation after secret formatting began",
        ));
    }
    Ok((record, reserved))
}

fn checked_match_append_len(
    current: u64,
    header_len: u64,
    record_len: u64,
) -> std::io::Result<u64> {
    let final_len = current
        .checked_add(header_len)
        .and_then(|length| length.checked_add(record_len))
        .ok_or_else(|| std::io::Error::other("match-file length overflow"))?;
    if final_len > MAX_PRIVATE_MATCH_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "match file would exceed the supported {}-byte read/append bound",
                MAX_PRIVATE_MATCH_FILE_BYTES
            ),
        ));
    }
    Ok(final_len)
}

#[cfg(test)]
fn write_hit(
    file: &Mutex<std::fs::File>,
    h: &Hit,
    style: PathStyle,
    header: &MatchFileHeader,
) -> std::io::Result<()> {
    if header.chain != h.chain {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "match header chain does not match the record",
        ));
    }
    let (record, _) = format_hit_record(h, style)?;
    let mut file = file
        .lock()
        .map_err(|_| std::io::Error::other("match-file lock poisoned"))?;
    #[cfg(unix)]
    validate_grind_output_descriptor(&file)?;
    let current = file.metadata()?.len();
    let header_len = if current == 0 {
        u64::try_from(header.bytes.len())
            .map_err(|_| std::io::Error::other("match header length does not fit u64"))?
    } else {
        0
    };
    let record_len = u64::try_from(record.len())
        .map_err(|_| std::io::Error::other("match record length does not fit u64"))?;
    let final_len = checked_match_append_len(current, header_len, record_len)?;
    if current == 0 {
        file.write_all(header.bytes.as_bytes())?;
    }
    file.write_all(record.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    validate_grind_output_descriptor(&file)?;
    if file.metadata()?.len() != final_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "match file length changed outside the held append operation",
        ));
    }
    Ok(())
}

fn managed_match_path(
    lane: &std::path::Path,
    realized: &str,
    ordinal: usize,
) -> std::io::Result<std::path::PathBuf> {
    let base = lane
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "managed match lane has no safe UTF-8 filename stem",
            )
        })?;
    let suffix = if ordinal == 1 {
        String::new()
    } else {
        format!(".{ordinal:02}")
    };
    let leaf = format!("{base}.{realized}{suffix}.md");
    // Linux, macOS, and the Unix filesystems used under WSL admit 255-byte
    // components. Leave margin rather than discovering an overlong generated
    // name only after an expensive match has landed.
    if leaf.len() > 240 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed match filename would exceed the supported 240-byte bound",
        ));
    }
    Ok(lane.with_file_name(leaf))
}

#[cfg(unix)]
#[derive(Clone)]
struct PersistedMatchIdentity {
    path: std::path::PathBuf,
    dev: u64,
    ino: u64,
    len: u64,
}

/// Owns the managed lane's completed, independently named match documents.
struct ManagedMatchWriter {
    lane: std::path::PathBuf,
    #[cfg(unix)]
    persisted: Vec<PersistedMatchIdentity>,
}

impl ManagedMatchWriter {
    fn new(lane: std::path::PathBuf) -> Self {
        Self {
            lane,
            #[cfg(unix)]
            persisted: Vec::new(),
        }
    }

    fn write(
        &mut self,
        hit: &Hit,
        style: PathStyle,
        header: &MatchFileHeader,
        matcher: &Matcher,
    ) -> std::io::Result<std::path::PathBuf> {
        let document = format_markdown_match_file(hit, style, header)?;
        let realized = matcher.realized_filename_edge(&hit.address)?;
        let mut ordinal = 1usize;
        let (path, mut file) = loop {
            let path = managed_match_path(&self.lane, &realized, ordinal)?;
            validate_operator_path(&path)?;
            match private_create_new(&path) {
                Ok(file) => break (path, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ordinal = ordinal.checked_add(1).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "managed match duplicate ordinal overflow",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            validate_grind_output_descriptor(&file)?;
        }
        let expected_len = u64::try_from(document.len())
            .map_err(|_| std::io::Error::other("Markdown match length does not fit u64"))?;
        if expected_len > MAX_PRIVATE_MATCH_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Markdown match exceeds the private-file size bound",
            ));
        }
        file.write_all(document.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = validate_grind_output_descriptor(&file)?;
            if meta.len() != expected_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed match length changed outside its held write",
                ));
            }
            validate_grind_output_path(&file, &path)?;
            sync_parent_dir(&path)?;
            self.persisted.push(PersistedMatchIdentity {
                path: path.clone(),
                dev: meta.dev(),
                ino: meta.ino(),
                len: expected_len,
            });
        }
        Ok(path)
    }

    #[cfg(unix)]
    fn validate_all(&self) -> std::io::Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for expected in &self.persisted {
            let meta = std::fs::symlink_metadata(&expected.path)?;
            let mode = meta.permissions().mode() & 0o777;
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.nlink() != 1
                || mode != 0o600
                || meta.dev() != expected.dev
                || meta.ino() != expected.ino
                || meta.len() != expected.len
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "managed match custody changed before completion: {}",
                        ui::path_text(&expected.path)
                    ),
                ));
            }
        }
        Ok(())
    }
}

enum GrindSink {
    Aggregate {
        path: std::path::PathBuf,
        file: std::fs::File,
    },
    Managed(ManagedMatchWriter),
}

fn write_grind_hit(
    sink: &Mutex<GrindSink>,
    hit: &Hit,
    style: PathStyle,
    header: &MatchFileHeader,
    matcher: &Matcher,
) -> std::io::Result<std::path::PathBuf> {
    let mut sink = sink
        .lock()
        .map_err(|_| std::io::Error::other("match-file lock poisoned"))?;
    match &mut *sink {
        GrindSink::Aggregate { path, file } => {
            if header.chain != hit.chain {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "match header chain does not match the record",
                ));
            }
            let (record, _) = format_hit_record(hit, style)?;
            #[cfg(unix)]
            validate_grind_output_descriptor(file)?;
            let current = file.metadata()?.len();
            let header_len = if current == 0 {
                u64::try_from(header.bytes.len())
                    .map_err(|_| std::io::Error::other("match header length does not fit u64"))?
            } else {
                0
            };
            let record_len = u64::try_from(record.len())
                .map_err(|_| std::io::Error::other("match record length does not fit u64"))?;
            let final_len = checked_match_append_len(current, header_len, record_len)?;
            if current == 0 {
                file.write_all(header.bytes.as_bytes())?;
            }
            file.write_all(record.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            validate_grind_output_descriptor(file)?;
            if file.metadata()?.len() != final_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "match file length changed outside the held append operation",
                ));
            }
            Ok(path.clone())
        }
        GrindSink::Managed(writer) => writer.write(hit, style, header, matcher),
    }
}

/// Time-to-first-match rows, framed. The 50% line carries the accent: it is
/// the number the operator plans around.
/// Time to ALL of n matches. Each match is an independent geometric wait with
/// exact mean 1/(prob*rate). The displayed 50% and 90% rows use the continuous
/// Gamma rare-event approximation; the UI labels that approximation instead
/// of presenting it as the discrete negative-binomial quantile.
fn quantiles_n(prob: f64, rate: f64, n: usize) {
    let k = n as f64;
    if prob >= 1.0 {
        let exact = k / rate;
        println!("{}", ui::kv_accent("50%", &fmt_dur(exact)));
        println!("{}", ui::kv("90%", &fmt_dur(exact)));
        println!(
            "{}",
            ui::kv("mean", &format!("{}   ({} candidates)", fmt_dur(exact), n))
        );
        println!("{}", ui::note("exact here: every candidate is a match"));
        return;
    }
    let mean_one = 1.0 / prob / rate;
    for (label, z) in [("50%", 0.0f64), ("90%", 1.2815516)] {
        let q = k * (1.0 - 1.0 / (9.0 * k) + z * (1.0 / (9.0 * k)).sqrt()).powi(3);
        let row = if label == "50%" {
            ui::kv_accent(label, &fmt_dur(q * mean_one))
        } else {
            ui::kv(label, &fmt_dur(q * mean_one))
        };
        println!("{}", row);
    }
    println!(
        "{}",
        ui::kv(
            "mean",
            &format!("{}   ({} x the mean above)", fmt_dur(k * mean_one), n)
        )
    );
    println!(
        "{}",
        ui::note("Gamma approximation to discrete waits; best for rare patterns")
    );
}

fn quantiles(prob: f64, rate: f64) {
    for (label, q) in [("50%", 0.5f64), ("90%", 0.9), ("99%", 0.99)] {
        let n = trials_for(q, prob);
        let row = if label == "50%" {
            ui::kv_accent(label, &fmt_dur(n / rate))
        } else {
            ui::kv(label, &fmt_dur(n / rate))
        };
        println!("{}", row);
    }
    println!("{}", ui::kv("mean", &fmt_dur(1.0 / prob / rate)));
}

fn trials_for(q: f64, prob: f64) -> f64 {
    if prob >= 1.0 {
        1.0
    } else {
        ((-q).ln_1p() / (-prob).ln_1p()).ceil().max(1.0)
    }
}

// ---------------------------------------------------------------- main

fn main() {
    let cli = Cli::parse();
    if cli.update {
        cmd_update();
        return;
    }
    let cmd = match cli.cmd {
        Some(c) => c,
        None => {
            cmd_start();
            return;
        }
    };
    match cmd {
        Cmd::Verify => cmd_verify(),
        Cmd::Estimate {
            pattern,
            threads,
            indices,
            count,
            words,
        } => cmd_estimate(pattern, threads, indices, count, words),
        Cmd::Bench {
            chain,
            threads,
            indices,
            seconds,
            path,
            words,
        } => cmd_bench(chain, threads, indices, seconds, path, words),
        Cmd::Show { file, seeds, keys } => cmd_show(file, seeds, keys),
        Cmd::Donate => cmd_donate(),
        Cmd::Networks => cmd_networks(),
        Cmd::Grind {
            pattern,
            threads,
            indices,
            count,
            words,
            out,
            show_seed,
            passphrase,
        } => {
            let managed_out = out.is_none();
            let out = out
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| default_out(&pattern));
            let status = cmd_grind(
                pattern,
                threads,
                indices,
                count,
                words,
                out,
                managed_out,
                show_seed,
                passphrase,
            );
            if status != 0 {
                // cmd_grind has returned, so its held output descriptor and
                // exact-inode marker have both been released before exit.
                std::process::exit(status);
            }
        }
    }
}

/// The start screen: `keyrx` with no arguments. Every command, every flag,
/// and the two ideas you need - what a path index is, and why --indices
/// trades speed for where the match lands.
/// `keyrx --update`: the install line - cargo install --locked keyrx, then keyrx -
/// as one flag. cargo does the work with its own output on screen; if it ends
/// clean, the screen is cleared and the freshly installed keyrx starts, so the
/// first thing you see is the new start screen with the new version on it.
#[cfg(not(unix))]
fn cmd_update() {
    ui::masthead(&format!("v{}", env!("CARGO_PKG_VERSION")));
    println!("{}", ui::top("UPDATE", "manual on this platform"));
    println!(
        "{}",
        ui::crit_line("automatic update refuses without held-executable relaunch support.")
    );
    println!("{}", ui::note("run: cargo install --locked keyrx"));
    println!("{}", ui::bot("then start keyrx again from your shell"));
    println!();
    std::process::exit(1);
}

#[cfg(unix)]
fn cmd_update() {
    ui::masthead(&format!("v{}", env!("CARGO_PKG_VERSION")));
    let Some(cargo) = find_cargo() else {
        println!("{}", ui::top("UPDATE", ""));
        println!(
            "{}",
            ui::crit_line("cargo is not on PATH - keyrx is installed and updated by cargo.")
        );
        println!(
            "{}",
            ui::note("install Rust from https://rustup.rs (one command), then:")
        );
        println!("{}", ui::note("cargo install --locked keyrx"));
        println!("{}", ui::bot(""));
        println!();
        std::process::exit(1);
    };
    let install_root = match cargo_install_root() {
        Ok(Some(root)) => root,
        Ok(None) => {
            eprintln!(
                "cannot choose an exact Cargo install root; set an absolute CARGO_INSTALL_ROOT or CARGO_HOME"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("cannot choose an exact Cargo install root: {}", error);
            std::process::exit(1);
        }
    };
    println!(
        "{}",
        ui::top("UPDATE", "cargo install --locked keyrx, then keyrx")
    );
    println!(
        "{}",
        ui::kv(
            "running",
            &format!(
                "{} install --locked --root {} keyrx",
                ui::path_text(&cargo),
                ui::path_text(&install_root)
            )
        )
    );
    println!(
        "{}",
        ui::note("cargo's output follows - \"already installed\" means you have the latest")
    );
    println!(
        "{}",
        ui::bot("then the screen clears and the new keyrx starts")
    );
    println!();
    let status = std::process::Command::new(&cargo)
        .arg("install")
        .arg("--locked")
        .arg("--root")
        .arg(&install_root)
        .arg("keyrx")
        .status();
    match status {
        Ok(st) if st.success() => {}
        Ok(st) => {
            eprintln!("cargo install --locked keyrx exited with {}", st);
            std::process::exit(st.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("could not run {}: {}", ui::path_text(&cargo), e);
            std::process::exit(1);
        }
    }
    // `--root` makes the installation destination part of the command rather
    // than an inference from Cargo configuration. When this executable already
    // lives at <root>/bin/keyrx, root selection preserves that exact lane so a
    // configured Cargo install root cannot receive a one-off second install.
    let exe = if cfg!(windows) { "keyrx.exe" } else { "keyrx" };
    let bin = install_root.join("bin").join(exe);
    let installed = match open_installed_executable(&bin) {
        Ok(file) => file,
        Err(error) => {
            eprintln!(
                "cargo reported success but its installed executable cannot be held safely at {}: {}",
                ui::path_text(&bin),
                error
            );
            std::process::exit(1);
        }
    };
    if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        print!("\x1b[2J\x1b[H");
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let err = exec_held_executable(&installed, &bin);
    eprintln!("could not start {}: {}", ui::path_text(&bin), err);
    std::process::exit(1);
}

/// cargo, wherever rustup put it: $CARGO (set when run under cargo), then PATH,
/// then $CARGO_HOME/bin, then ~/.cargo/bin.
fn find_cargo() -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) { "cargo.exe" } else { "cargo" };
    if let Some(c) = std::env::var_os("CARGO") {
        let p = std::path::PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            let p = d.join(exe);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    cargo_home()
        .map(|h| h.join("bin").join(exe))
        .filter(|p| p.is_file())
}

fn absolute_env_path(name: &str, value: std::ffi::OsString) -> Result<std::path::PathBuf, String> {
    if value.is_empty() {
        return Err(format!("{} is empty", name));
    }
    let path = std::path::PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{} must be an absolute path", name));
    }
    Ok(path)
}

fn running_install_root(current_exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) { "keyrx.exe" } else { "keyrx" };
    if !current_exe.is_absolute() || current_exe.file_name()? != exe {
        return None;
    }
    let bin = current_exe.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    bin.parent().map(std::path::Path::to_path_buf)
}

/// The exact root handed to `cargo install --root`: an explicit override;
/// otherwise the root containing the running installed keyrx; otherwise an
/// absolute Cargo home. The running-executable lane is what preserves Cargo's
/// `[install] root` without trying to reinterpret every Cargo config format.
fn cargo_install_root() -> Result<Option<std::path::PathBuf>, String> {
    if let Some(value) = std::env::var_os("CARGO_INSTALL_ROOT") {
        return absolute_env_path("CARGO_INSTALL_ROOT", value).map(Some);
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(root) = running_install_root(&current_exe) {
            return Ok(Some(root));
        }
    }
    if let Some(value) = std::env::var_os("CARGO_HOME") {
        return absolute_env_path("CARGO_HOME", value).map(Some);
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match home {
        Some(value) => {
            absolute_env_path("HOME/USERPROFILE", value).map(|path| Some(path.join(".cargo")))
        }
        None => Ok(None),
    }
}

fn cargo_home() -> Option<std::path::PathBuf> {
    if let Some(h) = std::env::var_os("CARGO_HOME") {
        return absolute_env_path("CARGO_HOME", h).ok();
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .and_then(|h| absolute_env_path("HOME/USERPROFILE", h).ok())
        .map(|h| h.join(".cargo"))
}

#[cfg(unix)]
fn installed_executable_metadata_is_safe(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = meta.permissions().mode() & 0o777;
    meta.is_file()
        && meta.len() > 0
        && meta.uid() == unsafe { libc::geteuid() }
        && meta.nlink() == 1
        && mode & 0o100 != 0
        && mode & 0o022 == 0
}

#[cfg(unix)]
fn open_installed_executable(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = std::fs::symlink_metadata(path)?;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let held = file.metadata()?;
    let after = std::fs::symlink_metadata(path)?;
    if !installed_executable_metadata_is_safe(&held)
        || before.dev() != held.dev()
        || before.ino() != held.ino()
        || after.dev() != held.dev()
        || after.ino() != held.ino()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed executable is not the same caller-owned, not-group/world-writable, executable, single-link regular file throughout the open",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn held_executable_path_matches(
    file: &std::fs::File,
    path: &std::path::Path,
) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let held = file.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    Ok(installed_executable_metadata_is_safe(&held)
        && current.file_type().is_file()
        && held.dev() == current.dev()
        && held.ino() == current.ino())
}

#[cfg(unix)]
fn exec_vectors(
    argv0: &std::path::Path,
) -> std::io::Result<(Vec<std::ffi::CString>, Vec<std::ffi::CString>)> {
    use std::os::unix::ffi::OsStrExt;
    let argv = vec![
        std::ffi::CString::new(argv0.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "installed path contains NUL",
            )
        })?,
    ];
    let mut environment = Vec::new();
    for (name, value) in std::env::vars_os() {
        let mut bytes = name.as_os_str().as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_os_str().as_bytes());
        environment.push(std::ffi::CString::new(bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "environment contains NUL")
        })?);
    }
    Ok((argv, environment))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn exec_held_executable(file: &std::fs::File, path: &std::path::Path) -> std::io::Error {
    use std::os::fd::AsRawFd;

    if !held_executable_path_matches(file, path).unwrap_or(false) {
        return std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed executable pathname changed before relaunch",
        );
    }
    let Ok((argv, environment)) = exec_vectors(path) else {
        return std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "could not encode the exact relaunch environment",
        );
    };
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = environment.iter().map(|s| s.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let empty = b"\0";
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            file.as_raw_fd(),
            empty.as_ptr().cast::<libc::c_char>(),
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    std::io::Error::last_os_error()
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn exec_held_executable(file: &std::fs::File, path: &std::path::Path) -> std::io::Error {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    if !held_executable_path_matches(file, path).unwrap_or(false) {
        return std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed executable pathname changed before relaunch",
        );
    }
    let descriptor_path = std::path::PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()));
    if !descriptor_path.exists() {
        return std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this Unix does not expose a held executable through /dev/fd",
        );
    }
    std::process::Command::new(descriptor_path)
        .arg0(path)
        .exec()
}

fn cmd_start() {
    ui::masthead(&format!("v{}", env!("CARGO_PKG_VERSION")));
    let n = ui::note;
    let kvw = ui::kvw;
    let cont = ui::cont;
    let blank = || println!("{}", ui::mid(""));
    let head = |t: &str| {
        println!(
            "{}",
            ui::mid(&format!("  {}{}{}{}", ui::b(), ui::wht(), t, ui::r()))
        )
    };

    println!(
        "{}",
        ui::top(
            "WHAT THIS IS",
            "one seed, many addresses, exact keys and paths"
        )
    );
    println!(
        "{}",
        n("Grinds Solana and EVM vanity addresses - an address that ends (or")
    );
    println!(
        "{}",
        n("starts) with the letters you choose - and hands you everything a")
    );
    println!(
        "{}",
        n("wallet needs to hold it: seed phrase, derivation path, and the key in")
    );
    println!(
        "{}",
        n("every import form (base58 and JSON array for Solana, 0x hex for EVM).")
    );
    blank();
    println!(
        "{}",
        n("Fast because `solana-keygen grind` pays 2048 rounds of PBKDF2 (~1.2 ms)")
    );
    println!(
        "{}",
        n("to test ONE address; keyRX pays it once per seed, then walks that")
    );
    println!(
        "{}",
        n("seed's account indices at ~21 us each. The cited run measured")
    );
    println!(
        "{}",
        n("19.5-32.2x aggregate throughput and 33-55x per core.")
    );
    blank();
    println!(
        "{}",
        n("Standalone. No daemon or service. Grinding and local checks are")
    );
    println!(
        "{}",
        n("offline; --update alone uses Cargo's network. Secrets go to a")
    );
    println!(
        "{}",
        n("one private Markdown file per default match (Unix: mode 0600),")
    );
    println!(
        "{}",
        n("never to the screen unless you ask. --out keeps an aggregate.")
    );
    println!(
        "{}",
        ui::bot("verify -> bench -> estimate -> grind -> show")
    );

    println!("{}", ui::top("COMMANDS", "in the order you use them"));
    println!(
        "{}",
        kvw(
            "verify",
            "self-test: base58, both derivations (Solana, EVM) and"
        )
    );
    println!(
        "{}",
        cont("the pinned answers. Prints the manual cross-checks.")
    );
    println!("{}", cont("Run first, always."));
    blank();
    println!(
        "{}",
        kvw(
            "bench",
            "measures this machine's real rate and SAVES it for"
        )
    );
    println!("{}", cont("estimate, per chain.  --chain evm  --indices N"));
    blank();
    println!(
        "{}",
        kvw("estimate", "odds and time-to-match for a pattern, from the")
    );
    println!(
        "{}",
        cont("measured rate. Says what --ignore-case, --checksum")
    );
    println!("{}", cont("or --indices 128 would buy.   --chain sol|evm"));
    blank();
    println!(
        "{}",
        kvw("grind", "the real thing. Same pattern flags as estimate,")
    );
    println!(
        "{}",
        cont("plus output. Ctrl-C stops after the current batch.")
    );
    blank();
    println!(
        "{}",
        kvw("show", "lists matches from the file: address + path,")
    );
    println!(
        "{}",
        cont("seeds withheld. --seeds / --keys print them too.")
    );
    blank();
    println!("{}", kvw("donate", "optional, and it changes nothing."));
    println!(
        "{}",
        kvw(
            "networks",
            "EVM networks a wallet does not list (Robinhood Chain):"
        )
    );
    println!(
        "{}",
        cont("the add-a-network steps and values, bare, for pasting.")
    );
    blank();
    println!(
        "{}",
        kvw(
            "--update",
            "cargo install --locked keyrx, then starts keyrx."
        )
    );
    println!(
        "{}",
        cont("cargo prints its work; then the new start screen.")
    );
    println!("{}", ui::bot("every command takes --help"));

    println!("{}", ui::top("PATTERN FLAGS", "estimate and grind"));
    println!(
        "{}",
        kvw(
            "--ends-with S",
            "suffix. Repeatable. Cheap: only the last N base58"
        )
    );
    println!("{}", cont("characters are computed per candidate."));
    blank();
    println!(
        "{}",
        kvw(
            "--starts-with P",
            "prefix. Repeatable. Slower: needs the full address."
        )
    );
    blank();
    println!(
        "{}",
        kvw(
            "--ignore-case",
            "match either case. ~2^letters more likely:"
        )
    );
    println!("{}", cont("KEYRX goes from 1 in 656M to 1 in 20.5M."));
    blank();
    println!(
        "{}",
        kvw(
            "--path phantom",
            "m/44'/501'/N'/0'   printed with every matching seed"
        )
    );
    println!(
        "{}",
        kvw(
            "--path legacy",
            "m/44'/501'/N'      alternate legacy family"
        )
    );
    blank();
    println!(
        "{}",
        kvw(
            "--chain evm",
            "Ethereum and every EVM chain instead of Solana:"
        )
    );
    println!("{}", cont("hex patterns, m/44'/60'/0'/0/N. See EVM below."));
    println!(
        "{}",
        kvw(
            "--checksum",
            "EVM: letters must land in EIP-55 case as typed."
        )
    );
    blank();
    println!(
        "{}",
        n("base58 has no 0 O I l - patterns using them are rejected.")
    );
    println!("{}", ui::bot("suffixes are the fast lane"));

    println!(
        "{}",
        ui::top(
            "EVM",
            "Ethereum, Base, Arbitrum, Polygon, BNB, Robinhood: one key"
        )
    );
    println!(
        "{}",
        kvw(
            "--chain evm",
            "a 0x address: forty hex digits. secp256k1 in the BIP44"
        )
    );
    println!(
        "{}",
        cont("tree at m/44'/60'/0'/0/N. Import the resulting private")
    );
    println!(
        "{}",
        cont("key into a compatible EVM wallet: one key, every chain.")
    );
    blank();
    println!(
        "{}",
        kvw(
            "patterns",
            "0-9 and a-f. Matched in ANY case by default: hex has"
        )
    );
    println!(
        "{}",
        cont("no case of its own. 0x is allowed in front of a prefix.")
    );
    println!(
        "{}",
        kvw(
            "--checksum",
            "the letters must ALSO come out in EIP-55 case exactly"
        )
    );
    println!(
        "{}",
        cont("as you typed them. Each letter halves the odds: rarer,")
    );
    println!("{}", cont("and it shows. estimate prints both numbers."));
    blank();
    println!(
        "{}",
        kvw(
            "import",
            "MetaMask/Rabby: choose Import account / Private key"
        )
    );
    println!(
        "{}",
        cont("where your current wallet version exposes it, then paste")
    );
    println!("{}", cont("the 0x hex: this address, every EVM chain."));
    println!(
        "{}",
        cont("Seed recovery requires a wallet that accepts the exact")
    );
    println!(
        "{}",
        cont("printed path. Verify the address before funding.")
    );
    blank();
    println!(
        "{}",
        kvw(
            "files",
            "matches/evm/<pattern>.<actual>[.02].md · keyrx show lists"
        )
    );
    println!(
        "{}",
        kvw(
            "networks",
            "keyrx networks - add-a-network steps and the values for"
        )
    );
    println!(
        "{}",
        cont("chains a wallet does not list (Robinhood Chain, 4663).")
    );
    println!(
        "{}",
        kvw("rate", "keyrx bench --chain evm. secp256k1 costs more per")
    );
    println!(
        "{}",
        cont("candidate than Ed25519, so --indices buys less here;")
    );
    println!(
        "{}",
        cont("estimate --chain evm says what, from your own bench.")
    );
    println!(
        "{}",
        ui::bot("the 25th word, --count, --out, --words work the same on both chains")
    );

    println!("{}", ui::top("GRIND FLAGS", ""));
    println!(
        "{}",
        kvw(
            "--out FILE",
            "explicit aggregate file, for scripts and legacy workflows."
        )
    );
    println!(
        "{}",
        cont("Default: one Markdown document per hit, named with its actual case.")
    );
    blank();
    println!(
        "{}",
        kvw(
            "--count N",
            "persist exactly N matches. Default 1. Threads reserve"
        )
    );
    println!(
        "{}",
        cont("slots are reserved before writing; hits cannot overshoot.")
    );
    println!(
        "{}",
        cont("Default: one file per match. With --out, all land in FILE.")
    );
    println!("{}", cont("estimate --count N prints"));
    println!("{}", cont("the time to all N - each match is independent."));
    blank();
    println!(
        "{}",
        kvw(
            "--passphrase",
            "BIP39 passphrase, the '25th word'. Prompted, hidden,"
        )
    );
    println!(
        "{}",
        cont("twice; never stored or printed. The seed alone then")
    );
    println!(
        "{}",
        cont("does NOT reach the address - the keys do. Most browser")
    );
    println!(
        "{}",
        cont("wallets have no passphrase field: import the KEY.")
    );
    blank();
    println!(
        "{}",
        kvw(
            "--words 12|24",
            "mnemonic length. Default 12 - what Phantom generates"
        )
    );
    println!(
        "{}",
        cont("and what most people are used to. BIP39 defines both;")
    );
    println!(
        "{}",
        cont("confirm your receiving wallet supports the length.")
    );
    println!("{}", kvw("--threads N", "default: every core."));
    blank();
    println!(
        "{}",
        kvw(
            "--show-seed",
            "ALSO print the seed to the screen. Off by default:"
        )
    );
    println!(
        "{}",
        cont("keep it out of scrollback, tmux, screen shares.")
    );
    println!("{}", ui::bot(""));

    println!(
        "{}",
        ui::top("THE 128", "what --indices means and why it matters")
    );
    println!(
        "{}",
        n("One seed phrase is a TREE of addresses, not one address. Wallets")
    );
    println!(
        "{}",
        n("number the branches: account 0, 1, 2 ... - that is the N' in")
    );
    println!(
        "{}",
        n("m/44'/501'/N'/0'. Every branch is a real address; all of them")
    );
    println!("{}", n("belong to that phrase."));
    blank();
    println!(
        "{}",
        n("Turning a phrase into the tree's root costs ~1.2 ms (PBKDF2).")
    );
    println!(
        "{}",
        n("Stepping to the next branch costs ~21 us. --indices is how many")
    );
    println!(
        "{}",
        n("branches you check per phrase before throwing the phrase away:")
    );
    blank();
    println!(
        "{}",
        kvw(
            "--indices 8",
            "1.2 ms + 8 x 21 us    =   8 candidates per ~1.4 ms"
        )
    );
    println!(
        "{}",
        kvw(
            "--indices 128",
            "1.2 ms + 128 x 21 us  = 128 candidates per ~3.9 ms"
        )
    );
    println!(
        "{}",
        cont("about six times more per unit of the expensive work")
    );
    blank();
    println!(
        "{}",
        n("The cost: the match lands on ANY branch you checked - with 128 it")
    );
    println!(
        "{}",
        n("may be account 97. That only matters if you import the SEED:")
    );
    println!(
        "{}",
        n("Private-key import lands exactly. Seed recovery depends on whether")
    );
    println!(
        "{}",
        n("that wallet/version can discover the exact printed path.")
    );
    blank();
    println!(
        "{}",
        n("Or skip the tree entirely: every match also writes its PRIVATE KEY,")
    );
    println!(
        "{}",
        n("and a supported 'Import Private Key' flow lands on the")
    );
    println!(
        "{}",
        n("address in one paste, standalone. The index never matters - grind wide.")
    );
    blank();
    head("Private key: --indices 128  ·  Seed recovery: --indices 8");
    blank();
    println!(
        "{}",
        n("EVM: the same 1.2 ms per phrase, then ~65 us per branch (secp256k1")
    );
    println!(
        "{}",
        n("costs more than Ed25519), so --indices buys less there. EVM seed")
    );
    println!(
        "{}",
        n("discovery varies by wallet; exact private-key import skips it.")
    );
    println!(
        "{}",
        ui::bot("estimate shows the exact speed difference on this machine")
    );

    println!("{}", ui::top("WHAT A MATCH WRITES", "and where"));
    println!(
        "{}",
        n("Default: every completed match is one private Markdown document")
    );
    println!(
        "{}",
        n("with clean headings, recovery guidance, and its creation recipe.")
    );
    println!(
        "{}",
        n("Solana carries address, path, seed, private key, and JSON keypair")
    );
    println!(
        "{}",
        n("in mode 0600 inside a mode-0700 managed directory.")
    );
    println!(
        "{}",
        n("--out FILE keeps the compatible aggregate format instead:")
    );
    blank();
    println!("{}", kvw("address", "the vanity address"));
    println!(
        "{}",
        kvw(
            "path",
            "m/44'/501'/N'/0' - where it sits in the seed's tree"
        )
    );
    println!(
        "{}",
        kvw("seed", "the 12 or 24 words - restores the WHOLE tree")
    );
    println!(
        "{}",
        kvw(
            "privkey",
            "base58 keypair - supported private-key import form"
        )
    );
    println!(
        "{}",
        kvw("keypair", "the same key as a JSON array [1,2,...] for")
    );
    println!("{}", cont("solana-keygen."));
    println!(
        "{}",
        cont("Use it only where the wallet exposes key import.")
    );
    println!(
        "{}",
        cont("The keyRX seed + printed path (+ passphrase, if used)")
    );
    println!(
        "{}",
        cont("re-derive this key; an unrelated wallet seed does not.")
    );
    blank();
    println!("{}", kvw("file", &ui::dir_link(&matches_dir())));
    println!(
        "{}",
        cont("one per hit: KEYRX.KEYRX.md / coined.ic.coiNED.md")
    );
    if ui::links_on() {
        println!("{}", cont(ui::CLICK_HINT));
    }
    blank();
    head("EVM: one chain-specific Markdown recovery record per hit");
    println!(
        "{}",
        kvw("address", "0x + forty hex digits, in EIP-55 case")
    );
    println!(
        "{}",
        kvw(
            "path",
            "m/44'/60'/0'/0/N - keyRX's EVM software-wallet lane"
        )
    );
    println!(
        "{}",
        kvw("seed", "the 12 or 24 words - restores the WHOLE tree")
    );
    println!(
        "{}",
        kvw(
            "privkey",
            "0x hex - MetaMask/Rabby 'Import account -> Private key'"
        )
    );
    println!(
        "{}",
        cont("one key form, every EVM chain. Keep the match file or an")
    );
    println!("{}", cont("equivalent seed + path (+ passphrase) backup."));
    println!(
        "{}",
        ui::bot("show lists files · copy its exact .md/.txt command to read one")
    );

    println!(
        "{}",
        ui::top("RECIPES", "pick the wallet you will import into")
    );
    let cmd = |c: &str| {
        println!(
            "{}",
            ui::mid(&format!("    {}{}{}", ui::accent(), c, ui::r()))
        )
    };
    let sub = |t: &str| println!("{}", ui::mid(&format!("    {}{}{}", ui::gry(), t, ui::r())));
    let wal = |w: &str, t: &str| {
        println!(
            "{}",
            ui::mid(&format!(
                "  {}{}{}{}  {}{}{}",
                ui::b(),
                ui::wht(),
                w,
                ui::r(),
                ui::gry(),
                t,
                ui::r()
            ))
        )
    };
    wal(
        "Any wallet",
        "key import - the simplest route, exact address",
    );
    cmd("keyrx grind --ends-with KEYRX --indices 128");
    sub("keyrx show lists the exact record command; add --keys for the");
    sub("base58 used by Phantom/Solflare. JSON is for solana-keygen.");
    sub("The keyRX seed + path re-derives the same key.");
    sub("An unrelated receiving-wallet seed does not back up this imported");
    sub("account. Keep the keyRX match file or equivalent backup.");
    blank();
    wal(
        "Seed route",
        "wallet/version path discovery varies; keep it bounded",
    );
    cmd("keyrx grind --ends-with KEYRX --words 12 --indices 8");
    sub("restore with tooling that can select the exact printed path;");
    sub("verify the address. Eight indices bound the possible index to 0-7.");
    blank();
    wal(
        "Solflare",
        "by seed - path discovery depends on the installed version",
    );
    cmd("keyrx grind --ends-with KEYRX --indices 8");
    sub("use the printed path where supported and verify the exact address;");
    sub("private-key import above is the reliable exact-address lane.");
    blank();
    wal("Either", "case-insensitive: 32x more likely for KEYRX");
    cmd("keyrx grind --ends-with KEYRX --ignore-case --indices 8");
    sub("matches keyrx, Keyrx, KEYRX, kEyRx... - only an exact-case grind");
    sub("guarantees the letters print exactly KEYRX.");
    blank();
    wal("Prefix", "the address STARTS with your letters");
    cmd("keyrx grind --starts-with Key --indices 128");
    sub("slower per candidate: a prefix needs the whole address encoded,");
    sub("a suffix only its last N characters. Solana prefix odds are shown as");
    sub("approximate because leading base58 characters are not uniform.");
    sub("Repeatable, and combinable: --starts-with Key --ends-with RX");
    blank();
    wal(
        "EVM",
        "MetaMask/Rabby private-key import - one key, every EVM chain",
    );
    cmd("keyrx grind --chain evm --ends-with dead --indices 128");
    sub("hex, any case: 0x...dead, 0x...DEAD, 0x...DeAd all count. keyrx show");
    sub("evm/dead --keys: paste the 0x hex into Import account / Private key.");
    blank();
    wal(
        "EVM, EIP-55",
        "the letters land in checksum case exactly as typed",
    );
    cmd("keyrx grind --chain evm --ends-with DeAd --checksum");
    sub("rarer by a coin flip per letter (here 16x): the address prints DeAd.");
    sub("prefix with 0x: --starts-with 0xc0ffee. estimate prints both odds.");
    println!(
        "{}",
        ui::bot("estimate first: it prints the odds for THIS machine")
    );

    println!(
        "{}",
        ui::top(
            "A TYPICAL SESSION",
            "variations, in the order you reach for them"
        )
    );
    // command, then a grey note: beside it when the row has room (with a column of air before
    // the border), beneath it when not. Indent 2, command column 44, one space, "# ", the note.
    let step = |c: &str, n: &str| {
        if 2 + c.chars().count().max(44) + 3 + n.chars().count() < ui::IN {
            println!(
                "{}",
                ui::mid(&format!(
                    "  {}{:<44}{} {}# {}{}",
                    ui::accent(),
                    c,
                    ui::r(),
                    ui::gry(),
                    n,
                    ui::r()
                ))
            );
        } else {
            cmd(c);
            println!(
                "{}",
                ui::mid(&format!("    {}# {}{}", ui::gry(), n, ui::r()))
            );
        }
    };
    step("keyrx verify", "once per machine");
    step("keyrx bench --indices 128", "this box's rate, saved");
    step(
        "keyrx estimate --ends-with KEYRX --indices 128 --count 10",
        "odds; time to one and ten",
    );
    step(
        "keyrx grind --ends-with KEYRX --indices 128",
        "the real thing",
    );
    step(
        "keyrx grind --ends-with KEYRX --count 10",
        "ten private Markdown records",
    );
    step(
        "keyrx grind --ends-with KEYRX --indices 8",
        "seed path bounded to index 0-7",
    );
    step(
        "keyrx grind --ends-with KEYRX --passphrase",
        "a 25th word, prompted",
    );
    step(
        "keyrx grind --starts-with Key --ends-with RX",
        "both ends at once",
    );
    step(
        "keyrx grind --ends-with KEYRX --ignore-case",
        "any case, 32x likelier",
    );
    step(
        "keyrx estimate --chain evm --ends-with dead",
        "EVM: hex, any case",
    );
    step(
        "keyrx grind --chain evm --ends-with dead",
        "0x...dead, MetaMask/Rabby",
    );
    step("keyrx bench --chain evm", "the EVM rate, saved");
    step("keyrx show", "every match file, with exact read commands");
    step("keyrx networks", "add a network: Robinhood");
    step(
        "keyrx show FILE.md --keys",
        "one listed file, keys revealed",
    );
    step("keyrx --update", "latest, then this screen");
    blank();
    println!(
        "{}",
        ui::warn_line("import and verify the address BEFORE funding.")
    );
    println!(
        "{}",
        ui::warn_line("the match file holds seed and keys. Treat it like a key - it is one.")
    );
    println!("{}", ui::bot("keyrx <command> --help · keyrx.tech · MIT"));
    println!();
}

fn cmd_donate() {
    ui::masthead("donate");
    println!("{}", ui::top("DONATE", "optional, and it changes nothing"));
    println!(
        "{}",
        ui::note("keyRX is MIT and stays that way. No paid tier, no hosted version")
    );
    println!(
        "{}",
        ui::note("waiting behind it, no feature held back. Nothing is gated on this.")
    );
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::mid(&format!("  {}{}Solana{}", ui::b(), ui::wht(), ui::r()))
    );
    #[allow(clippy::const_is_empty)] // empty until the vanity grind lands
    if DONATE_SOL.is_empty() {
        println!(
            "{}",
            ui::note("address not set yet - it will be a keyRX vanity address, ground")
        );
        println!("{}", ui::note("with this tool. Check keyrx.tech."));
    } else {
        println!(
            "{}",
            ui::mid(&format!("  {}{}{}", ui::warn(), DONATE_SOL, ui::r()))
        );
        println!("{}", ui::note("the literal address above is authoritative"));
    }
    #[allow(clippy::const_is_empty)] // empty until the EVM vanity grind lands
    if !DONATE_EVM.is_empty() {
        println!("{}", ui::mid(""));
        println!(
            "{}",
            ui::mid(&format!(
                "  {}{}EVM{}  {}Ethereum, Base, Arbitrum, Polygon, BNB... one address for all{}",
                ui::b(),
                ui::wht(),
                ui::r(),
                ui::gry(),
                ui::r()
            ))
        );
        println!(
            "{}",
            ui::mid(&format!("  {}{}{}", ui::warn(), DONATE_EVM, ui::r()))
        );
        // keyrx.eth (ENS, every EVM chain), keyrx.base.eth (Base), keyrx.hoodfi.eth (Robinhood
        // Chain): all resolve to the address above. Same rule: aliases of the address.
        println!("{}", ui::mid(&format!("  {}keyrx.eth   keyrx.base.eth   keyrx.hoodfi.eth{}  {}the same address, by name{}", ui::wht(), ui::r(), ui::gry(), ui::r())));
    }
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::note("If you got more out of this than it cost you to read the source,")
    );
    println!(
        "{}",
        ui::note("that trade already worked. Chip in a Sol or two, or some ETH, if")
    );
    println!(
        "{}",
        ui::note("you like. It buys nothing - no tier, no badge, no priority - which")
    );
    println!(
        "{}",
        ui::note("is what makes it a donation and not a purchase.")
    );
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::mid(&format!(
            "  {}{}There will be no keyRX token from the developer of keyRX.{}",
            ui::b(),
            ui::wht(),
            ui::r()
        ))
    );
    println!(
        "{}",
        ui::note("No presale. No airdrop. No community round. No Phase 3.")
    );
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::note("You can launch one - someone always does. The ask: creator fees")
    );
    println!(
        "{}",
        ui::note("plus 3% of supply to the address above, and the token's socials")
    );
    println!(
        "{}",
        ui::note("pointed at @keyrx_tech and keyrx.tech - the only two places this")
    );
    println!(
        "{}",
        ui::note("project exists. What you may not do is LARP as this project while")
    );
    println!(
        "{}",
        ui::note("you do it: no \"official\", no borrowed name, no invented team.")
    );
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::mid(&format!(
            "  {}{}X is the only place keyRX exists.{}",
            ui::b(),
            ui::wht(),
            ui::r()
        ))
    );
    println!(
        "{}",
        ui::note("No Discord, no Telegram, no Reddit, no group chat, no \"community\".")
    );
    println!(
        "{}",
        ui::note("If something calls itself keyRX anywhere other than @keyrx_tech or")
    );
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
    println!(
        "{}",
        ui::top(
            "ADD A NETWORK",
            "one address across EVM chains; add some once"
        )
    );
    println!(
        "{}",
        ui::note("MetaMask and Rabby ship the big chains. For any other EVM chain you add")
    );
    println!(
        "{}",
        ui::note("the network once; the ACCOUNT does not change - same 0x address, same")
    );
    println!("{}", ui::note("key - only the network you are looking at."));
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::kv(
            "MetaMask",
            "network selector (top left) -> Add a custom network ->"
        )
    );
    println!(
        "{}",
        ui::kv("", "fill the five fields below -> Save -> select it")
    );
    println!(
        "{}",
        ui::kv("Rabby", "More -> Add Custom Network -> the same fields")
    );
    println!(
        "{}",
        ui::bot("values bare below the frame, one per line, for pasting")
    );
    for n in NETWORKS {
        println!("{}", ui::top(n.name, n.what));
        println!("{}", ui::kv("name", n.name));
        println!("{}", ui::kv("RPC URL", &ui::link(n.rpc, n.rpc)));
        println!("{}", ui::kv("chain ID", &n.chain_id.to_string()));
        println!("{}", ui::kv("currency", n.symbol));
        println!(
            "{}",
            ui::kv(
                "explorer",
                &format!(
                    "{}  ({})",
                    ui::link(n.explorer, n.explorer),
                    n.explorer_note
                )
            )
        );
        println!(
            "{}",
            ui::bot(&format!(
                "chain id checked against the live RPC on {}",
                n.checked
            ))
        );
        for (label, value) in [
            ("network name", n.name.to_string()),
            ("RPC URL", n.rpc.to_string()),
            ("chain ID", n.chain_id.to_string()),
            ("currency symbol", n.symbol.to_string()),
            ("block explorer", n.explorer.to_string()),
        ] {
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
    let mut hex = String::with_capacity(seed.len() * 2);
    for byte in seed {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    mn.to_string() == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" && hex == BIP39_VECTOR_SEED
}

fn cmd_verify() {
    ui::masthead("verify");
    println!(
        "{}",
        ui::top("SELF-TEST", "run this before trusting a result")
    );
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
                println!(
                    "{}",
                    ui::crit_line(&format!("b58_suffix MISMATCH iter={} n={}", i, n))
                );
                println!("{}", ui::bot("STOP"));
                std::process::exit(1);
            }
        }
    }
    println!(
        "{}",
        ui::ok_line("b58_suffix vs full encoding   50,000 pubkeys x 10 lengths")
    );

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
        println!(
            "{}",
            ui::ok_line("BIP39 passphrase matches the spec vector  (\"TREZOR\", pinned)")
        );
    } else {
        println!(
            "{}",
            ui::crit_line("BIP39 passphrase seed DOES NOT match the specification vector")
        );
        println!("{}", ui::bot("STOP"));
        std::process::exit(1);
    }
    // The pinned solana-keygen answer for this public test entropy - checked
    // by hand on 2026-08-16 and locked as a test. If it ever moves, STOP.
    const XCHECK: &str = "8zzKEAB4VqnUchbsmAor9QzyVWVQFanQGJYQw8UQPh1j";
    if addr == XCHECK {
        println!(
            "{}",
            ui::ok_line("SLIP-0010 matches solana-keygen  (pinned cross-check)")
        );
    } else {
        println!(
            "{}",
            ui::crit_line("SLIP-0010 does NOT match the pinned solana-keygen answer")
        );
    }
    println!(
        "{}",
        ui::bot(if addr == XCHECK {
            "all green"
        } else {
            "STOP - do not fund anything from this build"
        })
    );

    // EVM: every pinned answer - the published mnemonic, the independent reference for
    // this tool's own test seed, EIP-55's examples, private key 1 - and the walk.
    println!(
        "{}",
        ui::top("SELF-TEST · EVM", "secp256k1 · BIP32 · keccak · EIP-55")
    );
    let mut evm_ok = true;
    for (what, ok) in evm::self_test() {
        evm_ok &= ok;
        println!(
            "{}",
            if ok {
                ui::ok_line(&what)
            } else {
                ui::crit_line(&format!("{}  - DOES NOT HOLD", what))
            }
        );
    }
    println!(
        "{}",
        ui::bot(if evm_ok {
            "all green"
        } else {
            "STOP - do not fund anything from this build"
        })
    );

    println!(
        "{}",
        ui::top("MANUAL CROSS-CHECK", "one command, once per machine")
    );
    println!(
        "{}",
        ui::note("Nothing automated can prove SLIP-0010 matches what wallets do.")
    );
    println!(
        "{}",
        ui::note("A wrong build grinds normally and prints an address no wallet")
    );
    println!(
        "{}",
        ui::note("can derive. Confirm once with Solana's own tool:")
    );
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::kv("test seed", "(throwaway, public constant, never fund it)")
    );
    // Never clip a seed word: a truncated word is a wrong word. Eight per row
    // fits the frame at the longest BIP39 word length.
    let words: Vec<&str> = mn.words().collect();
    for chunk in words.chunks(8) {
        println!(
            "{}",
            ui::mid(&format!("    {}{}{}", ui::wht(), chunk.join(" "), ui::r()))
        );
    }
    println!("{}", ui::mid(""));
    println!("{}", ui::kv("this build", &addr));
    println!("{}", ui::kv("path", "m/44'/501'/0'/0'"));
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::note("run:  solana-keygen pubkey \"prompt://?full-path=m/44'/501'/0'/0'\"")
    );
    println!(
        "{}",
        ui::note("      paste the seed, empty passphrase - the two addresses must match")
    );
    println!(
        "{}",
        ui::note("      (a --passphrase grind: type the same passphrase at its prompt)")
    );
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::kv(
            "EVM",
            "the same seed at m/44'/60'/0'/0/0, throwaway wallet:"
        )
    );
    println!("{}", ui::kv("this build", evm::TEST_SEED_ACCOUNTS[0].1));
    println!(
        "{}",
        ui::note("run:  cast wallet address --mnemonic \"<seed>\" --mnemonic-index 0")
    );
    println!(
        "{}",
        ui::note("      or import the seed in a fresh MetaMask: account 1 must show it")
    );
    println!("{}", ui::bot("if they differ, STOP"));
    println!();
    if addr != XCHECK || !evm_ok {
        std::process::exit(1);
    }
}

/// The pattern line, per chain: `*KEYRX` / `Key*` for Solana; `*dead` / `0xdead*`
/// for EVM, with what the case means on that chain.
fn pattern_line(m: &Matcher, p: &PatternArgs) -> String {
    let sfx: Vec<String> = m
        .suffixes
        .iter()
        .map(|s| format!("*{}", String::from_utf8_lossy(s)))
        .collect();
    let pfx: Vec<String> = match m.chain {
        Chain::Sol => m
            .prefixes
            .iter()
            .map(|s| format!("{}*", String::from_utf8_lossy(s)))
            .collect(),
        Chain::Evm => m
            .prefixes
            .iter()
            .map(|s| format!("0x{}*", String::from_utf8_lossy(s)))
            .collect(),
    };
    // both kinds present = one hunt with two ends, and the line says so
    let pats: Vec<String> = if !sfx.is_empty() && !pfx.is_empty() {
        vec![format!("{} AND {}", pfx.join("  "), sfx.join("  "))]
    } else {
        sfx.into_iter().chain(pfx).collect()
    };
    let case = match (m.chain, p.ignore_case, p.checksum) {
        (Chain::Sol, true, _) => "   (case-insensitive)",
        (Chain::Sol, false, _) => "",
        (Chain::Evm, _, true) => "   (EVM · letters in EIP-55 case)",
        (Chain::Evm, _, false) => "   (EVM · any case)",
    };
    format!("{}{}", pats.join("  "), case)
}

fn cmd_estimate(p: PatternArgs, threads: usize, indices: u32, count: usize, words: usize) {
    if let Err(e) = validate_work_args(threads, indices, count) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
    if !matches!(words, 12 | 24) {
        eprintln!("error: --words must be 12 or 24");
        std::process::exit(1);
    }
    let m = match Matcher::new(&p) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };
    let chain = p.chain;
    let path = p.path;
    let prob = m.probability();
    let cached = load_rate(chain, path, words);
    // A measurement is evidence only for the exact thread/index lane that ran.
    // Even on that lane, a different matcher shape is an approximate measured
    // baseline, never an exact rate for the requested work.
    let measured = cached.filter(|rate| rate.threads == threads && rate.indices == indices);
    let exact_measured = measured.filter(|rate| rate.workload.is_exact_for(&m));
    let rate_context = format!(
        "{}w {} - {}t / {} idx",
        words,
        match chain {
            Chain::Sol => match path {
                PathStyle::Phantom => "Phantom",
                PathStyle::Legacy => "legacy",
            },
            Chain::Evm => "EVM",
        },
        threads,
        indices
    );
    #[derive(Copy, Clone, PartialEq)]
    enum RateBasis {
        ExactMeasured,
        ApproximateMeasured,
        Theoretical,
    }
    let (rate, basis, rate_basis) = match (exact_measured, measured) {
        (Some(saved), _) => (
            saved.rate,
            format!("MEASURED EXACT - {rate_context}"),
            RateBasis::ExactMeasured,
        ),
        (None, Some(saved)) => (
            saved.rate,
            format!("APPROX MEASURED - matcher differs - {rate_context}"),
            RateBasis::ApproximateMeasured,
        ),
        (None, None) => (
            model_rate(chain, path, indices) * threads as f64,
            format!("THEORETICAL - bench first - {rate_context}"),
            RateBasis::Theoretical,
        ),
    };
    ui::masthead("estimate");
    println!("{}", ui::top("ODDS", "before you grind"));
    println!("{}", ui::kv("pattern", &pattern_line(&m, &p)));
    println!(
        "{}",
        ui::kv(
            "odds",
            &format!(
                "{}1 in {}",
                if m.probability_is_approximate() {
                    "~"
                } else {
                    ""
                },
                group(1.0 / prob)
            )
        )
    );
    if chain == Chain::Sol {
        println!("{}", ui::warn_line("Solana odds are an approximate model."));
        println!(
            "{}",
            ui::note("Signing-key outputs are not uniform base58 text.")
        );
        if !m.prefixes.is_empty() {
            println!("{}", ui::note("Leading characters add length bias too."));
            println!("{}", ui::mid(""));
            println!("{}", ui::kv("rate", "not claimed for a prefix lane"));
            println!(
                "{}",
                ui::note("bench measures suffix grinding; grind shows this exact lane live.")
            );
            println!("{}", ui::bot("no suffix-lane ETA reused for a prefix"));
            println!();
            return;
        }
    }
    if chain == Chain::Evm && m.checksum && m.probability_is_approximate() {
        println!("{}", ui::warn_line("EIP-55 checksum odds are approximate."));
        println!(
            "{}",
            ui::note("Checksum letter case is modeled as a random oracle.")
        );
    }
    println!(
        "{}",
        ui::kv(
            "rate",
            &format!(
                "{}/sec  ({} threads, {} indices/mnemonic{})",
                group(rate),
                threads,
                indices,
                if chain == Chain::Evm {
                    " · secp256k1"
                } else {
                    ""
                }
            )
        )
    );
    println!(
        "{}",
        if rate_basis == RateBasis::ExactMeasured {
            ui::note(&format!("basis      {}", basis))
        } else {
            ui::warn_line(&format!("basis    {}", basis))
        }
    );
    println!("{}", ui::mid(""));
    println!("{}", ui::note("time to first match"));
    quantiles(prob, rate);
    if count > 1 {
        println!("{}", ui::mid(""));
        println!(
            "{}",
            ui::note(&format!(
                "time to all {} matches  (grind --count {} - each one is independent)",
                count, count
            ))
        );
        quantiles_n(prob, rate, count);
    }
    println!(
        "{}",
        ui::bot(match rate_basis {
            RateBasis::ExactMeasured => "from this machine's exact benchmark workload",
            RateBasis::ApproximateMeasured => {
                "approximate - measured benchmark workload differs from this matcher"
            }
            RateBasis::Theoretical => match chain {
                Chain::Sol => "theoretical - ran 2.6x optimistic on real hardware",
                Chain::Evm => "theoretical - anchored to one measured machine; bench yours",
            },
        })
    );

    // The levers, as numbers.
    let mut levers: Vec<String> = Vec::new();
    let has_letters = m
        .suffixes
        .iter()
        .chain(m.prefixes.iter())
        .any(|s| s.iter().any(|c| c.is_ascii_alphabetic()));
    if chain == Chain::Sol && !p.ignore_case && has_letters {
        let ic = PatternArgs {
            ignore_case: true,
            ..p.clone()
        };
        if let Ok(mi) = Matcher::new(&ic) {
            let k = mi.probability() / prob;
            if k > 1.5 {
                levers.push(format!(
                    "--ignore-case   {:.0}x more likely - 1 in {}, 50% in ~{}",
                    k,
                    group(1.0 / mi.probability()),
                    fmt_dur(trials_for(0.5, mi.probability()) / rate)
                ));
            }
        }
    }
    if chain == Chain::Evm && has_letters {
        // the other way round on EVM: any case is the default, and --checksum is the
        // rarer ask - say what it costs, or what dropping it would give back
        let other = PatternArgs {
            checksum: !p.checksum,
            ignore_case: false,
            ..p.clone()
        };
        if let Ok(mo) = Matcher::new(&other) {
            let k = mo.probability() / prob;
            if p.checksum {
                levers.push(format!(
                    "without --checksum   {:.0}x more likely - 1 in {}, 50% in ~{}",
                    k,
                    group(1.0 / mo.probability()),
                    fmt_dur(trials_for(0.5, mo.probability()) / rate)
                ));
            } else {
                levers.push(format!(
                    "--checksum   EIP-55 case too - 1 in {}, 50% in ~{}",
                    group(1.0 / mo.probability()),
                    fmt_dur(trials_for(0.5, mo.probability()) / rate)
                ));
            }
        }
    }
    if indices < 128 {
        // Never project a measured benchmark onto settings that were not
        // measured. This comparison is the model's rough shape only.
        let modeled_now = model_rate(chain, path, indices) * threads as f64;
        let modeled_128 = model_rate(chain, path, 128) * threads as f64;
        if modeled_128 / modeled_now > 1.05 {
            levers.push(format!(
                "--indices 128   rough theoretical ~{:.1}x rate - benchmark it",
                modeled_128 / modeled_now
            ));
            levers.push("                match may land at a higher account index".to_string());
        }
    }
    if !levers.is_empty() {
        println!("{}", ui::top("LEVERS", "what the flags would buy"));
        for l in levers {
            println!("{}", ui::note(&l));
        }
        println!("{}", ui::bot(""));
    }
    println!();
}

fn cmd_bench(
    chain: Chain,
    threads: usize,
    indices: u32,
    seconds: u64,
    path: PathStyle,
    words: usize,
) {
    #[cfg(not(unix))]
    {
        let _ = (chain, threads, indices, seconds, path, words);
        eprintln!(
            "bench refuses on this platform because atomic private cache replacement is not yet implemented; use a Unix host or WSL"
        );
        std::process::exit(1);
    }
    if let Err(e) = validate_bench_args(threads, indices, seconds) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
    if !matches!(words, 12 | 24) {
        eprintln!("error: --words must be 12 or 24");
        std::process::exit(1);
    }
    if chain == Chain::Evm && path == PathStyle::Legacy {
        eprintln!("error: --path legacy is Solana-only");
        std::process::exit(1);
    }
    let executable = match executable_fingerprint() {
        Ok(fingerprint) => fingerprint,
        Err(e) => {
            eprintln!(
                "error: cannot bind this benchmark to the exact running executable: {}",
                e
            );
            std::process::exit(1);
        }
    };
    let cache = match rate_cache_path(chain, path, words) {
        Some(path) => path,
        None => {
            eprintln!(
                "error: cannot locate a benchmark cache; set XDG_DATA_HOME or HOME before bench"
            );
            std::process::exit(1);
        }
    };
    let cache_stage = match RateCacheStage::acquire(&cache) {
        Ok(stage) => stage,
        Err(e) => {
            eprintln!("error: benchmark cache custody failed before timing: {}", e);
            std::process::exit(1);
        }
    };
    let entropy_len = if words == 12 { 16 } else { 32 };
    let workload = BenchWorkload::for_chain(chain);
    ui::masthead("bench");
    println!(
        "{}",
        ui::top(
            "BENCH",
            &format!(
                "{}{} threads · {} indices/mnemonic · {}s",
                if chain == Chain::Evm { "EVM · " } else { "" },
                threads,
                indices,
                seconds
            )
        )
    );
    println!(
        "{}",
        ui::kv(
            "lane",
            &match chain {
                Chain::Sol => format!("{:?} · {}-word mnemonics", path, words),
                Chain::Evm => format!("EVM BIP44 m/44'/60'/0'/0/N · {}-word mnemonics", words),
            }
        )
    );
    println!("{}", ui::kv("workload", workload.description()));
    println!(
        "{}",
        ui::note("grinding an astronomically rare target; any hit is ignored...")
    );
    let _ = std::io::stdout().flush();
    let p = PatternArgs {
        ends_with: vec![match chain {
            Chain::Sol => "zzzzz".into(),
            Chain::Evm => "ffffffffffffffff".into(),
        }],
        starts_with: vec![],
        ignore_case: false,
        path,
        chain,
        checksum: false,
    };
    let m = Arc::new(Matcher::new(&p).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let spawn_result = std::thread::scope(|s| {
        for _ in 0..threads {
            let (m, stop, counter) = (Arc::clone(&m), Arc::clone(&stop), Arc::clone(&counter));
            let lane_stop = Arc::clone(&stop);
            if let Err(e) = std::thread::Builder::new().spawn_scoped(s, move || match chain {
                Chain::Sol => {
                    grind_loop(&m, path, indices, entropy_len, "", &stop, &counter, &|_| {})
                }
                Chain::Evm => {
                    grind_loop_evm(&m, indices, entropy_len, "", &stop, &counter, &|_| {})
                }
            }) {
                lane_stop.store(true, Ordering::SeqCst);
                return Err(e);
            }
        }
        std::thread::sleep(Duration::from_secs(seconds));
        stop.store(true, Ordering::SeqCst);
        Ok::<(), std::io::Error>(())
    });
    if let Err(e) = spawn_result {
        eprintln!("could not start every benchmark worker: {}", e);
        drop(cache_stage);
        std::process::exit(1);
    }

    let n = counter.load(Ordering::Relaxed);
    let secs = start.elapsed().as_secs_f64();
    let rate = n as f64 / secs;
    println!("{}", ui::mid(""));
    println!(
        "{}",
        ui::kv(
            "candidates",
            &format!("{} in {:.1}s", group(n as f64), secs)
        )
    );
    println!(
        "{}",
        ui::kv_accent(
            "rate",
            &format!(
                "{}/sec total · {}/sec/thread",
                group(rate),
                group(rate / threads as f64)
            )
        )
    );
    match chain {
        Chain::Sol => {
            println!("{}", ui::mid(""));
            println!(
                "{}",
                ui::note("time to first 5-char suffix (1 in 656,356,768)")
            );
            quantiles(1.0 / 656_356_768.0, rate);
        }
        Chain::Evm => {
            // no baseline claim here: nothing measured to compare against yet
            println!("{}", ui::mid(""));
            println!(
                "{}",
                ui::note("time to first 6-hex suffix, any case (1 in 16,777,216)")
            );
            quantiles(1.0 / 16_777_216.0, rate);
            println!("{}", ui::mid(""));
            println!(
                "{}",
                ui::note("time to first 8-hex suffix, any case (1 in 4,294,967,296)")
            );
            quantiles(1.0 / 4_294_967_296.0, rate);
        }
    }
    match save_rate(
        cache_stage,
        chain,
        path,
        words,
        threads,
        indices,
        rate,
        &executable,
    ) {
        Ok(cache) => println!(
            "{}",
            ui::bot(&format!("saved for estimate -> {}", ui::path_text(&cache)))
        ),
        Err(e) => {
            eprintln!("could not save benchmark cache: {}", e);
            std::process::exit(1);
        }
    }
    println!();
}

/// Ask for the BIP39 passphrase on the terminal, hidden, twice. Empty is
/// refused (that is the default, and asking for it would only confuse the
/// file's "passphrase used" line); a mismatch asks again.
fn ask_passphrase() -> Result<Zeroizing<String>, String> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err("--passphrase needs a terminal to type it into (it is never read from a file, a flag, or the environment)".into());
    }
    println!();
    println!("{}", ui::top("PASSPHRASE", "BIP39, the \"25th word\""));
    println!(
        "{}",
        ui::note("Typed twice, hidden. Never stored, never printed, never in the match file.")
    );
    println!(
        "{}",
        ui::note("The seed alone will NOT reach the address without it - the keys will.")
    );
    println!(
        "{}",
        ui::note("Most browser wallets have no passphrase field: import the KEY.")
    );
    println!(
        "{}",
        ui::bot("lose the passphrase and the seed is just twelve words")
    );
    loop {
        let a = match rpassword::prompt_password("  passphrase: ") {
            Ok(v) => Zeroizing::new(v),
            Err(e) => {
                return Err(format!("could not read the passphrase: {}", e));
            }
        };
        if a.is_empty() {
            println!(
                "{}",
                ui::warn_line(
                    "empty - run without --passphrase for the standard, passphrase-free seed"
                )
            );
            continue;
        }
        let b = match rpassword::prompt_password("  again:      ") {
            Ok(v) => Zeroizing::new(v),
            Err(e) => {
                return Err(format!("could not read the passphrase: {}", e));
            }
        };
        if *a != *b {
            println!("{}", ui::warn_line("they differ - again"));
            continue;
        }
        return Ok(a);
    }
}

fn grind_exit_status(write_failed: bool, interrupted: bool, hits: u64, count: usize) -> i32 {
    if write_failed {
        1
    } else if hits < count as u64 {
        if interrupted {
            130
        } else {
            1
        }
    } else {
        0
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_grind(
    p: PatternArgs,
    threads: usize,
    indices: u32,
    count: usize,
    words: usize,
    out: std::path::PathBuf,
    managed_out: bool,
    show_seed: bool,
    with_passphrase: bool,
) -> i32 {
    #[cfg(not(unix))]
    {
        let _ = (
            p,
            threads,
            indices,
            count,
            words,
            out,
            managed_out,
            show_seed,
            with_passphrase,
        );
        eprintln!("grind refuses on this platform because an owner-only output ACL is not yet implemented; use a Unix host or WSL");
        return 1;
    }
    if let Err(e) = validate_work_args(threads, indices, count) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
    let entropy_len = match words {
        12 => 16,
        24 => 32,
        _ => {
            eprintln!("--words must be 12 or 24");
            std::process::exit(1);
        }
    };
    let m = match Matcher::new(&p) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };
    let chain = p.chain;
    let match_header = match build_match_file_header(&p, indices, words, with_passphrase) {
        Ok(header) => Arc::new(header),
        Err(e) => {
            eprintln!("cannot build the match-file header: {}", e);
            return 1;
        }
    };
    if m.needs_full && chain == Chain::Sol {
        eprintln!("note: prefix matching needs full base58 per candidate (slower than suffix)");
    }
    if indices > 16 && chain == Chain::Sol {
        eprintln!(
            "note: --indices {} - the match may land at account index up to {}.",
            indices,
            indices - 1
        );
        eprintln!("      Fine for private-key import. Seed recovery depends on wallet/version");
        eprintln!("      path discovery; use --indices 8 unless that exact path is proven.");
    }

    let prob = m.probability();
    let style = p.path;
    let m = Arc::new(m);
    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    let write_failed = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let reserved = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(AtomicU64::new(0));
    let display = Arc::new(Mutex::new(()));
    let stdout_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());

    // Prompt before acquiring any filesystem custody. Error paths in the hidden
    // terminal prompt exit the process directly, which would otherwise strand a
    // live-looking marker because process::exit does not run Drop.
    let passphrase: Arc<Zeroizing<String>> = Arc::new(if with_passphrase {
        match ask_passphrase() {
            Ok(passphrase) => passphrase,
            Err(e) => {
                eprintln!("{}", e);
                return 1;
            }
        }
    } else {
        Zeroizing::new(String::new())
    });

    // Install the handler after the hidden prompt, while no output file or
    // marker exists. Ctrl-C at the prompt keeps the terminal library's normal
    // abort behaviour; a handler that cannot be installed is a refusal rather
    // than a grind that may strand its marker on an unhandled signal.
    {
        let stop = Arc::clone(&stop);
        let interrupted = Arc::clone(&interrupted);
        if let Err(e) = ctrlc::set_handler(move || {
            eprintln!("\ninterrupted -- finishing current batch");
            interrupted.store(true, Ordering::SeqCst);
            stop.store(true, Ordering::SeqCst);
        }) {
            eprintln!("cannot install the interrupt handler: {}", e);
            return 1;
        }
    }

    let requested = out;
    if let Err(e) = validate_operator_path(&requested) {
        eprintln!("cannot use output path: {}", e);
        return 1;
    }
    if let Err(e) = prepare_output_parent(&requested, managed_out) {
        eprintln!("cannot prepare {}: {}", ui::path_text(&requested), e);
        return 1;
    }
    if managed_out {
        let widest = "x".repeat(m.max_realized_filename_edge_len());
        if let Err(e) = managed_match_path(&requested, &widest, usize::MAX) {
            eprintln!("cannot use managed output lane: {}", e);
            return 1;
        }
    }
    // Coordination owns the requested name before the file is opened, read,
    // chmodded, or validated. A second process therefore refuses rather than
    // mistaking an in-flight append for corruption and diverting to recovery.
    let mut requested_lock = match GrindLock::acquire(&requested) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("cannot start grind: {}", e);
            return 1;
        }
    };
    let mut recovery_lock: Option<GrindLock> = None;
    let (out_path, sink) = if managed_out {
        let out_path = requested.clone();
        (
            out_path,
            GrindSink::Managed(ManagedMatchWriter::new(requested)),
        )
    } else {
        let (out_path, file) = match open_match_file(&requested, &match_header) {
            Ok(file) => (requested, file),
            Err(first) => {
                let recovered = recovery_output_path(&requested);
                if let Err(e) = prepare_output_parent(&recovered, false) {
                    eprintln!(
                        "cannot prepare {} after {}: {}",
                        ui::path_text(&recovered),
                        first,
                        e
                    );
                    return 1;
                }
                recovery_lock = match GrindLock::acquire(&recovered) {
                    Ok(lock) => Some(lock),
                    Err(e) => {
                        eprintln!("cannot start recovery grind: {}", e);
                        return 1;
                    }
                };
                match open_match_file(&recovered, &match_header) {
                    Ok(file) => {
                        eprintln!(
                            "OUTPUT REFUSED ({}) -- using {} instead",
                            first,
                            ui::path_text(&recovered)
                        );
                        (recovered, file)
                    }
                    Err(second) => {
                        eprintln!(
                            "OUTPUT REFUSED twice ({}; {}) -- no grind started",
                            first, second
                        );
                        return 1;
                    }
                }
            }
        };
        (
            out_path.clone(),
            GrindSink::Aggregate {
                path: out_path,
                file,
            },
        )
    };
    let sink = Arc::new(Mutex::new(sink));
    ui::masthead("grind");
    println!(
        "{}",
        ui::top("GRIND", "Ctrl-C stops after the current batch")
    );
    println!("{}", ui::kv("pattern", &pattern_line(&m, &p)));
    println!(
        "{}",
        ui::kv(
            "odds",
            &format!(
                "{}1 in {}",
                if m.probability_is_approximate() {
                    "~"
                } else {
                    ""
                },
                group(1.0 / prob)
            )
        )
    );
    println!(
        "{}",
        ui::kv(
            "threads",
            &format!(
                "{} · {} indices/mnemonic · {}-word seeds{}",
                threads,
                indices,
                words,
                if chain == Chain::Evm {
                    " · m/44'/60'/0'/0/N"
                } else {
                    ""
                }
            )
        )
    );
    println!(
        "{}",
        ui::kv(
            "matches ->",
            &format!(
                "{}  ({})",
                if managed_out {
                    let base = out_path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("match");
                    format!(
                        "{}/{}.<matched-case>[.02].md",
                        ui::dir_link(
                            out_path
                                .parent()
                                .unwrap_or_else(|| std::path::Path::new("."))
                        ),
                        base
                    )
                } else {
                    out_link(&out_path)
                },
                output_protection()
            )
        )
    );
    println!("{}", ui::kv("stop after", &format!("{} match(es)", count)));
    if with_passphrase {
        println!(
            "{}",
            ui::kv(
                "passphrase",
                "used - not stored; the seed alone will not reach the address"
            )
        );
    }
    if ui::links_on() {
        println!("{}", ui::note(ui::CLICK_HINT));
    }
    let out_parent = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    println!("{}", ui::bot(&format!("in {}", ui::dir_link(out_parent))));
    println!();

    // Prompt time, filesystem setup, and terminal rendering are not grinding.
    // Start the rate/ETA clock immediately before the progress and worker lanes.
    let start = Instant::now();
    let progress = {
        // A live line, not a log: rewritten in place every 2s from the first
        // seconds, so the operator sees rate and ETA immediately instead of
        // staring at nothing for 15s. Falls back to appended lines when
        // stdout is not a terminal (piped/logged runs).
        let (stop, counter, hits, display) = (
            Arc::clone(&stop),
            Arc::clone(&counter),
            Arc::clone(&hits),
            Arc::clone(&display),
        );
        let tty = stdout_tty;
        std::thread::spawn(move || {
            let mut tick = 0u64;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                tick += 1;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let every = if tty { 4 } else { 30 };
                if tick % every != 0 {
                    continue;
                }
                let n = counter.load(Ordering::Relaxed);
                let secs = start.elapsed().as_secs_f64();
                let rate = if secs > 0.0 { n as f64 / secs } else { 0.0 };
                let found = hits.load(Ordering::Relaxed).min(count as u64);
                let line = if count > 1 {
                    let remaining = (count as u64).saturating_sub(found);
                    let mean_remaining = if rate > 0.0 {
                        remaining as f64 / prob / rate
                    } else {
                        f64::INFINITY
                    };
                    format!(
                        "  {:>14} tried | found {}/{} | {:>8.0}/sec | {} | mean remaining {}",
                        n,
                        found,
                        count,
                        rate,
                        fmt_dur(secs),
                        fmt_dur(mean_remaining)
                    )
                } else {
                    let median_n = trials_for(0.5, prob);
                    let p90_n = trials_for(0.9, prob);
                    let done = (n as f64 / median_n * 50.0).min(99.0);
                    let left = if rate > 0.0 {
                        median_n / rate - secs
                    } else {
                        f64::INFINITY
                    };
                    let left90 = if rate > 0.0 {
                        p90_n / rate - secs
                    } else {
                        f64::INFINITY
                    };
                    format!(
                        "  {:>14} tried | {:>8.0}/sec | {} | 50% in {} | 90% in {} | ~{:.0}% of the way to median",
                        n,
                        rate,
                        fmt_dur(secs),
                        if left > 0.0 { fmt_dur(left) } else { "overdue".into() },
                        if left90 > 0.0 { fmt_dur(left90) } else { "overdue".into() },
                        done
                    )
                };
                let _display = display.lock().unwrap_or_else(|e| e.into_inner());
                if tty {
                    print!("\r\x1b[2K{}{}{}", ui::gry(), line, ui::r());
                } else {
                    println!("{}", line);
                }
                let _ = std::io::stdout().flush();
            }
            if tty {
                print!("\r\x1b[2K");
                let _ = std::io::stdout().flush();
            }
        })
    };

    let worker_spawn_error = std::thread::scope(|s| {
        for _ in 0..threads {
            let (m, stop, counter, reserved, hits, write_failed, display, match_header) = (
                Arc::clone(&m),
                Arc::clone(&stop),
                Arc::clone(&counter),
                Arc::clone(&reserved),
                Arc::clone(&hits),
                Arc::clone(&write_failed),
                Arc::clone(&display),
                Arc::clone(&match_header),
            );
            let sink = Arc::clone(&sink);
            let pass = Arc::clone(&passphrase);
            let lane_stop = Arc::clone(&stop);
            if let Err(e) = std::thread::Builder::new().spawn_scoped(s, move || {
                let on_hit = |h: Hit| {
                    let slot = match reserved.fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |n| (n < count as u64).then_some(n + 1),
                    ) {
                        Ok(previous) => previous + 1,
                        Err(_) => return,
                    };
                    if slot >= count as u64 {
                        stop.store(true, Ordering::SeqCst);
                    }
                    let persisted_out = match write_grind_hit(
                        &sink,
                        &h,
                        style,
                        &match_header,
                        &m,
                    ) {
                        Ok(path) => path,
                        Err(e) => {
                        // Never fall back to the terminal. The descriptor was secured
                        // before grinding; a later storage failure stops the run and
                        // withholds this candidate rather than leaking its seed.
                        eprintln!("WRITE FAILED ({}) -- seed NOT printed; grind stopped.", e);
                        eprintln!("Fix storage and re-run; this candidate may be incomplete on disk.");
                        write_failed.store(true, Ordering::SeqCst);
                        stop.store(true, Ordering::SeqCst);
                        return;
                        }
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _display = display.lock().unwrap_or_else(|e| e.into_inner());
                    if stdout_tty { print!("\r\x1b[2K"); }
                    println!("{}", ui::top("MATCH", &fmt_dur(start.elapsed().as_secs_f64())));
                    println!("{}", ui::kv_accent("address", &h.address));
                    println!("{}", ui::kv("path", &path_for(h.chain, style, h.index)));
                    if show_seed {
                        for row in seed_display_rows(&h.mnemonic) {
                            println!("{row}");
                        }
                    } else {
                        println!("{}", ui::kv("seed", &format!("-> {}   (--show-seed to print here)", out_link(&persisted_out))));
                    }
                    match h.chain {
                        Chain::Sol => {
                            println!("{}", ui::kv("keys", &format!("-> {}   base58 + JSON array (show --keys)", out_link(&persisted_out))));
                            println!("{}", ui::mid(""));
                            println!("{}", ui::note("Key:      Phantom/Solflare: choose Import Private Key where your"));
                            println!("{}", ui::note("          wallet version exposes it, then paste the base58."));
                            println!("{}", ui::note("          The JSON keypair is for solana-keygen."));
                            println!("{}", ui::note("          -> this exact address, standalone, no clicks"));
                        }
                        Chain::Evm => {
                            println!("{}", ui::kv("key", &format!("-> {}   hex private key (show --keys)", out_link(&persisted_out))));
                            println!("{}", ui::mid(""));
                            println!("{}", ui::note("Key:      MetaMask/Rabby: choose Import account ->"));
                            println!("{}", ui::note("          Private key -> paste the 0x hex: this address, every chain"));
                        }
                    }
                    for l in import_hint(h.chain, style, h.index) { println!("{}", ui::note(&l)); }
                    println!(
                        "{}",
                        ui::note("other accounts on this seed are not guaranteed vanity")
                    );
                    if h.passphrase { println!("{}", ui::warn_line("passphrase used - the seed alone will NOT reach this; the keys will")); }
                    if ui::links_on() { println!("{}", ui::note(ui::CLICK_HINT)); }
                    println!("{}", ui::bot("import and verify the address BEFORE funding"));
                    println!();
                };
                match chain {
                    Chain::Sol => grind_loop(&m, style, indices, entropy_len, pass.as_str(), &stop, &counter, &on_hit),
                    Chain::Evm => grind_loop_evm(&m, indices, entropy_len, pass.as_str(), &stop, &counter, &on_hit),
                }
            }) {
                lane_stop.store(true, Ordering::SeqCst);
                return Err(e);
            }
        }
        Ok::<(), std::io::Error>(())
    });
    stop.store(true, Ordering::SeqCst);
    let _ = progress.join();

    let n = hits.load(Ordering::Relaxed);
    let held_sink = match Arc::try_unwrap(sink) {
        Ok(mutex) => match mutex.into_inner() {
            Ok(sink) => Some(sink),
            Err(_) => {
                eprintln!("grind failed because the match-file lock was poisoned");
                None
            }
        },
        Err(_) => {
            eprintln!("grind failed because a worker retained the output descriptor");
            None
        }
    };
    let mut custody_failed = held_sink.is_none();
    #[cfg(unix)]
    if let Some(ref sink) = held_sink {
        let validation = match sink {
            GrindSink::Aggregate { path, file } => validate_grind_output_path(file, path),
            GrindSink::Managed(writer) => writer.validate_all(),
        };
        if let Err(e) = validation {
            custody_failed = true;
            eprintln!("grind failed because output custody changed: {}", e);
        }
    }
    let mut marker_failed = false;
    if let Some(lock) = recovery_lock.as_mut() {
        if let Err(e) = lock.release() {
            marker_failed = true;
            eprintln!("cannot release recovery grind marker: {}", e);
        }
    }
    if let Err(e) = requested_lock.release() {
        marker_failed = true;
        eprintln!("cannot release requested-output grind marker: {}", e);
    }
    if stdout_tty {
        print!("\r\x1b[2K");
    }
    println!(
        " {}stopped · {} match(es) · {} candidates · {}{}",
        ui::gry(),
        n,
        group(counter.load(Ordering::Relaxed) as f64),
        fmt_dur(start.elapsed().as_secs_f64()),
        ui::r()
    );
    if n > 0 && !custody_failed && !marker_failed && worker_spawn_error.is_ok() {
        let (show_target, reveal_hint) = if managed_out {
            (
                String::new(),
                "lists every file; use its printed command to reveal",
            )
        } else {
            (
                format!(
                    "-- {}",
                    shell_quote_posix(
                        out_path
                            .to_str()
                            .expect("validated operator path remains UTF-8")
                    )
                ),
                "put --seeds / --keys before the -- separator",
            )
        };
        println!(
            " {}keyrx show{}{}   {}{}",
            ui::gry(),
            if show_target.is_empty() { "" } else { " " },
            show_target,
            reveal_hint,
            ui::r()
        );
    }
    println!();
    let failed_write = write_failed.load(Ordering::SeqCst);
    if failed_write {
        eprintln!("grind failed because a complete match record could not be persisted");
    }
    if marker_failed {
        eprintln!("grind failed because its coordination marker was not durably released");
    }
    if custody_failed {
        eprintln!("grind failed because output custody was lost; no success path is reported");
    }
    if let Err(ref e) = worker_spawn_error {
        eprintln!("grind failed because a worker could not start: {}", e);
    }
    grind_exit_status(
        failed_write || custody_failed || marker_failed || worker_spawn_error.is_err(),
        interrupted.load(Ordering::SeqCst),
        n,
        count,
    )
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn pargs(sw: &[&str], ew: &[&str], chain: Chain) -> PatternArgs {
        PatternArgs {
            ends_with: ew.iter().map(|s| s.to_string()).collect(),
            starts_with: sw.iter().map(|s| s.to_string()).collect(),
            ignore_case: false,
            path: PathStyle::Phantom,
            chain,
            checksum: false,
        }
    }

    fn test_match_header(chain: Chain) -> MatchFileHeader {
        let suffix = match chain {
            Chain::Sol => "j",
            Chain::Evm => "4",
        };
        build_match_file_header(&pargs(&[], &[suffix], chain), 4, 12, false).unwrap()
    }

    fn public_evm_hit() -> Hit {
        public_evm_hit_at(0)
    }

    fn public_evm_hit_at(index: u32) -> Hit {
        let mnemonic = bip39::Mnemonic::parse_normalized(evm::ABANDON).unwrap();
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let branch = evm::Branch::from_seed(seed.as_ref()).unwrap();
        let mut key = branch.key_at(index).unwrap();
        let address = evm::eip55(&evm::address_of(&key));
        let privkey = evm::privkey_hex(&key);
        key.zeroize();
        Hit {
            chain: Chain::Evm,
            index,
            address,
            mnemonic: Zeroizing::new(evm::ABANDON.to_string()),
            passphrase: false,
            privkey,
            keypair_json: Zeroizing::new(String::new()),
        }
    }

    fn public_sol_hit() -> Hit {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap();
        let bip39_seed = Zeroizing::new(mnemonic.to_seed(""));
        let secret = sol_secret_from_seed(bip39_seed.as_ref(), PathStyle::Phantom, 0);
        let address =
            bs58::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes()).into_string();
        Hit {
            chain: Chain::Sol,
            index: 0,
            address,
            mnemonic: Zeroizing::new(mnemonic.to_string()),
            passphrase: false,
            privkey: keypair_b58(&secret),
            keypair_json: keypair_json(&secret),
        }
    }

    #[test]
    fn realized_filename_edges_preserve_the_address_case() {
        let mut pattern = pargs(&[], &["Ab"], Chain::Sol);
        pattern.ignore_case = true;
        let matcher = Matcher::new(&pattern).unwrap();
        assert_eq!(matcher.realized_filename_edge("123456789aB").unwrap(), "aB");

        let mut both = pargs(&["c0"], &["De"], Chain::Evm);
        both.checksum = false;
        let matcher = Matcher::new(&both).unwrap();
        assert_eq!(
            matcher
                .realized_filename_edge("0xC0000000000000000000000000000000000000dE")
                .unwrap(),
            "C0...dE"
        );
    }

    #[test]
    fn managed_match_names_number_only_exact_case_collisions() {
        let lane = std::path::Path::new("/private/coined.ic.txt");
        assert_eq!(
            managed_match_path(lane, "coiNED", 1).unwrap(),
            std::path::Path::new("/private/coined.ic.coiNED.md")
        );
        assert_eq!(
            managed_match_path(lane, "coiNED", 2).unwrap(),
            std::path::Path::new("/private/coined.ic.coiNED.02.md")
        );
        assert_eq!(
            managed_match_path(lane, "COIned", 3).unwrap(),
            std::path::Path::new("/private/coined.ic.COIned.03.md")
        );
    }

    #[test]
    fn strict_markdown_round_trips_solana_and_evm_and_refuses_heading_drift() {
        let mut format_digests = Vec::new();
        for hit in [public_sol_hit(), public_evm_hit()] {
            let suffix = hit.address.chars().last().unwrap().to_string();
            let words = hit.mnemonic.split_whitespace().count();
            let header =
                build_match_file_header(&pargs(&[], &[&suffix], hit.chain), 1, words, false)
                    .unwrap();
            let markdown = format_markdown_match_file(&hit, PathStyle::Phantom, &header).unwrap();
            format_digests.push(format!("{:x}", Sha256::digest(markdown.as_bytes())));
            assert!(markdown.contains("## ADDRESS\n\n"));
            assert!(markdown.contains(MARKDOWN_PRIVATE_WARNING));
            assert_eq!(
                parse_match_file_bytes(markdown.as_bytes())
                    .unwrap()
                    .records
                    .len(),
                1
            );
            let drifted = markdown.replacen("## PATH", "## DERIVATION PATH", 1);
            assert!(parse_match_file_bytes(drifted.as_bytes()).is_err());
        }
        // keyrx-match-md-v1 is an on-disk compatibility promise. A copy or
        // layout change requires a new format marker and parser branch that
        // retains these exact Solana and EVM documents.
        assert_eq!(
            format_digests,
            [
                "e5a6ca4a3917ac9a1c94cf165abbb5485a6946f5d206f27fc2250dfcc634c3fd",
                "0bcadefb19ba51eb624c3eec2a7b20b866d83c8558204d5a6b8e8778fe9a9771",
            ]
        );
    }

    fn private_test_dir(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "keyrx-match-header-{}-{}-{nonce}",
            std::process::id(),
            label
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn creation_recipe_preserves_search_semantics_and_omits_execution_controls() {
        let mut sol = pargs(&["cMaiL"], &["coined", "KEYRX"], Chain::Sol);
        sol.ignore_case = true;
        sol.path = PathStyle::Legacy;
        let recipe = grind_creation_recipe(&sol, 128, 24, true).unwrap();
        assert_eq!(
            recipe,
            "keyrx grind --chain sol --ends-with coined --ends-with KEYRX --starts-with cMaiL --ignore-case --path legacy --indices 128 --words 24 --passphrase"
        );
        for omitted in ["--count", "--out", "--threads", "--show-seed"] {
            assert!(!recipe.split_ascii_whitespace().any(|word| word == omitted));
        }
        let header = format_match_file_header(Chain::Sol, &recipe).unwrap();
        let parsed = parse_match_file_bytes(header.bytes.as_bytes()).unwrap();
        assert_eq!(parsed.header_chain, Some(Chain::Sol));

        let mut evm = pargs(&["0xC0ffee"], &["DeAd"], Chain::Evm);
        evm.checksum = true;
        let recipe = grind_creation_recipe(&evm, 64, 12, false).unwrap();
        assert_eq!(
            recipe,
            "keyrx grind --chain evm --ends-with DeAd --starts-with 0xC0ffee --checksum --indices 64 --words 12"
        );
        assert!(!recipe.contains("--path"));
        let header = format_match_file_header(Chain::Evm, &recipe).unwrap();
        let parsed = parse_match_file_bytes(header.bytes.as_bytes()).unwrap();
        assert_eq!(parsed.header_chain, Some(Chain::Evm));

        let mut coined = pargs(&[], &["coined"], Chain::Sol);
        coined.ignore_case = true;
        let recipe = grind_creation_recipe(&coined, 128, 12, false).unwrap();
        assert_eq!(
            recipe,
            "keyrx grind --chain sol --ends-with coined --ignore-case --path phantom --indices 128 --words 12"
        );
        let header = format_match_file_header(Chain::Sol, &recipe).unwrap();
        assert!(parse_match_file_bytes(header.bytes.as_bytes()).is_ok());

        let mut unsafe_pattern = pargs(&[], &["bad value"], Chain::Sol);
        assert!(grind_creation_recipe(&unsafe_pattern, 1, 12, false).is_err());
        unsafe_pattern.ends_with = vec!["bad\nvalue".into()];
        assert!(grind_creation_recipe(&unsafe_pattern, 1, 12, false).is_err());
    }

    #[test]
    fn match_headers_are_canonical_fixed_width_and_strictly_parsed() {
        for chain in [Chain::Sol, Chain::Evm] {
            let header = test_match_header(chain);
            let parsed = parse_match_file_bytes(header.bytes.as_bytes()).unwrap();
            assert_eq!(parsed.header_chain, Some(chain));
            assert!(parsed.records.is_empty());
            for line in header.bytes.lines().filter(|line| {
                line.starts_with('╔') || line.starts_with('║') || line.starts_with('╚')
            }) {
                assert_eq!(line.chars().count(), ui::W, "ragged header row: {line:?}");
            }
            assert_eq!(header.bytes.matches(MATCH_FILE_HEADER_VERSION).count(), 1);
            assert!(header.bytes.contains(
                "creation recipe (count, output, display, and worker settings omitted):"
            ));
        }

        let sol = test_match_header(Chain::Sol);
        for required in [
            "SOLANA PRIVATE MATCH FILE",
            "Phantom/Solflare",
            "base58 privkey",
            "JSON for solana-keygen-compatible tools",
            "m/44'/501'/N'/0'",
            "N=89 is account #90",
            "printed path is authoritative",
            "not guaranteed vanity",
            "Verify the imported address before funding",
        ] {
            assert!(
                sol.bytes.contains(required),
                "Solana header lost {required:?}"
            );
        }
        for forbidden in ["MetaMask", "Rabby", "m/44'/60'/0'/0/N"] {
            assert!(
                !sol.bytes.contains(forbidden),
                "Solana header contains EVM guidance {forbidden:?}"
            );
        }

        let evm = test_match_header(Chain::Evm);
        for required in [
            "EVM PRIVATE MATCH FILE",
            "MetaMask/Rabby",
            "0x hex privkey",
            "standalone across EVM networks",
            "m/44'/60'/0'/0/N",
            "not guaranteed vanity",
            "Verify the imported address before funding",
        ] {
            assert!(evm.bytes.contains(required), "EVM header lost {required:?}");
        }
        for forbidden in [
            "Phantom",
            "Solflare",
            "solana-keygen",
            "base58",
            "JSON",
            "m/44'/501'",
        ] {
            assert!(
                !evm.bytes.contains(forbidden),
                "EVM header contains Solana guidance {forbidden:?}"
            );
        }

        // keyrx-match-v1 is an on-disk compatibility promise. A copy change
        // requires a new version and an explicit parser branch that retains v1.
        assert_eq!(
            format!("{:x}", Sha256::digest(sol.bytes.as_bytes())),
            "ede75c735f0fb5debab374edb600326d4bd1081b78ecca69a9cbedcf0380b9b0"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(evm.bytes.as_bytes())),
            "bacb372e4f13cadd3ac5775d3e4e0d9d493ac7db164f198adb5223680461e032"
        );

        let header = test_match_header(Chain::Sol);
        for mutation in [
            header
                .bytes
                .replace(MATCH_FILE_HEADER_VERSION, "keyrx-match-v2"),
            header.bytes.replace("--indices 4", "--indices 0"),
            header.bytes.replace("--indices 4", "--indices 4 --count 2"),
            format!("prose that is not a header\n\n{}", header.bytes),
            format!("{}{}", header.bytes, header.bytes),
        ] {
            assert!(
                parse_match_file_bytes(mutation.as_bytes()).is_err(),
                "accepted malformed header: {mutation:?}"
            );
        }
        let mut truncated = header.bytes.clone();
        truncated.pop();
        assert!(parse_match_file_bytes(truncated.as_bytes()).is_err());
        let oversized = format!("╔{}\n\n", "a".repeat(MAX_MATCH_FILE_HEADER_BYTES));
        let error = parse_match_file_bytes(oversized.as_bytes())
            .err()
            .expect("an oversized header must be refused");
        assert!(error.to_string().contains("header exceeds"), "{error}");
        assert!(
            format_match_file_header(Chain::Sol, "keyrx grind --chain sol\n--ends-with a").is_err()
        );
    }

    #[test]
    fn a_header_recipe_is_bound_to_every_record_dimension() {
        let evm_hit = public_evm_hit();
        let (evm_record, _) = format_hit_record(&evm_hit, PathStyle::Phantom).unwrap();
        let evm_pattern = pargs(&[], &["94"], Chain::Evm);
        let evm_header = build_match_file_header(&evm_pattern, 4, 12, false).unwrap();
        let green = format!(
            "{}{}{}",
            evm_header.bytes,
            evm_record.as_str(),
            evm_record.as_str()
        );
        assert_eq!(
            parse_match_file_bytes(green.as_bytes())
                .unwrap()
                .records
                .len(),
            2
        );

        let wrong_pattern =
            build_match_file_header(&pargs(&[], &["00"], Chain::Evm), 4, 12, false).unwrap();
        assert!(parse_match_file_bytes(
            format!("{}{}", wrong_pattern.bytes, evm_record.as_str()).as_bytes()
        )
        .is_err());

        let mut wrong_checksum_pattern = pargs(&[], &["A94"], Chain::Evm);
        wrong_checksum_pattern.checksum = true;
        let wrong_checksum =
            build_match_file_header(&wrong_checksum_pattern, 4, 12, false).unwrap();
        assert!(parse_match_file_bytes(
            format!("{}{}", wrong_checksum.bytes, evm_record.as_str()).as_bytes()
        )
        .is_err());

        for header in [
            build_match_file_header(&evm_pattern, 4, 24, false).unwrap(),
            build_match_file_header(&evm_pattern, 4, 12, true).unwrap(),
        ] {
            assert!(parse_match_file_bytes(
                format!("{}{}", header.bytes, evm_record.as_str()).as_bytes()
            )
            .is_err());
        }

        let evm_index_one = public_evm_hit_at(1);
        let suffix = &evm_index_one.address[evm_index_one.address.len() - 1..];
        let index_header =
            build_match_file_header(&pargs(&[], &[suffix], Chain::Evm), 1, 12, false).unwrap();
        let (index_record, _) = format_hit_record(&evm_index_one, PathStyle::Phantom).unwrap();
        assert!(parse_match_file_bytes(
            format!("{}{}", index_header.bytes, index_record.as_str()).as_bytes()
        )
        .is_err());

        let sol_hit = public_sol_hit();
        let suffix = &sol_hit.address[sol_hit.address.len() - 1..];
        let mut wrong_path_pattern = pargs(&[], &[suffix], Chain::Sol);
        wrong_path_pattern.path = PathStyle::Legacy;
        let wrong_path = build_match_file_header(&wrong_path_pattern, 4, 12, false).unwrap();
        let (sol_record, _) = format_hit_record(&sol_hit, PathStyle::Phantom).unwrap();
        assert!(parse_match_file_bytes(
            format!("{}{}", wrong_path.bytes, sol_record.as_str()).as_bytes()
        )
        .is_err());
    }

    #[test]
    fn first_record_writes_one_header_while_legacy_append_stays_headerless() {
        let dir = private_test_dir("once");
        let out = dir.join("new.txt");
        let header = test_match_header(Chain::Evm);
        let hit = public_evm_hit();
        let file = Mutex::new(open_match_file(&out, &header).unwrap());
        write_hit(&file, &hit, PathStyle::Phantom, &header).unwrap();
        write_hit(&file, &hit, PathStyle::Phantom, &header).unwrap();
        drop(file);
        let file = Mutex::new(open_match_file(&out, &header).unwrap());
        write_hit(&file, &hit, PathStyle::Phantom, &header).unwrap();
        drop(file);

        let bytes = std::fs::read(&out).unwrap();
        let parsed = parse_match_file_bytes(&bytes).unwrap();
        assert_eq!(parsed.header_chain, Some(Chain::Evm));
        assert_eq!(parsed.records.len(), 3);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(text.matches(MATCH_FILE_HEADER_VERSION).count(), 1);
        assert_eq!(text.matches(MATCH_FILE_RECIPE_LABEL).count(), 1);
        let sol_header = test_match_header(Chain::Sol);
        assert!(open_match_file(&out, &sol_header)
            .unwrap_err()
            .to_string()
            .contains("other chain"));
        let other_evm_header =
            build_match_file_header(&pargs(&[], &["b"], Chain::Evm), 4, 12, false).unwrap();
        assert!(open_match_file(&out, &other_evm_header)
            .unwrap_err()
            .to_string()
            .contains("another creation recipe"));

        let legacy = dir.join("legacy.txt");
        let (record, _) = format_hit_record(&hit, PathStyle::Phantom).unwrap();
        let mut legacy_file = private_create_new(&legacy).unwrap();
        legacy_file.write_all(record.as_bytes()).unwrap();
        legacy_file.sync_all().unwrap();
        drop(legacy_file);
        let legacy_file = Mutex::new(open_match_file(&legacy, &header).unwrap());
        write_hit(&legacy_file, &hit, PathStyle::Phantom, &header).unwrap();
        drop(legacy_file);
        let bytes = std::fs::read(&legacy).unwrap();
        assert!(!bytes
            .windows(MATCH_FILE_HEADER_VERSION.len())
            .any(|window| window == MATCH_FILE_HEADER_VERSION.as_bytes()));
        assert_eq!(parse_match_bytes(&bytes).unwrap().len(), 2);
        assert!(open_match_file(&legacy, &sol_header)
            .unwrap_err()
            .to_string()
            .contains("other chain"));

        let legacy_sol = dir.join("legacy-sol.txt");
        let (record, _) = format_hit_record(&public_sol_hit(), PathStyle::Phantom).unwrap();
        let mut legacy_sol_file = private_create_new(&legacy_sol).unwrap();
        legacy_sol_file.write_all(record.as_bytes()).unwrap();
        legacy_sol_file.sync_all().unwrap();
        drop(legacy_sol_file);
        assert!(open_match_file(&legacy_sol, &header)
            .unwrap_err()
            .to_string()
            .contains("other chain"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_header_rejects_records_from_the_other_chain_and_counts_toward_the_bound() {
        let sol_header = test_match_header(Chain::Sol);
        let (evm_record, _) = format_hit_record(&public_evm_hit(), PathStyle::Phantom).unwrap();
        let mut mixed = sol_header.bytes.clone();
        mixed.push_str(evm_record.as_str());
        assert!(parse_match_file_bytes(mixed.as_bytes()).is_err());

        assert!(checked_match_append_len(0, MAX_PRIVATE_MATCH_FILE_BYTES, 1).is_err());
        assert_eq!(
            checked_match_append_len(0, sol_header.bytes.len() as u64, 1).unwrap(),
            sol_header.bytes.len() as u64 + 1
        );
    }

    /// 0.4.11 pooled every pattern into one OR, so `--starts-with cMaiL
    /// --ends-with gg` stopped on the first address ending gg. The grammar:
    /// OR within a kind, AND across kinds.
    #[test]
    fn both_kinds_multiply_the_odds() {
        let both = Matcher::new(&pargs(&["cM"], &["gg"], Chain::Sol)).unwrap();
        assert!(
            (both.probability() * 58f64.powi(4) - 1.0).abs() < 1e-9,
            "prefix AND suffix is 1 in 58^4, not the pool's 2 in 58^2"
        );
        let pool = Matcher::new(&pargs(&[], &["cM", "gg"], Chain::Sol)).unwrap();
        assert!(
            (pool.probability() * 58f64.powi(2) - 2.0).abs() < 1e-9,
            "two suffixes stay alternatives: 2 in 58^2"
        );
    }

    #[test]
    fn evm_conjunction_needs_both_ends() {
        let m = Matcher::new(&pargs(&["aa"], &["bb"], Chain::Evm)).unwrap();
        let addr = [0u8; 20];
        let mut hit = [b'a'; 40];
        hit[38] = b'b';
        hit[39] = b'b';
        let mut suffix_only = [b'c'; 40];
        suffix_only[38] = b'b';
        suffix_only[39] = b'b';
        let mut prefix_only = [b'a'; 40];
        prefix_only[38] = b'c';
        prefix_only[39] = b'c';
        assert!(m.evm_hit(&hit, &addr), "both ends landing must hit");
        assert!(
            !m.evm_hit(&suffix_only, &addr),
            "a suffix alone must not hit when a prefix is asked for"
        );
        assert!(
            !m.evm_hit(&prefix_only, &addr),
            "a prefix alone must not hit when a suffix is asked for"
        );
    }

    #[test]
    fn the_match_file_names_the_conjunction() {
        let out = default_out(&pargs(&["cMaiL"], &["gg"], Chain::Sol));
        assert!(out.ends_with("cMaiL_...gg.txt"), "got {}", out.display());
        let single = default_out(&pargs(&[], &["gg"], Chain::Sol));
        assert!(single.ends_with("gg.txt"), "got {}", single.display());
    }

    /// When this is a repository checkout, the site's masthead version must
    /// agree. Published crates intentionally omit `site/`; the release preflight
    /// owns the required-artifact check and refuses a missing site/index.html.
    #[test]
    fn repository_checkout_site_shows_this_version() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        if !root.join("site").exists() {
            return;
        }
        let path = root.join("site/index.html");
        let site = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("repository site/index.html is required: {e}"));
        let want = format!("var VERSION='{}';", env!("CARGO_PKG_VERSION"));
        assert_eq!(
            site.matches(&want).count(),
            1,
            "site/index.html must carry exactly one `{}`",
            want
        );
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
            let fast =
                bs58::encode(SigningKey::from_bytes(&kf).verifying_key().to_bytes()).into_string();
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
                if full.len() < n {
                    continue;
                }
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
        for pk in [
            [0u8; 32],
            [0xffu8; 32],
            {
                let mut p = [0u8; 32];
                p[31] = 1;
                p
            },
            {
                let mut p = [0xffu8; 32];
                p[0] = 0;
                p[1] = 0;
                p
            },
        ] {
            let full = bs58::encode(pk).into_string();
            for n in 1..=8usize {
                if full.len() < n {
                    continue;
                }
                b58_suffix(&pk, n, &mut buf);
                assert_eq!(
                    &buf[..n],
                    &full.as_bytes()[full.len() - n..],
                    "pk={:?} n={}",
                    &pk[..4],
                    n
                );
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
    fn probability_plain_5_char_suffix_is_an_explicit_model() {
        let m = Matcher::new(&pat(&["abcde"], &[], false)).unwrap();
        let want = 1.0 / 58f64.powi(5);
        assert!((m.probability() - want).abs() < want * 1e-12);
        assert!(m.probability_is_approximate());
    }

    #[test]
    fn benchmark_workload_is_exact_only_for_the_shape_that_ran() {
        let sol_workload = BenchWorkload::SolSuffix5CaseSensitive;
        let sol_exact = Matcher::new(&pat(&["abcde"], &[], false)).unwrap();
        let sol_short = Matcher::new(&pat(&["abcd"], &[], false)).unwrap();
        let sol_casefold = Matcher::new(&pat(&["abcde"], &[], true)).unwrap();
        let sol_many = Matcher::new(&pat(&["abcde", "fghij"], &[], false)).unwrap();
        assert!(sol_workload.is_exact_for(&sol_exact));
        assert!(!sol_workload.is_exact_for(&sol_short));
        assert!(!sol_workload.is_exact_for(&sol_casefold));
        assert!(!sol_workload.is_exact_for(&sol_many));

        let evm_workload = BenchWorkload::EvmSuffix16AnyCase;
        let evm_exact = Matcher::new(&pargs(&[], &["cafebabedeadbeef"], Chain::Evm)).unwrap();
        let evm_short = Matcher::new(&pargs(&[], &["cafebabedeadbee"], Chain::Evm)).unwrap();
        let mut checksum_args = pargs(&[], &["cafebabedeadbeef"], Chain::Evm);
        checksum_args.checksum = true;
        let evm_checksum = Matcher::new(&checksum_args).unwrap();
        assert!(evm_workload.is_exact_for(&evm_exact));
        assert!(!evm_workload.is_exact_for(&evm_short));
        assert!(!evm_workload.is_exact_for(&evm_checksum));
    }

    #[test]
    fn duplicate_and_subsumed_or_patterns_are_canonicalized() {
        let duplicate = Matcher::new(&pat(&["ab", "ab"], &[], false)).unwrap();
        assert_eq!(duplicate.suffixes, vec![b"ab".to_vec()]);
        assert!((duplicate.probability() - 1.0 / 58f64.powi(2)).abs() < 1e-15);

        let subsumed = Matcher::new(&pat(&["ab", "cab"], &[], false)).unwrap();
        assert_eq!(subsumed.suffixes, vec![b"ab".to_vec()]);
        let prefix = Matcher::new(&pat(&[], &["Key", "KeyRX"], false)).unwrap();
        assert_eq!(prefix.prefixes, vec![b"Key".to_vec()]);
    }

    #[test]
    fn long_pattern_quantiles_use_stable_logarithms() {
        let probability = 1.0 / 58f64.powi(10);
        let median = trials_for(0.5, probability);
        assert!(median.is_finite() && median > 0.0);
        assert!((median * probability - std::f64::consts::LN_2).abs() < 1e-6);
        assert_eq!(trials_for(0.5, 1.0), 1.0);
        assert_eq!(trials_for(0.9, 1.0), 1.0);
    }

    #[test]
    fn updater_root_selection_requires_absolute_paths_and_preserves_installed_lane() {
        assert!(absolute_env_path("CARGO_INSTALL_ROOT", "".into()).is_err());
        assert!(absolute_env_path("CARGO_INSTALL_ROOT", "relative/root".into()).is_err());
        assert_eq!(
            running_install_root(std::path::Path::new("/opt/keyrx/bin/keyrx")),
            Some(std::path::PathBuf::from("/opt/keyrx"))
        );
        assert_eq!(
            running_install_root(std::path::Path::new("/work/target/debug/keyrx")),
            None
        );
        assert_eq!(running_install_root(std::path::Path::new("keyrx")), None);
    }

    #[cfg(unix)]
    #[test]
    fn updater_holds_one_executable_and_rejects_symlink_or_replacement() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "keyrx-update-custody-{}-{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir(&dir).unwrap();
        let binary = dir.join("keyrx");
        std::fs::write(&binary, b"not empty").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            open_installed_executable(&binary).is_err(),
            "a group/world-writable executable can change through the held inode"
        );
        for mode in [0o001, 0o010, 0o600] {
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                open_installed_executable(&binary).is_err(),
                "mode {mode:03o} is not executable by its owner"
            );
        }
        for mode in [0o700, 0o755] {
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                open_installed_executable(&binary).is_ok(),
                "normal owner-executable mode {mode:03o} was refused"
            );
        }
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = open_installed_executable(&binary).unwrap();
        assert!(held_executable_path_matches(&held, &binary).unwrap());

        let link = dir.join("linked-keyrx");
        symlink(&binary, &link).unwrap();
        assert!(open_installed_executable(&link).is_err());

        let old = dir.join("old-keyrx");
        std::fs::rename(&binary, &old).unwrap();
        std::fs::write(&binary, b"replacement").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!held_executable_path_matches(&held, &binary).unwrap());
        drop(held);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn benchmark_guard_excludes_a_new_ceremony_for_the_whole_read_decision() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("keyrx-rate-guard-{}-{}", std::process::id(), nonce));
        std::fs::create_dir(&dir).unwrap();
        let cache = dir.join("bench.txt");
        std::fs::write(&cache, b"placeholder").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o600)).unwrap();

        let reader = RateCacheCeremonyLock::open_guard(&cache, false).unwrap();
        let conflict = match RateCacheCeremonyLock::acquire(&cache) {
            Ok(_) => panic!("an exclusive ceremony acquired while the shared guard was held"),
            Err(error) => error,
        };
        assert_eq!(conflict.kind(), std::io::ErrorKind::WouldBlock);
        drop(reader);
        let mut ceremony = RateCacheCeremonyLock::acquire(&cache).unwrap();
        ceremony.release_success().unwrap();
        drop(ceremony);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn impossible_patterns_and_work_sizes_are_refused() {
        let long = "a".repeat(45);
        assert!(Matcher::new(&pat(&[], &[&long], false)).is_err());
        let outside = "z".repeat(44);
        assert!(Matcher::new(&pat(&[], &[&outside], false)).is_err());
        let outside_prefix = "z".repeat(43);
        assert!(
            Matcher::new(&pat(&["z"], &[&outside_prefix], false)).is_err(),
            "canonical text is not enough when every completion is an invalid public key"
        );
        assert!(Matcher::new(&pat(&["z"], &[&outside_prefix], true)).is_err());
        let impossible_partial = "1".repeat(31);
        let impossible_suffix = "z".repeat(12);
        assert!(
            Matcher::new(&pat(&[&impossible_suffix], &[&impossible_partial], false)).is_err(),
            "a free text digit is not proof that the base58 value can occupy exactly 32 bytes"
        );
        assert!(Matcher::new(&pat_evm(
            &["a".repeat(16).as_str()],
            &["b".repeat(25).as_str()],
            false
        ))
        .is_err());
        assert!(Matcher::new(&PatternArgs {
            path: PathStyle::Legacy,
            ..pat_evm(&["a"], &[], false)
        })
        .is_err());
        assert!(validate_work_args(0, 1, 1).is_err());
        assert!(validate_work_args(1, 0, 1).is_err());
        assert!(validate_work_args(1, 1, 0).is_err());
        assert_eq!(default_threads_for(513), 512);
        assert_eq!(default_threads_for(1024), 512);
        assert!(default_threads_for(1024) <= max_threads_for(1024));
    }

    #[test]
    fn sol_full_edges_are_refused_and_overlap_is_not_double_counted() {
        const ED25519_BASEPOINT: &str = "6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7ieH";
        let basepoint_error = Matcher::new(&pat(&[], &[ED25519_BASEPOINT], false))
            .err()
            .expect("a full point without a signing-key witness is refused");
        assert!(basepoint_error.contains("cannot be proven reachable"));
        assert!(Matcher::new(&pat(&[], &[XCHECK_PHANTOM], false)).is_err());
        assert!(
            Matcher::new(&pat(&[], &[&XCHECK_PHANTOM[..40]], false)).is_ok(),
            "a 40-character edge can extend to a 44-character address with four free characters"
        );
        assert!(
            Matcher::new(&pat(&[], &["a", XCHECK_PHANTOM], false)).is_err(),
            "a feasible alternative cannot hide an unprovable full alternative"
        );
        assert_eq!(
            edge_probability(XCHECK_PHANTOM.as_bytes(), false),
            sol_pair_probability(XCHECK_PHANTOM.as_bytes(), b"j", false),
            "a suffix already fixed by a full prefix is not a second event"
        );

        let impossible_prefix = "1".repeat(31);
        let impossible_suffix = "z".repeat(12);
        let feasible = Matcher::new(&pat(&[&impossible_suffix], &["A"], false)).unwrap();
        let alternatives = Matcher::new(&pat(
            &[&impossible_suffix],
            &["A", &impossible_prefix],
            false,
        ))
        .unwrap();
        assert_eq!(
            alternatives.probability(),
            feasible.probability(),
            "an impossible alternative contributes no probability"
        );
    }

    #[test]
    fn recovery_name_stays_in_the_showable_txt_namespace() {
        assert_eq!(
            recovery_output_path(std::path::Path::new("/private/matches.txt")),
            std::path::Path::new("/private/matches.recovered.txt")
        );
        assert_eq!(
            recovery_output_path(std::path::Path::new("/private/matches")),
            std::path::Path::new("/private/matches.recovered")
        );
    }

    #[test]
    fn probability_case_insensitive_gauge_is_32_over_58_pow_5() {
        // G,A,U,G,E each have two cases in base58 (none of them are o/i/L,
        // the letters that lost a case) -> 2^5 = 32 variants.
        let m = Matcher::new(&pat(&["GAUGE"], &[], true)).unwrap();
        let want = 32.0 / 58f64.powi(5);
        assert!(
            (m.probability() - want).abs() < want * 1e-12,
            "{}",
            m.probability()
        );
    }

    #[test]
    fn probability_case_insensitive_respects_single_case_letters() {
        // 'l' has no upper case in base58 (L exists, l does not) -> 1 variant;
        // 'o' likewise (O excluded). "lo" case-insensitive = 1*1 / 58^2... but
        // wait: 'l' is excluded and 'L' allowed; 'o' allowed and 'O' excluded.
        // So a pattern containing L matches only L; containing o matches only o.
        let m = Matcher::new(&pat(&["Lo"], &[], true)).unwrap();
        let want = 1.0 / 58f64.powi(2);
        assert!(
            (m.probability() - want).abs() < want * 1e-12,
            "{}",
            m.probability()
        );
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
        let bytes: Vec<u8> = j
            .trim_matches(&['[', ']'][..])
            .split(',')
            .map(|x| x.parse::<u8>().unwrap())
            .collect();
        assert_eq!(bytes.len(), 64);
        let b58 = bs58::decode(keypair_b58(&secret).as_str())
            .into_vec()
            .unwrap();
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
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[..32]);
        let re = bs58::encode(SigningKey::from_bytes(&s).verifying_key().to_bytes()).into_string();
        assert_eq!(re, addr, "secret half does not re-derive the address");
    }

    fn pat_evm(ends: &[&str], starts: &[&str], checksum: bool) -> PatternArgs {
        PatternArgs {
            chain: Chain::Evm,
            checksum,
            ..pat(ends, starts, false)
        }
    }

    #[test]
    fn evm_matcher_takes_hex_in_any_case_and_refuses_the_rest() {
        let m = Matcher::new(&pat_evm(&["DeAd"], &["0xC0ffee"], false)).unwrap();
        assert_eq!(
            m.suffixes,
            vec![b"dead".to_vec()],
            "stored lowercase: any case matches"
        );
        assert_eq!(
            m.prefixes,
            vec![b"c0ffee".to_vec()],
            "0x dropped, lowercase"
        );
        assert!(
            Matcher::new(&pat_evm(&["keyrx"], &[], false)).is_err(),
            "not hex"
        );
        assert!(
            Matcher::new(&pat_evm(&["0xdead"], &[], false)).is_err(),
            "0x on a suffix"
        );
        assert!(Matcher::new(&pat_evm(&[], &[], false)).is_err());
        assert!(
            Matcher::new(&PatternArgs {
                ignore_case: true,
                ..pat_evm(&["dead"], &[], true)
            })
            .is_err(),
            "checksum + ignore-case"
        );
        assert!(
            Matcher::new(&PatternArgs {
                checksum: true,
                ..pat(&["KEYRX"], &[], false)
            })
            .is_err(),
            "checksum on sol"
        );
        let c = Matcher::new(&pat_evm(&["DeAd"], &[], true)).unwrap();
        assert_eq!(
            c.suffixes,
            vec![b"DeAd".to_vec()],
            "checksum keeps the typed case"
        );
        let correct = PatternArgs {
            starts_with: vec!["0x52908400098527886E0F7030069857D2E4169EE7".into()],
            checksum: true,
            ..pat_evm(&[], &[], true)
        };
        let full = Matcher::new(&correct).expect("canonical full EIP-55 address");
        assert_eq!(full.probability(), 1.0 / 16f64.powi(40));
        let wrong = PatternArgs {
            starts_with: vec!["0x52908400098527886e0f7030069857d2e4169ee7".into()],
            ..correct
        };
        assert!(Matcher::new(&wrong).is_err());
        let mixed = Matcher::new(&PatternArgs {
            starts_with: vec![
                "0x52908400098527886E0F7030069857D2E4169EE7".into(),
                "0x52908400098527886e0f7030069857d2e4169ee7".into(),
            ],
            checksum: true,
            ..pat_evm(&[], &[], true)
        })
        .expect("one valid full-checksum alternative keeps the matcher feasible");
        assert_eq!(mixed.probability(), 1.0 / 16f64.powi(40));
        assert!(!mixed.probability_is_approximate());
    }

    #[test]
    fn evm_probability_is_sixteen_per_digit_and_two_per_letter_with_checksum() {
        let m = Matcher::new(&pat_evm(&["dead"], &[], false)).unwrap();
        let want = 1.0 / 16f64.powi(4);
        assert!((m.probability() - want).abs() < want * 1e-12);
        let c = Matcher::new(&pat_evm(&["dead"], &[], true)).unwrap();
        let want = 1.0 / 16f64.powi(4) / 2f64.powi(4); // d, e, a, d: four letters
        assert!((c.probability() - want).abs() < want * 1e-12);
        let digits = Matcher::new(&pat_evm(&["1234"], &[], true)).unwrap();
        assert!(
            (digits.probability() - 1.0 / 16f64.powi(4)).abs() < 1e-18,
            "digits have no case to match"
        );
        // a prefix AND a suffix multiply: two 2-hex ends are 1 in 65,536, not 2 in 256
        let both = Matcher::new(&pat_evm(&["ab"], &["cd"], false)).unwrap();
        assert!((both.probability() - 1.0 / (256.0 * 256.0)).abs() < 1e-18);

        let address = "52908400098527886e0f7030069857d2e4169ee7";
        let overlap = Matcher::new(&pat_evm(&[&address[24..]], &[address], false)).unwrap();
        assert!(
            (overlap.probability() - 1.0 / 16f64.powi(40)).abs() < 1e-60,
            "overlapping edges constrain forty unique digits, not fifty-six"
        );
        assert!(Matcher::new(&pat_evm(&["dead"], &[address], false)).is_err());
    }

    #[test]
    fn near_full_eip55_case_is_exhaustively_proven() {
        let address = "52908400098527886E0F7030069857D2E4169EE7";
        let valid_prefix = &address[..39];
        let valid = Matcher::new(&pat_evm(&[], &[valid_prefix], true)).unwrap();
        assert!(!valid.probability_is_approximate());

        let impossible = (0..39)
            .filter(|index| address.as_bytes()[*index].is_ascii_alphabetic())
            .find_map(|index| {
                let mut changed = address.as_bytes()[..39].to_vec();
                changed[index] = if changed[index].is_ascii_uppercase() {
                    changed[index].to_ascii_lowercase()
                } else {
                    changed[index].to_ascii_uppercase()
                };
                let changed = String::from_utf8(changed).unwrap();
                Matcher::new(&pat_evm(&[], &[&changed], true))
                    .is_err()
                    .then_some(changed)
            })
            .expect("at least one flipped 39-nibble case has no valid completion");
        assert!(Matcher::new(&pat_evm(&[], &[&impossible], true)).is_err());

        let five_free_but_impossible = "a".repeat(35);
        let error = Matcher::new(&pat_evm(&[], &[&five_free_but_impossible], true))
            .err()
            .expect("five free nibbles fit the full budget and must be exhausted, not estimated");
        assert_eq!(
            error,
            "EVM edge constraints conflict or cannot form any address with the requested EIP-55 checksum case"
        );
    }

    #[test]
    fn partial_eip55_case_has_a_concrete_feasibility_witness() {
        let witnessed = Matcher::new(&pat_evm(&["DeAd"], &[], true))
            .expect("ordinary partial checksum pattern has a concrete completion");
        assert!(witnessed.probability_is_approximate());
    }

    #[test]
    fn evm_hit_checks_any_case_then_eip55_when_asked() {
        // EIP-55 example 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed: ends "BeAed"
        let want = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let mut a = [0u8; 20];
        for i in 0..20 {
            a[i] = u8::from_str_radix(&want[2 + 2 * i..4 + 2 * i], 16).unwrap();
        }
        let mut lower = [0u8; 40];
        evm::hex40(&a, &mut lower);
        assert!(Matcher::new(&pat_evm(&["beaed"], &[], false))
            .unwrap()
            .evm_hit(&lower, &a));
        assert!(
            Matcher::new(&pat_evm(&["BEAED"], &[], false))
                .unwrap()
                .evm_hit(&lower, &a),
            "any case without --checksum"
        );
        assert!(
            Matcher::new(&pat_evm(&["BeAed"], &[], true))
                .unwrap()
                .evm_hit(&lower, &a),
            "the real casing"
        );
        assert!(
            !Matcher::new(&pat_evm(&["beaed"], &[], true))
                .unwrap()
                .evm_hit(&lower, &a),
            "wrong casing under --checksum"
        );
        assert!(Matcher::new(&pat_evm(&[], &["0x5aAeb6"], true))
            .unwrap()
            .evm_hit(&lower, &a));
        assert!(!Matcher::new(&pat_evm(&[], &["0x5AAEB6"], true))
            .unwrap()
            .evm_hit(&lower, &a));
        assert!(!Matcher::new(&pat_evm(&["dead"], &[], false))
            .unwrap()
            .evm_hit(&lower, &a));
    }

    #[test]
    fn evm_default_out_lives_under_matches_evm() {
        let d = default_out(&pat_evm(&["DEAD"], &[], false));
        assert!(d.ends_with("matches/evm/dead.txt"), "{}", d.display());
        let d = default_out(&pat_evm(&["DeAd"], &["0xC0ffee"], true));
        assert!(
            d.ends_with("matches/evm/C0ffee_...DeAd.cs.txt"),
            "{}",
            d.display()
        );
    }

    #[test]
    fn evm_grind_finds_a_hit_that_rederives_and_writes_one_header_and_four_record_lines() {
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
        assert!(
            h.address.starts_with("0x") && h.address.len() == 42,
            "{}",
            h.address
        );
        assert!(h.address.to_ascii_lowercase().ends_with('a'));
        let seed = bip39::Mnemonic::parse_normalized(&h.mnemonic)
            .unwrap()
            .to_seed("");
        let b = evm::Branch::from_seed(&seed).unwrap();
        let k = b.key_at(h.index).unwrap();
        assert_eq!(
            evm::eip55(&evm::address_of(&k)),
            h.address,
            "hit does not re-derive from its own mnemonic"
        );
        assert_eq!(
            evm::privkey_hex(&k).as_str(),
            h.privkey.as_str(),
            "the written key is not the address's key"
        );
        assert!(h.keypair_json.is_empty());
        let dir = std::env::temp_dir().join(format!("keyrx-evm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let out = dir.join("a.txt");
        let header = test_match_header(Chain::Evm);
        let file = Mutex::new(open_match_file(&out, &header).unwrap());
        write_hit(&file, &h, PathStyle::Phantom, &header).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(text.starts_with("╔═ keyRX · EVM PRIVATE MATCH FILE"));
        let (_, records) = split_match_file_header(&text).unwrap();
        assert!(
            records.starts_with(&format!(
                "address {}\npath    m/44'/60'/0'/0/{}\nseed    ",
                h.address, h.index
            )),
            "{}",
            records
        );
        assert!(text.contains(&format!("\nprivkey {}\n", h.privkey.as_str())));
        assert!(!text.contains("keypair"), "EVM has one key form");
        assert_eq!(records.lines().filter(|l| !l.is_empty()).count(), 4);
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
        assert!(
            addr.ends_with('A'),
            "EIP-55 case must be the typed one: {}",
            addr
        );
    }

    #[test]
    fn the_network_table_is_well_formed() {
        // one entry per chain id, https everywhere, and the one chain we ship is the one checked
        let mut ids: Vec<u64> = NETWORKS.iter().map(|n| n.chain_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), NETWORKS.len());
        for n in NETWORKS {
            assert!(
                n.rpc.starts_with("https://") && n.explorer.starts_with("https://"),
                "{}",
                n.name
            );
            assert!(!n.name.is_empty() && !n.symbol.is_empty() && !n.checked.is_empty());
        }
        let rh = NETWORKS
            .iter()
            .find(|n| n.name == "Robinhood Chain")
            .expect("Robinhood Chain");
        assert_eq!(rh.chain_id, 4663);
        assert_eq!(rh.rpc, "https://rpc.mainnet.chain.robinhood.com");
        assert_eq!(rh.explorer, "https://robinhoodchain.blockscout.com");
    }

    #[test]
    fn the_evm_self_test_is_green() {
        for (what, ok) in evm::self_test() {
            assert!(ok, "{}", what);
        }
    }

    #[test]
    fn default_out_names_the_file_after_the_pattern() {
        let d = default_out(&pat(&["KEYRX"], &[], false));
        assert!(d.ends_with("matches/KEYRX.txt"), "{}", d.display());
        // both kinds: one hunt with two ends, named PREFIX_...SUFFIX
        let d = default_out(&pat(&["KEYRX"], &["Ab"], true));
        assert!(d.ends_with("matches/Ab_...KEYRX.ic.txt"), "{}", d.display());
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
        assert_eq!(
            addr_for(""),
            "8zzKEAB4VqnUchbsmAor9QzyVWVQFanQGJYQw8UQPh1j",
            "the pinned passphrase-free answer"
        );
        assert_ne!(
            addr_for("x"),
            addr_for(""),
            "a passphrase must change the tree"
        );
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
        grind_loop(
            &m,
            PathStyle::Phantom,
            64,
            16,
            "correct horse",
            &stop,
            &counter,
            &|h| {
                *found.lock().unwrap() = Some(h);
                stop.store(true, Ordering::SeqCst);
            },
        );
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
        assert_eq!(
            addr_for("correct horse"),
            h.address,
            "the hit must derive WITH the passphrase"
        );
        assert_ne!(
            addr_for(""),
            h.address,
            "and the seed alone must NOT reach it"
        );
        let dir = std::env::temp_dir().join(format!("keyrx-pass-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("a.txt");
        let header = build_match_file_header(&pargs(&[], &["a"], Chain::Sol), 4, 12, true).unwrap();
        let file = Mutex::new(open_match_file(&out, &header).unwrap());
        write_hit(&file, &h, PathStyle::Phantom, &header).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(text.contains("\npassphrase used - NOT stored"), "{}", text);
        assert!(
            !text.contains("correct horse"),
            "the passphrase must never be written"
        );
        assert!(text.contains(&format!("address {}", h.address)));
    }

    #[test]
    fn private_reads_are_exact_bounded_and_refuse_descriptor_length_drift() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "keyrx-held-private-read-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let exact = dir.join("exact.txt");
        let mut writer = private_create_new(&exact).unwrap();
        writer.write_all(b"abc").unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let exact_bytes = read_private_text(&exact).unwrap();
        assert_eq!(exact_bytes.as_slice(), b"abc");
        assert_eq!(exact_bytes.capacity(), exact_bytes.len());

        let grown = dir.join("grown.txt");
        let mut writer = private_create_new(&grown).unwrap();
        writer.write_all(b"abc").unwrap();
        writer.sync_all().unwrap();
        let mut reader = std::fs::File::open(&grown).unwrap();
        let held_meta = reader.metadata().unwrap();
        writer.write_all(b"d").unwrap();
        writer.sync_all().unwrap();
        let error = read_held_private_bytes(&mut reader, &held_meta, &grown).unwrap_err();
        assert!(error.to_string().contains("changed length"), "{error}");

        let shrunk = dir.join("shrunk.txt");
        let mut writer = private_create_new(&shrunk).unwrap();
        writer.write_all(b"abc").unwrap();
        writer.sync_all().unwrap();
        let mut reader = std::fs::File::open(&shrunk).unwrap();
        let held_meta = reader.metadata().unwrap();
        writer.set_len(2).unwrap();
        writer.sync_all().unwrap();
        let error = read_held_private_bytes(&mut reader, &held_meta, &shrunk).unwrap_err();
        assert!(error.to_string().contains("changed length"), "{error}");

        let oversized = dir.join("oversized.txt");
        let writer = private_create_new(&oversized).unwrap();
        writer.set_len(MAX_PRIVATE_MATCH_FILE_BYTES + 1).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let error = read_private_text(&oversized).unwrap_err();
        assert!(error.to_string().contains("supported maximum"), "{error}");
        let error = open_match_file(&oversized, &test_match_header(Chain::Sol)).unwrap_err();
        assert!(error.to_string().contains("supported maximum"), "{error}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn recovery_rows_and_inventory_commands_preserve_complete_dynamic_values() {
        for (address, path) in [
            (
                "11111111111111111111111111111111111111111111",
                "m/44'/501'/2147483647'/0'",
            ),
            (
                "0x1111111111111111111111111111111111111111",
                "m/44'/60'/0'/0/2147483647",
            ),
        ] {
            let rows = match_summary_rows(123, address, path);
            let plain = rows.map(|row| ui::plain(&row));
            assert!(plain[0].contains("123."), "ordinal missing: {:?}", plain);
            assert!(plain[0].contains(address), "address clipped: {:?}", plain);
            assert!(plain[1].contains(path), "path clipped: {:?}", plain);
            assert!(
                !plain.join("\n").contains("..."),
                "valid recovery data clipped"
            );
        }

        let stem = format!(
            "{}_...{}_{}",
            "a".repeat(40),
            "b".repeat(40),
            "c".repeat(40)
        );
        let command = show_command(&stem);
        assert!(
            command.contains(&stem),
            "inventory command clipped: {command}"
        );
        assert_eq!(command, format!("keyrx show -- '{stem}'"));
    }

    #[test]
    fn live_seed_rows_preserve_every_supported_word_without_clipping() {
        let mnemonic = std::iter::repeat_n("abstract", 24)
            .collect::<Vec<_>>()
            .join(" ");
        let rows = seed_display_rows(&mnemonic);
        assert_eq!(rows.len(), 4);
        let plain = rows.iter().map(|row| ui::plain(row)).collect::<Vec<_>>();
        assert_eq!(plain.join(" ").matches("abstract").count(), 24);
        assert!(!plain.join(" ").contains("..."));
        assert!(plain[0].contains("seed"));
        for row in plain {
            assert_eq!(row.chars().count(), ui::W, "ragged seed row: {row:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn grind_marker_suffix_is_appended_to_raw_path_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let raw = std::ffi::OsString::from_vec(b"/tmp/keyrx-\x80.txt".to_vec());
        let marker = grind_marker_path(std::path::Path::new(&raw));
        assert_eq!(
            marker.as_os_str().as_bytes(),
            b"/tmp/keyrx-\x80.txt.grinding"
        );
        assert_ne!(
            marker.as_os_str().as_bytes(),
            format!("{}.grinding", ui::path_text(std::path::Path::new(&raw))).as_bytes(),
            "rendered path text was fed back into a filesystem identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn grind_output_custody_refuses_path_replacement_and_new_hard_links() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "keyrx-output-custody-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let out = dir.join("held.txt");
        let header = test_match_header(Chain::Evm);
        let held = open_match_file(&out, &header).unwrap();
        let moved = dir.join("moved.txt");
        std::fs::rename(&out, &moved).unwrap();
        let replacement = open_match_file(&out, &header).unwrap();
        let error = validate_grind_output_path(&held, &out).unwrap_err();
        assert!(error.to_string().contains("no longer names"), "{error}");
        drop(replacement);
        std::fs::remove_file(&out).unwrap();

        let alias = dir.join("alias.txt");
        std::fs::hard_link(&moved, &alias).unwrap();
        let hit = Hit {
            chain: Chain::Evm,
            index: 0,
            address: format!("0x{}", "1".repeat(40)),
            mnemonic: Zeroizing::new("abandon ".repeat(11) + "about"),
            passphrase: false,
            privkey: Zeroizing::new(format!("0x{}", "2".repeat(64))),
            keypair_json: Zeroizing::new(String::new()),
        };
        let held = Mutex::new(held);
        let error = write_hit(
            &held,
            &hit,
            PathStyle::Phantom,
            &test_match_header(Chain::Evm),
        )
        .unwrap_err();
        assert!(error.to_string().contains("custody changed"), "{error}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn maximal_sol_and_evm_records_never_grow_the_secret_buffer() {
        let mnemonic = std::iter::repeat_n("abcdefgh", 24)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(mnemonic.len(), 24 * 8 + 23);
        let keypair_json = format!(
            "[{}]",
            std::iter::repeat_n("255", 64).collect::<Vec<_>>().join(",")
        );
        assert_eq!(keypair_json.len(), 257);
        let sol = Hit {
            chain: Chain::Sol,
            index: HARDENED - 1,
            address: "1".repeat(44),
            mnemonic: Zeroizing::new(mnemonic.clone()),
            passphrase: true,
            privkey: Zeroizing::new("1".repeat(88)),
            keypair_json: Zeroizing::new(keypair_json),
        };
        let (sol_record, sol_reserved) = format_hit_record(&sol, PathStyle::Phantom).unwrap();
        assert_eq!(sol_record.capacity(), sol_reserved);
        assert!(sol_record.len() < sol_reserved);
        assert!(
            sol_record.len() < 1024,
            "supported Sol record grew unexpectedly"
        );

        let evm = Hit {
            chain: Chain::Evm,
            index: HARDENED - 1,
            address: format!("0x{}", "f".repeat(40)),
            mnemonic: Zeroizing::new(mnemonic),
            passphrase: true,
            privkey: Zeroizing::new(format!("0x{}", "f".repeat(64))),
            keypair_json: Zeroizing::new(String::new()),
        };
        let (evm_record, evm_reserved) = format_hit_record(&evm, PathStyle::Phantom).unwrap();
        assert_eq!(evm_record.capacity(), evm_reserved);
        assert!(evm_record.len() < evm_reserved);
        assert!(
            evm_record.len() < 1024,
            "supported EVM record grew unexpectedly"
        );
    }

    #[test]
    fn append_refuses_before_a_match_file_outgrows_its_read_bound() {
        let hit = Hit {
            chain: Chain::Evm,
            index: 0,
            address: format!("0x{}", "1".repeat(40)),
            mnemonic: Zeroizing::new("abandon ".repeat(11) + "about"),
            passphrase: false,
            privkey: Zeroizing::new(format!("0x{}", "1".repeat(64))),
            keypair_json: Zeroizing::new(String::new()),
        };
        let (record, _) = format_hit_record(&hit, PathStyle::Phantom).unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("keyrx-write-bound-{}-{nonce}", std::process::id()));
        let file = private_create_new(&path).unwrap();
        let before = MAX_PRIVATE_MATCH_FILE_BYTES - record.len() as u64 + 1;
        file.set_len(before).unwrap();
        let file = Mutex::new(file);
        let error = write_hit(
            &file,
            &hit,
            PathStyle::Phantom,
            &test_match_header(Chain::Evm),
        )
        .unwrap_err();
        assert!(error.to_string().contains("would exceed the supported"));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn grind_lock_metadata_failure_removes_and_flushes_the_created_marker() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "keyrx-lock-metadata-failure-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("matches.txt");
        let mut marker = out.as_os_str().to_os_string();
        marker.push(".grinding");
        let marker = std::path::PathBuf::from(marker);

        let result = GrindLock::acquire_with_metadata(&out, |_| {
            Err(std::io::Error::other("injected metadata failure"))
        });
        let error = match result {
            Ok(_) => panic!("injected metadata failure was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected metadata failure"));
        assert!(!marker.exists(), "failed acquire stranded its marker");

        let mut retry = GrindLock::acquire(&out).unwrap();
        assert!(marker.exists(), "clean retry did not acquire its marker");
        retry.release().unwrap();
        assert!(!marker.exists(), "explicit release left its marker");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_failure_and_incomplete_interrupt_are_not_success() {
        assert_eq!(grind_exit_status(true, false, 0, 1), 1);
        assert_eq!(grind_exit_status(true, true, 1, 1), 1);
        assert_eq!(grind_exit_status(false, true, 0, 1), 130);
        assert_eq!(grind_exit_status(false, true, 1, 1), 0);
        assert_eq!(grind_exit_status(false, false, 0, 1), 1);
        assert!(validate_work_args(usize::MAX, 1, 1).is_err());

        for (value, expected) in [
            ("with space.txt", "'with space.txt'"),
            ("$(touch /tmp/not-run).txt", "'$(touch /tmp/not-run).txt'"),
            ("`touch /tmp/not-run`.txt", "'`touch /tmp/not-run`.txt'"),
            ("it's.txt", "'it'\"'\"'s.txt'"),
            ("-leading.txt", "'-leading.txt'"),
        ] {
            assert_eq!(shell_quote_posix(value), expected);
        }

        let dir =
            std::env::temp_dir().join(format!("keyrx-readonly-write-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("held.txt");
        std::fs::write(&out, b"").unwrap();
        let readonly = Mutex::new(std::fs::File::open(&out).unwrap());
        let hit = Hit {
            chain: Chain::Evm,
            index: 0,
            address: "0x0000000000000000000000000000000000000000".into(),
            mnemonic: Zeroizing::new("public test words".into()),
            passphrase: false,
            privkey: Zeroizing::new("0x00".into()),
            keypair_json: Zeroizing::new(String::new()),
        };
        assert!(write_hit(
            &readonly,
            &hit,
            PathStyle::Phantom,
            &test_match_header(Chain::Sol),
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
