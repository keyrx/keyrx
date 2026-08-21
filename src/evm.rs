//! EVM addresses - Ethereum and every chain that shares its key format (Base, Arbitrum,
//! Optimism, Polygon, BNB, Avalanche C-Chain, Robinhood Chain...): secp256k1 keys in a BIP32 tree at the
//! BIP44 path `m/44'/60'/0'/0/N`, the address the last twenty bytes of keccak-256 over
//! the uncompressed public key, written in EIP-55 mixed case.
//!
//! The same idea as the Solana path: one mnemonic pays PBKDF2 once, then the tree is
//! walked. Here the walk is the standard (non-hardened) last level, which costs one
//! HMAC-SHA512 plus one secp256k1 scalar multiplication per candidate - the latter is the
//! whole cost, and it is why the EVM rate per core is a fraction of the Ed25519 one.
//!
//! Every answer in here is pinned in `tests` against an independent implementation
//! (node crypto + noble, a different language and different libraries) and against
//! published vectors: the "abandon ... about" mnemonic, the EIP-55 examples, private key 1.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x8000_0000;

/// A private scalar from 32 big-endian bytes, if they name one: BIP32 rejects an IL that
/// is not below the curve order (and a child key of zero); both are astronomically rare
/// and both are handled by skipping, never by reducing.
#[inline]
fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let ct = Scalar::from_repr((*bytes).into());
    if bool::from(ct.is_some()) { Some(ct.unwrap()) } else { None }
}

#[inline]
fn split(out: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    c.copy_from_slice(&out[32..]);
    (k, c)
}

/// The compressed SEC1 public key (33 bytes) of a private scalar - what BIP32 feeds into
/// a non-hardened child derivation as `serP(K_par)`.
#[inline]
fn compressed(k: &Scalar) -> [u8; 33] {
    let p = ProjectivePoint::mul_by_generator(k).to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(p.as_bytes());
    out
}

/// BIP32 master node from a BIP39 seed: HMAC-SHA512 keyed "Bitcoin seed".
fn master(seed: &[u8]) -> Option<(Scalar, [u8; 32])> {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("hmac accepts any key length");
    mac.update(seed);
    let (k, c) = split(mac.finalize().into_bytes().as_slice());
    scalar(&k).map(|s| (s, c))
}

/// BIP32 hardened child: data = 0x00 || ser256(k_par) || ser32(i + 2^31).
fn child_hardened(k: &Scalar, c: &[u8; 32], index: u32) -> Option<(Scalar, [u8; 32])> {
    let mut mac = HmacSha512::new_from_slice(c).expect("hmac accepts any key length");
    mac.update(&[0u8]);
    mac.update(&k.to_bytes());
    mac.update(&(index | HARDENED).to_be_bytes());
    let (il, cc) = split(mac.finalize().into_bytes().as_slice());
    let il = scalar(&il)?;
    let child = il + k;
    if bool::from(child.is_zero()) { return None; }
    Some((child, cc))
}

/// BIP32 normal child, given the parent's compressed public key: data = serP(K_par) || ser32(i).
#[inline]
fn child_normal(k: &Scalar, c: &[u8; 32], parent_pub: &[u8; 33], index: u32) -> Option<(Scalar, [u8; 32])> {
    let mut mac = HmacSha512::new_from_slice(c).expect("hmac accepts any key length");
    mac.update(parent_pub);
    mac.update(&index.to_be_bytes());
    let (il, cc) = split(mac.finalize().into_bytes().as_slice());
    let il = scalar(&il)?;
    let child = il + k;
    if bool::from(child.is_zero()) { return None; }
    Some((child, cc))
}

/// The node `m/44'/60'/0'/0` of one seed: everything that is constant across the account
/// indices, computed once per mnemonic. From here each index is one HMAC and one scalar
/// multiplication.
pub struct Branch {
    key: Scalar,
    chain: [u8; 32],
    pubkey: [u8; 33],
}

impl Branch {
    /// `None` only for the one-in-2^127 seed whose tree hits an invalid key; the caller
    /// simply draws another mnemonic.
    pub fn from_seed(seed: &[u8]) -> Option<Branch> {
        let (k, c) = master(seed)?;
        let (k, c) = child_hardened(&k, &c, 44)?;
        let (k, c) = child_hardened(&k, &c, 60)?;
        let (k, c) = child_hardened(&k, &c, 0)?;
        let p = compressed(&k);
        let (k, c) = child_normal(&k, &c, &p, 0)?;
        let pubkey = compressed(&k);
        Some(Branch { key: k, chain: c, pubkey })
    }

    /// The private scalar at `m/44'/60'/0'/0/index`.
    #[inline]
    pub fn key_at(&self, index: u32) -> Option<Scalar> {
        child_normal(&self.key, &self.chain, &self.pubkey, index).map(|(k, _)| k)
    }

    /// The twenty-byte address at `m/44'/60'/0'/0/index`: keccak-256 over the 64-byte
    /// uncompressed public key (without its 0x04 tag), last twenty bytes.
    #[inline]
    pub fn address_at(&self, index: u32) -> Option<[u8; 20]> {
        self.key_at(index).map(|k| address_of(&k))
    }
}

/// The address of a private scalar.
#[inline]
pub fn address_of(k: &Scalar) -> [u8; 20] {
    let p = ProjectivePoint::mul_by_generator(k).to_affine().to_encoded_point(false);
    let bytes = p.as_bytes(); // 0x04 || X || Y
    let h = Keccak256::digest(&bytes[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    out
}

/// The private key as wallets import it: `0x` and sixty-four lowercase hex digits.
pub fn privkey_hex(k: &Scalar) -> Zeroizing<String> {
    let b = k.to_bytes();
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for x in b.iter() { s.push_str(&format!("{:02x}", x)); }
    Zeroizing::new(s)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Forty lowercase hex digits, no `0x`.
#[inline]
pub fn hex40(addr: &[u8; 20], out: &mut [u8; 40]) {
    for (i, b) in addr.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 15) as usize];
    }
}

/// EIP-55: keccak-256 over the forty lowercase hex digits (as ASCII); a letter is upper
/// case where the hash digit in its position is 8 or above. Returned with `0x`.
pub fn eip55(addr: &[u8; 20]) -> String {
    let mut lower = [0u8; 40];
    hex40(addr, &mut lower);
    let h = Keccak256::digest(lower);
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for (i, &c) in lower.iter().enumerate() {
        let nibble = if i % 2 == 0 { h[i / 2] >> 4 } else { h[i / 2] & 15 };
        s.push(if c.is_ascii_alphabetic() && nibble >= 8 { c.to_ascii_uppercase() as char } else { c as char });
    }
    s
}

/// Whether a pattern could be part of an EVM address: hex digits only, after an optional
/// `0x` that is only meaningful at the front of a prefix.
pub fn check_pattern(s: &str, is_prefix: bool) -> Result<String, String> {
    let body = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(rest) if is_prefix => rest,
        Some(_) => return Err("0x is the address prefix, not part of a suffix - write the hex digits only".into()),
        None => s,
    };
    if body.is_empty() { return Err("empty pattern".into()); }
    for c in body.chars() {
        if !c.is_ascii_hexdigit() {
            return Err(format!("'{}' is not hex - an EVM address is 0-9 and a-f only", c));
        }
    }
    Ok(body.to_string())
}

/// The "abandon ... about" mnemonic - MetaMask's, Hardhat's, every tutorial's - and its
/// published first account and key at m/44'/60'/0'/0/0.
pub const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const ABANDON_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
pub const ABANDON_KEY: &str = "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
/// keyrx's own public test seed (entropy [7u8; 32]), the one `verify` prints - and its EVM
/// accounts as derived by an independent implementation (node crypto + @noble/curves +
/// @noble/hashes, 2026-08-20): a different language and different libraries.
pub const TEST_SEED: &str = "alpha deal scrub asthma idea logic bright thought alpha deal scrub asthma idea logic bright thought alpha deal scrub asthma idea logic bright truly";
pub const TEST_SEED_ACCOUNTS: [(u32, &str, &str); 4] = [
    (0, "0x29458C602E3DB4fC3b54EC2bbEE26Dbe64C7779f", "0x0d943387d3a6266cb3c28401415291b05c16e594f01a441fe2f8626413c330c0"),
    (1, "0xa639149dF423F9a4A549E9B9929Ee22727128990", "0x1a9384c07fa4714285709897a0c4e65a8bd7e29cb542ef55723f4954ab96a698"),
    (2, "0xF66F9Ca03f6aabf3AAf38040aa6f25D10Bd2916a", "0xf9f33f742f1be60320af9b46e342ac20b43f1d052256c1d745a73d21736be2c5"),
    (7, "0xbA06F505C832FFa920Ae599b29088b2E9C5eA67e", "0x974d02aad83e6767fb5e6567c8aee5d3a69b862962cda249377b0bc4312442f0"),
];
/// The same seed with the passphrase "correct horse", account 0, from the same reference.
pub const TEST_SEED_PASSPHRASE_ADDRESS: &str = "0x02A1Fe3D6B8c2F1e6467bf0271cca23c929De5b5";
/// EIP-55's own examples.
pub const EIP55_EXAMPLES: [&str; 4] = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
];
/// Private key 1's address - the most-checked constant in the ecosystem.
pub const PRIVKEY_ONE_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

fn seed_of(mn: &str, pass: &str) -> [u8; 64] {
    bip39::Mnemonic::parse_normalized(mn).expect("a fixed, valid mnemonic").to_seed(pass)
}

/// Every pinned answer, checked: (what, holds). `verify` prints the list; a test asserts
/// it is all true. One implementation, so the command and the test cannot disagree.
pub fn self_test() -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let ab = Branch::from_seed(&seed_of(ABANDON, ""));
    let (a, k) = match &ab {
        Some(b) => match b.key_at(0) { Some(k) => (eip55(&address_of(&k)), privkey_hex(&k).to_string()), None => (String::new(), String::new()) },
        None => (String::new(), String::new()),
    };
    out.push(("\"abandon ... about\" account 0 is the published address".into(), a == ABANDON_ADDRESS));
    out.push(("... and its published private key".into(), k == ABANDON_KEY));
    let ts = Branch::from_seed(&seed_of(TEST_SEED, ""));
    let mut ok = true;
    for (i, want, key) in TEST_SEED_ACCOUNTS {
        match ts.as_ref().and_then(|b| b.key_at(i)) {
            Some(k) => { ok &= eip55(&address_of(&k)) == want && privkey_hex(&k).as_str() == key; }
            None => ok = false,
        }
    }
    out.push((format!("test seed accounts {} match the independent reference", TEST_SEED_ACCOUNTS.iter().map(|(i, _, _)| i.to_string()).collect::<Vec<_>>().join(", ")), ok));
    let tp = Branch::from_seed(&seed_of(TEST_SEED, "correct horse")).and_then(|b| b.address_at(0)).map(|a| eip55(&a));
    out.push(("a BIP39 passphrase changes the tree as the reference says".into(), tp.as_deref() == Some(TEST_SEED_PASSPHRASE_ADDRESS)));
    let mut e55 = true;
    for want in EIP55_EXAMPLES {
        let mut a = [0u8; 20];
        for i in 0..20 { a[i] = u8::from_str_radix(&want[2 + 2 * i..4 + 2 * i], 16).unwrap_or(0); }
        e55 &= eip55(&a) == want;
    }
    out.push(("EIP-55 casing matches the specification's four examples".into(), e55));
    let one = scalar(&{ let mut b = [0u8; 32]; b[31] = 1; b }).map(|k| eip55(&address_of(&k)));
    out.push(("private key 1 is the well-known address".into(), one.as_deref() == Some(PRIVKEY_ONE_ADDRESS)));
    // the hot loop's walk equals the straight derivation, and is deterministic
    let mut same = ts.is_some();
    if let Some(b) = &ts {
        let again = Branch::from_seed(&seed_of(TEST_SEED, ""));
        for i in 0..8u32 {
            same &= b.address_at(i) == b.key_at(i).map(|k| address_of(&k))
                && again.as_ref().and_then(|x| x.address_at(i)) == b.address_at(i);
        }
    }
    out.push(("walk equals straight derivation, deterministic, indices 0-7".into(), same));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(mn: &str, pass: &str) -> [u8; 64] { seed_of(mn, pass) }

    #[test]
    fn abandon_mnemonic_first_account_is_the_famous_address() {
        // The MetaMask / Hardhat / every-tutorial mnemonic. Published address and key.
        let b = Branch::from_seed(&seed(ABANDON, "")).unwrap();
        let k = b.key_at(0).unwrap();
        assert_eq!(eip55(&address_of(&k)), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(privkey_hex(&k).as_str(), "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727");
    }

    #[test]
    fn test_seed_matches_the_independent_reference_at_several_indices() {
        // node crypto (PBKDF2, HMAC) + @noble/curves + @noble/hashes, 2026-08-20: a
        // different language and different libraries deriving the same tree.
        let b = Branch::from_seed(&seed(TEST_SEED, "")).unwrap();
        for (i, want, key) in [
            (0u32, "0x29458C602E3DB4fC3b54EC2bbEE26Dbe64C7779f", "0x0d943387d3a6266cb3c28401415291b05c16e594f01a441fe2f8626413c330c0"),
            (1, "0xa639149dF423F9a4A549E9B9929Ee22727128990", "0x1a9384c07fa4714285709897a0c4e65a8bd7e29cb542ef55723f4954ab96a698"),
            (2, "0xF66F9Ca03f6aabf3AAf38040aa6f25D10Bd2916a", "0xf9f33f742f1be60320af9b46e342ac20b43f1d052256c1d745a73d21736be2c5"),
            (7, "0xbA06F505C832FFa920Ae599b29088b2E9C5eA67e", "0x974d02aad83e6767fb5e6567c8aee5d3a69b862962cda249377b0bc4312442f0"),
        ] {
            let k = b.key_at(i).unwrap();
            assert_eq!(eip55(&address_of(&k)), want, "index {}", i);
            assert_eq!(privkey_hex(&k).as_str(), key, "index {}", i);
            assert_eq!(b.address_at(i).unwrap(), address_of(&k));
        }
    }

    #[test]
    fn a_passphrase_changes_the_tree_and_matches_the_reference() {
        let b = Branch::from_seed(&seed(TEST_SEED, "correct horse")).unwrap();
        assert_eq!(eip55(&b.address_at(0).unwrap()), "0x02A1Fe3D6B8c2F1e6467bf0271cca23c929De5b5");
    }

    #[test]
    fn eip55_matches_the_specification_examples() {
        for want in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let mut a = [0u8; 20];
            for i in 0..20 { a[i] = u8::from_str_radix(&want[2 + 2 * i..4 + 2 * i], 16).unwrap(); }
            assert_eq!(eip55(&a), want);
        }
    }

    #[test]
    fn private_key_one_is_the_well_known_address() {
        let k = scalar(&{ let mut b = [0u8; 32]; b[31] = 1; b }).unwrap();
        assert_eq!(eip55(&address_of(&k)), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    #[test]
    fn the_self_test_is_all_green() {
        for (what, ok) in self_test() { assert!(ok, "{}", what); }
        assert!(self_test().len() >= 7);
    }

    #[test]
    fn hex40_is_the_lowercase_of_eip55() {
        let b = Branch::from_seed(&seed(TEST_SEED, "")).unwrap();
        let a = b.address_at(3).unwrap();
        let mut h = [0u8; 40];
        hex40(&a, &mut h);
        assert_eq!(std::str::from_utf8(&h).unwrap(), &eip55(&a)[2..].to_ascii_lowercase());
    }

    #[test]
    fn patterns_are_hex_with_0x_only_on_a_prefix() {
        assert_eq!(check_pattern("dead", false).unwrap(), "dead");
        assert_eq!(check_pattern("0xdead", true).unwrap(), "dead");
        assert_eq!(check_pattern("DeAd", false).unwrap(), "DeAd");
        assert!(check_pattern("0xdead", false).is_err());
        assert!(check_pattern("0x", true).is_err());
        assert!(check_pattern("", false).is_err());
        assert!(check_pattern("keyrx", false).is_err());
    }
}
