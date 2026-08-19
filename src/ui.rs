//! The dress: double-line frames with half-block title tabs, the `ink`
//! palette (healthy is HUELESS grey; colour is spent only where it
//! means something), gauge bars in █▌░, and one law - every framed line
//! measures exactly the same width, asserted in tests, never eyeballed.
//!
//! Escape codes are dropped entirely when stdout is not a terminal or
//! NO_COLOR is set, so piped output stays plain text.

use std::io::IsTerminal;
use std::sync::OnceLock;

pub const W: usize = 78; // board width; IN = W - 3 (space + two borders)
pub const IN: usize = W - 3;

fn on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
}

macro_rules! code {
    ($name:ident, $seq:expr) => {
        pub fn $name() -> &'static str { if on() { $seq } else { "" } }
    };
}
// `ink`: ok = neutral grey 245, warn = amber 179, crit = rose 167,
// accent = soft blue 110, gry 243, faint 237, wht 251.
code!(r, "\x1b[0m");
code!(b, "\x1b[1m");
code!(ok, "\x1b[38;5;245m");
code!(warn, "\x1b[38;5;179m");
code!(crit, "\x1b[38;5;167m");
code!(accent, "\x1b[38;5;110m");
code!(gry, "\x1b[38;5;243m");
code!(faint, "\x1b[38;5;237m");
code!(wht, "\x1b[38;5;251m");

/// Visible width: characters, with SGR escapes removed. Every glyph this
/// module emits is one column wide in a monospace font (no wide chars, no
/// combining marks), so char count is column count.
pub fn vis(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for ch in s.chars() {
        if in_esc {
            if ch == 'm' { in_esc = false; }
        } else if ch == '\x1b' {
            in_esc = true;
        } else {
            n += 1;
        }
    }
    n
}

/// Clip a (possibly coloured) string to at most `n` visible columns, keeping
/// escapes intact and closing with a reset.
pub fn clip(s: &str, n: usize) -> String {
    if vis(s) <= n { return s.to_string(); }
    let mut out = String::new();
    let mut seen = 0;
    let mut in_esc = false;
    for ch in s.chars() {
        if in_esc {
            out.push(ch);
            if ch == 'm' { in_esc = false; }
        } else if ch == '\x1b' {
            in_esc = true;
            out.push(ch);
        } else {
            if seen >= n { break; }
            out.push(ch);
            seen += 1;
        }
    }
    out.push_str(r());
    out
}

/// ╔══▌ TITLE ▐════ sub ═╗  - and a blank row of air after it.
pub fn top(title: &str, sub: &str) -> String {
    // geometry: ' ╔══' (4) + tabs + fill + tail + '╗' (1) == W, and W == IN + 3,
    // so tabs + fill + tail == IN - 2. The sub is decoration and goes first;
    // then the title clips; the frame itself never gives.
    let mk_tabs = |t: &str| format!("{}▌{}{}{} {} {}{}▐{}", accent(), r(), b(), wht(), t, r(), accent(), r());
    let mut tabs = mk_tabs(title);
    let mut tail = if sub.is_empty() { String::new() } else { format!("{} {} {}", gry(), sub, r()) };
    let budget = IN as isize - 2;
    let mut fill = budget - vis(&tabs) as isize - vis(&tail) as isize;
    if fill < 1 && !tail.is_empty() {
        tail.clear();
        fill = budget - vis(&tabs) as isize;
    }
    if fill < 1 {
        // title alone overflows: clip it to leave one cell of fill
        let room = (budget - 1 - 4).max(1) as usize;   // 4 = "▌ " + " ▐"
        let t: String = title.chars().take(room).collect();
        tabs = mk_tabs(&t);
        fill = budget - vis(&tabs) as isize;
    }
    let fill = fill.max(1) as usize;
    format!("\n\n {}╔══{}{}{}{}{}{}{}╗{}\n{}",
        accent(), r(), tabs, accent(), "═".repeat(fill), r(), tail, accent(), r(), mid(""))
}

/// ║ text ║ - padded to the inner width, clipped if longer.
pub fn mid(text: &str) -> String {
    let t = clip(text, IN);
    let pad = IN.saturating_sub(vis(&t));
    format!(" {}║{}{}{}{}║{}", accent(), r(), t, " ".repeat(pad), accent(), r())
}

/// A blank row of air, then ╚══ note ═══╝.
pub fn bot(note: &str) -> String {
    let body = if note.is_empty() {
        format!(" {}╚{}╝{}", accent(), "═".repeat(IN), r())
    } else {
        let n = clip(&format!("{} {} {}", gry(), note, r()), IN - 3);
        let fill = (IN as isize - vis(&n) as isize - 2).max(1) as usize;
        format!(" {}╚══{}{}{}{}╝{}", accent(), r(), n, accent(), "═".repeat(fill), r())
    };
    format!("{}\n{}", mid(""), body)
}

/// Gauge bar: █ fill with a ▌ half-cell cap, ░ track. Colour by severity of
/// the percentage the way the board colours a plan: grey, amber at 70, rose
/// at 90.
pub fn bar(pct: f64, w: usize) -> String {
    let full = ((pct / 100.0 * w as f64).round() as usize).min(w);
    let full = if pct > 0.0 { full.max(1) } else { full };
    let col = if pct >= 90.0 { crit() } else if pct >= 70.0 { warn() } else { ok() };
    let cap = if full > 0 && full < w { "▌" } else { "" };
    let track = w - full - cap.chars().count();
    format!("{}{}{}{}{}{}", col, "█".repeat(full), cap, faint(), "░".repeat(track), r())
}

/// A key/value row inside a panel: two-space gutter, grey key, white value.
pub fn kv(key: &str, val: &str) -> String {
    mid(&format!("  {}{:<11}{}{}{}{}", gry(), key, r(), wht(), val, r()))
}

/// Same with a wide key column - for flag names, which run long.
pub fn kvw(key: &str, val: &str) -> String {
    mid(&format!("  {}{:<16}{}{}{}{}", gry(), key, r(), wht(), val, r()))
}

/// Continuation line under a wide-key row: text aligned to the value column.
pub fn cont(text: &str) -> String {
    mid(&format!("  {:<16}{}{}{}", "", gry(), text, r()))
}

/// Same, with the value in the accent colour (a number worth reading).
pub fn kv_accent(key: &str, val: &str) -> String {
    mid(&format!("  {}{:<11}{}{}{}{}", gry(), key, r(), accent(), val, r()))
}

pub fn note(text: &str) -> String {
    mid(&format!("  {}{}{}", gry(), text, r()))
}

pub fn warn_line(text: &str) -> String {
    mid(&format!("  {}▲ {}{}", warn(), text, r()))
}

pub fn ok_line(text: &str) -> String {
    mid(&format!("  {}● {}{}", ok(), text, r()))
}

pub fn crit_line(text: &str) -> String {
    mid(&format!("  {}▲ {}{}", crit(), text, r()))
}

/// The masthead: ▐▌ keyRX  one mnemonic, unlimited addresses     right-hand note
/// The mark: the seal of the flagship keyRX Deploy record - the manifest sha256 of the first
/// keyRX/KEYRX launch (mint DH3EVN…KEYRX, devnet). Sixty-four hex digits on an 8x8 grid, a cell
/// lit where the digit is 8 or above - the rule that draws the seal of every deployment record on
/// deploy.keyrx.tech. Two grid rows per text line in half-blocks: rows 0-3 blue, rows 4-7 amber.
/// The same glyph is the site's favicon and the repository's avatar; here it is text.
pub const SEAL: &str = "fbd454bdefee923628fcb6f24667b772ea942f176f9c7988b5e2d2264b335ac8";

/// Four text lines, sixteen columns each (two columns per cell), coloured when stdout is a terminal.
pub fn seal_lines() -> [String; 4] {
    let lit: Vec<bool> = SEAL.bytes().map(|b| (b as char).to_digit(16).unwrap_or(0) >= 8).collect();
    let mut out: [String; 4] = Default::default();
    for (p, line) in out.iter_mut().enumerate() {
        let mut s = String::new();
        for c in 0..8 {
            let (t, bt) = (lit[p * 16 + c], lit[p * 16 + 8 + c]);
            let ch = match (t, bt) { (true, true) => "█", (true, false) => "▀", (false, true) => "▄", _ => " " };
            s.push_str(ch); s.push_str(ch);
        }
        *line = format!("{}{}{}", if p < 2 { accent() } else { warn() }, s, r());
    }
    out
}

pub fn masthead(right: &str) {
    let seal = seal_lines();
    let name = format!("{}{}keyRX{}  {}vanity addresses, keys for every wallet{}", b(), wht(), r(), gry(), r());
    let head = format!(" {}  {}", seal[0], name);
    let rt = format!("{}{}{}", gry(), right, r());
    let gap = (W as isize - vis(&head) as isize - vis(&rt) as isize - 1).max(1) as usize;
    println!("\n{}{}{}", head, " ".repeat(gap), rt);
    println!(" {}", seal[1]);
    println!(" {}  {}the mark is a record: the first keyRX Deploy launch, sealed{}", seal[2], faint(), r());
    println!(" {}", seal[3]);
    println!(" {}{}{}", faint(), "━".repeat(W - 2), r());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_four_lines_of_sixteen_columns_and_lit_where_the_digit_is_eight_or_more() {
        let l = seal_lines();
        assert!(l.iter().all(|x| vis(x) == 16));
        // top-left cell: 'f' (15) is lit; row 1 col 0: 'e' from "…efee9…"? derive from the constant instead
        let lit = |i: usize| SEAL.as_bytes()[i] as char >= '8';
        let first = l[0].chars().filter(|c| !c.is_ascii_control()).collect::<String>();
        let first: String = { let mut s = String::new(); let mut in_esc = false; for ch in first.chars() { if in_esc { if ch == 'm' { in_esc = false; } } else if ch == '\x1b' { in_esc = true; } else { s.push(ch); } } s };
        let expect0 = match (lit(0), lit(8)) { (true, true) => '█', (true, false) => '▀', (false, true) => '▄', _ => ' ' };
        assert_eq!(first.chars().next().unwrap(), expect0);
        assert_eq!(SEAL.bytes().filter(|b| (*b as char).to_digit(16).unwrap() >= 8).count(), 33);
    }

    fn frame_lines(s: &str) -> Vec<&str> {
        s.lines().filter(|l| {
            let p = strip(l);
            let t = p.trim_start();
            t.starts_with('╔') || t.starts_with('║') || t.starts_with('╚')
        }).collect()
    }

    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut in_esc = false;
        for ch in s.chars() {
            if in_esc { if ch == 'm' { in_esc = false; } }
            else if ch == '\x1b' { in_esc = true; }
            else { out.push(ch); }
        }
        out
    }

    #[test]
    fn every_frame_line_measures_w() {
        // The invariant that broke three times on the board: measure, do not
        // eyeball. Head, body, over-long body, foot, empty foot, coloured body.
        let long = "x".repeat(300);
        let panel = format!("{}\n{}\n{}\n{}\n{}\n{}",
            top("PLAN", "a subtitle"),
            mid("  hello"),
            mid(&long),
            kv("key", "value"),
            mid(&format!("  {}coloured{} {}text{}", crit(), r(), accent(), r())),
            bot("a note at the foot"));
        for l in frame_lines(&panel) {
            assert_eq!(strip(l).chars().count(), W, "ragged: {:?}", strip(l));
        }
        for l in frame_lines(&format!("{}\n{}", top(&long, &long), bot(&long))) {
            assert_eq!(strip(l).chars().count(), W, "ragged on overlong: {:?}", strip(l));
        }
        for l in frame_lines(&format!("{}\n{}", top("T", ""), bot(""))) {
            assert_eq!(strip(l).chars().count(), W);
        }
    }

    #[test]
    fn bar_is_exact_width_and_capped() {
        for w in [10usize, 22, 40] {
            for pct in [0.0, 0.4, 12.5, 50.0, 71.0, 95.0, 100.0] {
                let b = bar(pct, w);
                assert_eq!(vis(&b), w, "pct={} w={}", pct, w);
            }
        }
        assert!(strip(&bar(0.0, 10)).chars().all(|c| c == '░'));
        assert!(strip(&bar(100.0, 10)).chars().all(|c| c == '█'));
        assert!(strip(&bar(0.4, 10)).starts_with('█'), "tiny nonzero still lights a cell");
    }

    #[test]
    fn no_fallback_risk_glyphs() {
        // The glyphs that staggered a frame under font fallback. None may
        // appear anywhere in this module's output.
        let banned = ['—', '–', '‘', '’', '“', '”', '→', '▟', '▛', '▎', '▋', '▁', '▂', '▃', '▄', '▅', '▆', '▇'];
        let all = format!("{}{}{}{}{}{}{}", top("T", "s"), mid("m"), bot("n"), bar(33.0, 20),
            kv("k", "v"), warn_line("w"), crit_line("c"));
        for ch in strip(&all).chars() {
            assert!(!banned.contains(&ch), "fallback-risk glyph {:?}", ch);
        }
    }


    #[test]
    fn eight_seed_words_never_clip() {
        // longest BIP39 English word is 8 chars: 8*8 + 7 spaces + 4 indent = 75 <= IN (75)
        let worst = ["abstract"; 8].join(" ");
        let row = mid(&format!("    {}", worst));
        assert!(strip(&row).contains("abstract abstract abstract abstract abstract abstract abstract abstract"),
            "seed row clipped: {:?}", strip(&row));
    }

    #[test]
    fn vis_and_clip() {
        let s = format!("{}abc{}def", crit(), r());
        assert_eq!(vis(&s), 6);
        assert_eq!(vis(&clip(&s, 4)), 4);
        assert_eq!(vis(&clip("plain", 99)), 5);
    }
}
