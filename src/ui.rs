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

/// Walk a string, calling `f(ch, visible)` once per char. `visible` is false
/// for every char that belongs to an escape sequence: CSI/SGR (`ESC [ … final`)
/// and OSC (`ESC ] … BEL` or `ESC ] … ESC \`), the latter being the shape a
/// terminal hyperlink takes. Everything this module measures goes through here.
fn walk(s: &str, mut f: impl FnMut(char, bool)) {
    #[derive(Clone, Copy)]
    enum St { Text, Esc, Csi, Osc, OscEsc }
    let mut st = St::Text;
    for ch in s.chars() {
        match st {
            St::Text => { if ch == '\x1b' { st = St::Esc; f(ch, false); } else { f(ch, true); } }
            St::Esc => { f(ch, false); st = match ch { '[' => St::Csi, ']' => St::Osc, _ => St::Text }; }
            St::Csi => { f(ch, false); if ('@'..='~').contains(&ch) { st = St::Text; } }
            St::Osc => { f(ch, false); st = match ch { '\x07' => St::Text, '\x1b' => St::OscEsc, _ => St::Osc }; }
            St::OscEsc => { f(ch, false); st = if ch == '\\' { St::Text } else { St::Osc }; }
        }
    }
}

/// Visible width: characters, with escapes removed. Every glyph this module
/// emits is one column wide in a monospace font (no wide chars, no combining
/// marks), so char count is column count.
pub fn vis(s: &str) -> usize {
    let mut n = 0;
    walk(s, |_, v| if v { n += 1 });
    n
}

/// The text alone - every escape removed.
#[cfg_attr(not(test), allow(dead_code))]
pub fn plain(s: &str) -> String {
    let mut out = String::new();
    walk(s, |ch, v| if v { out.push(ch) });
    out
}

/// Clip a (possibly coloured, possibly linked) string to at most `n` visible
/// columns, keeping escapes intact, closing any hyperlink the cut left open,
/// and closing with a reset.
pub fn clip(s: &str, n: usize) -> String {
    if vis(s) <= n { return s.to_string(); }
    let mut out = String::new();
    let mut seen = 0;
    let mut stop = false;
    walk(s, |ch, v| {
        if stop { return; }
        if v {
            if seen >= n { stop = true; return; }
            seen += 1;
        }
        out.push(ch);
    });
    if link_open(&out) { out.push_str(LINK_END); }
    out.push_str(r());
    out
}

const LINK_END: &str = "\x1b]8;;\x1b\\";

/// Whether the last OSC 8 in `s` opened a link (carried a URL) rather than closed one.
fn link_open(s: &str) -> bool {
    let mut open = false;
    let mut rest = s;
    while let Some(i) = rest.find("\x1b]8;;") {
        let after = &rest[i + 5..];
        open = !(after.starts_with("\x1b\\") || after.starts_with('\x07'));
        rest = after;
    }
    open
}

/// A terminal hyperlink (OSC 8): `text` that opens `url` on click in terminals
/// that support it - Windows Terminal, VS Code, iTerm2, GNOME/VTE, kitty,
/// WezTerm, foot, Konsole - and plain `text` everywhere else, including piped
/// output, where no escape is ever emitted.
pub fn link(url: &str, text: &str) -> String {
    if on() { format!("\x1b]8;;{}\x1b\\{}{}", url, text, LINK_END) } else { text.to_string() }
}

/// A `file://` URL for a local path, in the form the terminal's host can open.
/// Under WSL the path lives inside the distro, so the URL is the UNC form Windows
/// understands - `file://wsl.localhost/<distro>/home/...` - which Explorer opens;
/// elsewhere `file:///home/...`.
pub fn file_url(p: &std::path::Path) -> String {
    let path = p.to_string_lossy();
    #[cfg(windows)]
    let path = format!("/{}", path.replace('\\', "/"));
    match std::env::var("WSL_DISTRO_NAME") {
        Ok(d) if !d.is_empty() => format!("file://wsl.localhost/{}{}", pct(&d), pct(&path)),
        _ => format!("file://{}", pct(&path)),
    }
}

/// Percent-encode everything outside the URL-safe set; `/` stays a separator.
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// A directory, printed as itself and clickable where the terminal allows it.
pub fn dir_link(p: &std::path::Path) -> String {
    link(&file_url(p), &p.display().to_string())
}

/// Whether links are being emitted at all (a terminal, no NO_COLOR) - the hint
/// below is printed only then, so piped output never mentions clicking.
pub fn links_on() -> bool { on() }

/// The one line that explains the links. Terminals differ on the modifier -
/// Windows Terminal, VS Code, GNOME and Konsole want ctrl, iTerm2 and VS Code on
/// a Mac want cmd, kitty and WezTerm take a plain click - so it names both.
pub const CLICK_HINT: &str = "ctrl/cmd-click a path to open the folder";

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
/// The mark: a seal, sealed on chain. Sixty-four hex digits on an 8x8 grid, a cell lit where the
/// digit is 8 or above. Two grid rows per text line in half-blocks: rows 0-3 blue, rows 4-7 amber.
/// The same glyph is the site's favicon and the repository's avatar; here it is text.
pub const SEAL: &str = "fbd454bdefee923628fcb6f24667b772ea942f176f9c7988b5e2d2264b335ac8";

/// Eight text lines, sixteen columns each (a lit cell is two full blocks, one grid row per line):
/// a terminal cell is about twice as tall as it is wide, so 16 x 8 is the mark's true square.
/// Coloured when stdout is a terminal.
pub fn seal_lines() -> [String; 8] {
    let lit: Vec<bool> = SEAL.bytes().map(|b| (b as char).to_digit(16).unwrap_or(0) >= 8).collect();
    let mut out: [String; 8] = Default::default();
    for (row, line) in out.iter_mut().enumerate() {
        let mut s = String::new();
        for c in 0..8 { s.push_str(if lit[row * 8 + c] { "██" } else { "  " }); }
        *line = format!("{}{}{}", if row < 4 { accent() } else { warn() }, s, r());
    }
    out
}

/// The one line, wrapped beside the seal (the seal is 16 columns; the text has the rest).
pub const SITE: &str = "keyRX.tech";
pub const CONTACT: &str = "dev@keyrx.tech";
pub const ABOUT: [&str; 4] = [
    "Solana and EVM vanity address grinder.",
    "One seed, unlimited addresses, keys for every wallet.",
    "Offline. Open. Verified.",
    "The mark is a record. What it seals comes next.",
];

pub fn masthead(right: &str) {
    let seal = seal_lines();
    let name = format!("{}{}keyRX{} {}|{} {}{}CLI{}", b(), wht(), r(), faint(), r(), b(), wht(), r());
    let head = format!(" {}  {}", seal[0], name);
    let rt = format!("{}{}{}", gry(), right, r());
    let gap = (W as isize - vis(&head) as isize - vis(&rt) as isize - 1).max(1) as usize;
    println!("\n{}{}{}", head, " ".repeat(gap), rt);
    for (i, l) in seal.iter().enumerate().skip(1) {
        match i {
            1 => println!(" {}  {}{}{}", l, gry(), ABOUT[0], r()),
            2 => println!(" {}  {}{}{}", l, gry(), ABOUT[1], r()),
            3 => println!(" {}  {}{}{}", l, gry(), ABOUT[2], r()),
            5 => println!(" {}  {}{}{}", l, faint(), ABOUT[3], r()),
            7 => {
                // the bottom line: the site at the text column, the contact at the right edge
                let left = format!(" {}  {}{}{}", l, gry(), SITE, r());
                let right = format!("{}{}{}", gry(), CONTACT, r());
                let gap = (W as isize - vis(&left) as isize - vis(&right) as isize - 1).max(1) as usize;
                println!("{}{}{}", left, " ".repeat(gap), right);
            }
            _ => println!(" {}", l),
        }
    }
    println!(" {}{}{}", faint(), "━".repeat(W - 2), r());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_about_lines_fit_beside_the_seal() {
        for l in ABOUT { assert!(l.len() <= W - 1 - 16 - 2, "{}", l); }
        assert_eq!(ABOUT.join(" "), "Solana and EVM vanity address grinder. One seed, unlimited addresses, keys for every wallet. Offline. Open. Verified. The mark is a record. What it seals comes next.");
    }

    #[test]
    fn seal_is_eight_lines_of_sixteen_columns_lit_where_the_digit_is_eight_or_more() {
        let l = seal_lines();
        assert!(l.iter().all(|x| vis(x) == 16));
        let strip = |x: &str| plain(x);
        for (r, line) in l.iter().enumerate() {
            let plain = strip(line);
            for c in 0..8 {
                let lit = SEAL.as_bytes()[r * 8 + c] as char >= '8';
                let cell: String = plain.chars().skip(c * 2).take(2).collect();
                assert_eq!(cell, if lit { "██" } else { "  " }, "row {} col {}", r, c);
            }
        }
        assert_eq!(SEAL.bytes().filter(|b| (*b as char).to_digit(16).unwrap() >= 8).count(), 33);
    }

    fn frame_lines(s: &str) -> Vec<&str> {
        s.lines().filter(|l| {
            let p = strip(l);
            let t = p.trim_start();
            t.starts_with('╔') || t.starts_with('║') || t.starts_with('╚')
        }).collect()
    }

    fn strip(s: &str) -> String { plain(s) }

    #[test]
    fn links_measure_as_their_text_and_never_widen_a_frame() {
        // The URL has an 'm' in it on purpose: the old escape scanner stopped at
        // the first 'm' and would have counted half a URL as visible text. "home" and
        // "matches" both carry one, so no real account name is needed here and none
        // belongs here: src/ ships inside the published crate.
        let url = "file://wsl.localhost/Ubuntu/home/example/.local/share/keyrx/matches";
        let l = format!("\x1b]8;;{}\x1b\\matches\x1b]8;;\x1b\\", url);
        assert_eq!(vis(&l), "matches".len());
        assert_eq!(plain(&l), "matches");
        let bel = format!("\x1b]8;;{}\x07matches\x1b]8;;\x07", url);
        assert_eq!(vis(&bel), "matches".len());
        for line in frame_lines(&format!("{}\n{}\n{}", top("T", &l), mid(&format!("  in {}", l)), bot(&format!("in {}", l)))) {
            assert_eq!(strip(line).chars().count(), W, "ragged: {:?}", strip(line));
        }
        // clipping through a link closes it before the reset, so the rest of the
        // row can never be swallowed into the URL's click target
        let long = format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, "m".repeat(200));
        let c = clip(&long, 10);
        assert_eq!(vis(&c), 10);
        assert!(c.ends_with(&format!("\x1b]8;;\x1b\\{}", r())), "{:?}", c);
        assert_eq!(vis(&clip("abc", 10)), 3);
    }

    #[test]
    fn file_urls_are_percent_encoded_and_wsl_aware() {
        assert_eq!(pct("/home/me/a b/ü"), "/home/me/a%20b/%C3%BC");
        let u = file_url(std::path::Path::new("/home/me/.local/share/keyrx/matches"));
        match std::env::var("WSL_DISTRO_NAME") {
            Ok(d) if !d.is_empty() => assert_eq!(u, format!("file://wsl.localhost/{}/home/me/.local/share/keyrx/matches", pct(&d))),
            _ => assert_eq!(u, "file:///home/me/.local/share/keyrx/matches"),
        }
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
