//! No em-dashes, no en-dashes, anywhere a reader meets this project: the CLI's own frames are
//! guarded at runtime by ui::banned (that list is the one place the glyphs may appear), and this
//! test covers everything else that ships or is read beside it: the source, the site's <head>,
//! the README, the changelog, the trademark notes and the asset licence. A dash that "sneaks in"
//! is a build failure, not a thing somebody notices on a phone.
use std::fs;

const FILES: &[&str] = &[
    "src/main.rs",
    "src/ui.rs",
    "site/index.html",
    "README.md",
    "CHANGELOG.md",
    "TRADEMARK.md",
    "assets/LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
];

#[test]
fn no_em_or_en_dash_anywhere_a_reader_meets_it() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut hits = Vec::new();
    for f in FILES {
        let path = format!("{root}/{f}");
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            // the one sanctioned occurrence: the list of banned glyphs itself
            if line.contains("let banned = [") {
                continue;
            }
            if line.contains('\u{2014}') || line.contains('\u{2013}') {
                hits.push(format!("{f}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(hits.is_empty(), "em/en-dash found:\n{}", hits.join("\n"));
}
