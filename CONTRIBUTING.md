# Contributing

keyRX is small on purpose: one Rust binary, a few files, and a start screen that explains every
flag. Changes are welcome through GitHub: open an issue to report a bug or propose something, or
open a pull request with the change. There is no CLA and no invitation needed. Questions that are
not bug reports: dev@keyrx.tech. Vulnerabilities: security@keyrx.tech, see [SECURITY.md](SECURITY.md).

## What a change has to bring

- `cargo test --all-targets` green. The tests pin derivations against published vectors and an
  independent implementation, the matcher against its stated odds, the match file's format, and
  the width of every framed line the CLI draws. A change to any of those comes with the test
  that would have caught it being wrong.
- `cargo clippy --all-targets -- -D warnings` clean. Warnings are errors here.
- New functionality comes with tests of that functionality in the same change, not later.
- Nothing that prints a seed or a key to the terminal unless the user asked for it with a flag.
  Nothing that makes a network call at run time.
- If the change touches what the site says (`site/index.html`), the site says the same words
  as the CLI, and `node tests/site_harness.js` passes (every panel row fits both grids).
- No person's name in code, comments or docs. The project speaks as keyRX.
- A CHANGELOG entry under the next version, in plain words, saying what a user would notice.

CI runs the same tests and lints on every pull request (`.github/workflows/ci.yml`); publishing
runs them again on the tag. A pull request is reviewed and merged by the maintainer; the
reviewer reads the change, not only the green check.

## Releases

Versions follow SemVer and are tagged `vX.Y.Z`. A tag publishes the crate by trusted publishing,
attests the build, attaches the crate, its Sigstore bundle and an SBOM to the GitHub Release, and
yanks the release before it on crates.io so a fresh install can only land on the newest.
