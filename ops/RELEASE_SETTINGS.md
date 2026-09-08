# KeyRX release settings

The normal release control is a protected `vMAJOR.MINOR.PATCH` tag. Push the
reviewed version commit to `main`, then push that tag. `publish.yml` does the
rest in one run: read-only source preparation, an isolated read-only Linux/WSL
target-test job, a dependent read-only binary build, a final read-only binary
verification job, then one sequential effect job.
There is no manual-dispatch release path and no temporary branch admission.

## One-time repository and provider settings

1. Keep GitHub **release immutability enabled** and protect `v*` tags from
   deletion or retargeting. Immutability is not an extra release action. The
   workflow creates a draft, uploads and checks all ten assets, publishes it,
   and then requires the resulting release object to report `immutable: true`.
2. Keep the GitHub environment named `release` restricted to tags matching
   `v*`. The effect job uses that environment; ordinary branch pushes never do.
   The normal flow does not require temporarily adding `main`.
3. Keep the crates.io trusted publisher bound to repository `keyrx/keyrx`,
   workflow `.github/workflows/publish.yml`, and environment `release`. The
   official crates.io authentication action issues the short-lived publish
   token, which is passed directly to `cargo publish`.
4. Keep the existing yank-only crates.io token as the environment secret
   `CARGO_YANK_TOKEN`. It cannot publish. Before publishing, the workflow
   requires at most two older unyanked releases: the normal predecessor plus,
   at most, one predecessor left by an interrupted prior run. After the new
   GitHub Release is immutable, it rebinds and yanks exactly that measured set
   and checks that only the new version remains installable.

No repository-administration PAT is part of this design. In particular,
`GH_ADMIN_READ_TOKEN` is neither read nor required. GitHub's built-in job token
has only the `actions`, `contents`, `id-token`, and `attestations` permissions
declared by the workflow.

## Per-release procedure

1. Update `Cargo.toml`, the root `keyrx` entry in `Cargo.lock`, the one
   `VERSION` assignment in `site/index.html`, and the newest dated section in
   `CHANGELOG.md` to the same canonical version.
2. Run CI and review the exact commit.
3. Push that commit to `main`.
4. Create and push one tag with the same version, for example `v0.4.14`.

The tag must resolve to a commit on live `main`. The prepare job runs every Rust
test target, clippy, the real site harness, all release controls, Cargo's publish
dry run, and two byte-identical crate package builds. A separate read-only job
tests `x86_64-unknown-linux-musl` without creating a release handoff. The
read-only binary job builds twice with Rust 1.85 and `--locked`, then compares
both binaries and both deterministic archives before uploading one immutable
artifact ID. That archive supports Linux x86-64 and WSL; this workflow does not
claim native Windows or macOS support. The final read-only job downloads that
exact artifact ID, independently rebuilds and re-packages it, compares every
byte, and only then exercises the executable extracted from the archive as its
terminal step. It emits no identity after candidate execution. Its success
gates the effect job, which consumes the builder's original exact artifact ID
directly. The effect job never compiles or executes the candidate binary. It
re-derives the crate, verifies and assembles the already-tested binary handoff,
uses official `cargo publish`, compares the registry download with the prepared
crate, creates separate single-subject provenance for the crate and binary
archive plus the deterministic SBOM, validates the complete ten-asset draft,
publishes it, verifies all remote asset digests, binary provenance, and release
immutability, and only then yanks the exactly rebound predecessor set.

## Deliberate boundary

The built-in GitHub token cannot read the repository's Administration setting
for release immutability. Avoiding a permanent administration PAT means the
workflow verifies the property on the newly published release instead of
preflighting the repository setting. Keep the one-time setting enabled. If it
is changed, final verification fails loudly after publication; restoring that
repository setting is an operator action.

An exact rerun discovers drafts through the authenticated, fully paginated
release collection, binds one exact match by its numeric release ID, and then
continues automatically from an empty draft, reuses and verifies the complete
ten-asset set in an exact draft, or finishes the remaining registry policy work
after an immutable release. A partial draft is the one deliberate
manual boundary: inspect and delete only that inert draft, then rerun. An exact
already-published registry version is recognized and is never uploaded twice.
Existing release bytes are validated rather than overwritten, and a published
immutable release is never edited.
