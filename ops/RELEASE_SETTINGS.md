# KeyRX release settings

The normal release control is a protected `vMAJOR.MINOR.PATCH` tag. Push the
reviewed version commit to `main`, then push that tag. `publish.yml` does the
rest in one run: read-only preparation first, then one sequential effect job.
There is no manual-dispatch release path and no temporary branch admission.

## One-time repository and provider settings

1. Keep GitHub **release immutability enabled** and protect `v*` tags from
   deletion or retargeting. Immutability is not an extra release action. The
   workflow creates a draft, uploads and checks all six assets, publishes it,
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
   requires at most one older unyanked release; after the new GitHub Release is
   immutable, it yanks exactly that measured predecessor and checks that only
   the new version remains installable.

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
dry run, and two byte-identical package builds. The effect job re-derives the
archive before acquiring provider authority, uses official `cargo publish`,
compares the registry download with the prepared archive, creates provenance
and a deterministic SBOM, validates the complete draft, publishes it, verifies
all remote asset digests and release immutability, and only then yanks the one
measured predecessor.

## Deliberate boundary

The built-in GitHub token cannot read the repository's Administration setting
for release immutability. Avoiding a permanent administration PAT means the
workflow verifies the property on the newly published release instead of
preflighting the repository setting. Keep the one-time setting enabled. If it
is changed, final verification fails loudly after publication; restoring that
repository setting is an operator action.

An exact rerun continues automatically from an empty draft, reuses and verifies
the complete six-asset set in an exact draft, or finishes the remaining registry
policy work after an immutable release. A partial draft is the one deliberate
manual boundary: inspect and delete only that inert draft, then rerun. An exact
already-published registry version is recognized and is never uploaded twice.
Existing release bytes are validated rather than overwritten, and a published
immutable release is never edited.
