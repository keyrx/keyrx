# Release settings required outside this repository

`publish.yml` fails closed when repository-visible state disagrees, but five
authority boundaries cannot be created or proven by code running in the same
repository. Configure and independently review them before creating `v0.4.13`.

1. **Protected GitHub environment `release`.** Require a human reviewer and do
   not allow self-review. Restrict deployments to protected refs. The privileged
   `effect` job is the only job attached to this environment. The tag supplies
   `publish.yml` itself, including its inline effect shell and job graph; before
   approval, the reviewer must independently resolve `SOURCE_SHA`, read the exact
   `.github/workflows/publish.yml` Git blob at that commit, compare it with the
   reviewed candidate, and verify that the run names the same full SHA. Binding
   the environment or trusted publisher to a workflow pathname alone does not
   make tag-supplied orchestration trusted. A reusable effect workflow pinned to
   a separately protected ref or repository would be a stronger future boundary.
2. **crates.io trusted publisher.** Bind `keyrx` publishing to
   `keyrx/keyrx`, `.github/workflows/publish.yml`, and environment `release`.
   The OIDC token is requested only after the exact draft assets and provenance
   have been downloaded and verified.
3. **Yank-only credential.** Store a crates.io token scoped to yanking `keyrx`
   as the `release` environment secret `CARGO_YANK_TOKEN`. It is not used for
   publishing. Its custody, rotation, and reviewer access remain operator work.
4. **Repository rules and immutable releases.** Protect `main`, protect `v*`
   tags from deletion or retargeting, and enable GitHub immutable releases. The
   workflow checks the immutable-release capability. Before any registry effect
   it requires live `main` to equal the prepared source SHA. After the exact
   registry version exists, a resume accepts only a still-exact protected tag
   plus API-proven ancestry showing that `SOURCE_SHA` is the merge base and
   ancestor of current `main`; divergent history remains a refusal. It cannot
   install or authenticate those administrative rules itself. Store a
   fine-grained, read-only token with repository Administration read permission
   as the `release` environment secret `GH_ADMIN_READ_TOKEN`; the ordinary
   workflow token cannot read this administrative capability endpoint.
5. **Exclusive Release writer and ceremony branch.** From environment approval
   through final immutable reread, no person, bot, workflow, or integration may
   create, edit, upload to, publish, or delete the `v0.4.13` GitHub Release. The
   workflow re-fetches and revalidates the full draft immediately before PATCH,
   but GitHub documents no conditional `If-Match` contract for that PATCH. The
   remaining close-read-to-PATCH interval is therefore an external custody
   requirement, not repository-enforced atomicity. Keep the ceremony on the
   protected tag/source lineage and authorize no concurrent release writer.

The privileged job does not accept semantic equivalence as the crate identity.
Before any provider attestation or draft, trusted inline code materializes only
the independently fetched raw package-input blobs using exclusive no-follow
descriptors. System Git fetches the peeled commit objects but performs no
worktree checkout; its isolated index marks every non-package path skip-worktree.
The pinned Rust 1.85.0 Cargo performs
`package --locked --no-verify` in isolated Cargo/target directories, and the two
complete `.crate` byte strings must be identical. `--no-verify` does not compile
or run a build script, test, or repository executable. This independently binds
Cargo's generated manifest and VCS JSON serialization, raw tar headers/order/
padding/mtimes, and its complete gzip header and deflate stream, not merely the
decoded member meanings. Root or nested `.gitattributes`, `.lfsconfig`, and
`.gitmodules` are refused case-insensitively before materialization, and Git
system/global configuration is disabled, so clean/smudge/LFS filters, hooks,
attributes, symlinks, submodules, and checkout paths never process source bytes.

This reproducibility step retains two explicit read-only supply-chain trusts.
Rust 1.85.0 is installed only from `https://static.rust-lang.org` and its Cargo
version string is pinned. Cargo runs under `env -i`, with an empty isolated
Cargo home and an explicit `sparse+https://index.crates.io/` source; the admitted
lock requires every non-root package to carry the standard crates.io registry
source plus a checksum. Crate downloads selected by that reviewed index may come
from crates.io's download service. The candidate manifest, lock, repository
configuration, process environment, and handoff cannot select another endpoint.
These are outbound reads, not release/provider writes, and they remain external
Rust-distribution and crates.io availability/integrity boundaries.

An exact inert draft containing one through five assets is deliberately not
repaired automatically. The workflow proves it is the canonical upload-order
prefix, prints `manual recovery required`, and stops before registry authority.
An authorized `release`-environment reviewer must independently verify and
delete that one draft, then rerun only after the tag's release cardinality is
zero. A non-prefix, changed identity, or changed metadata is not a recovery
candidate and remains an unconditional refusal.

A rerun starts from the same seven-file unprivileged handoff; it does not assume
that prior-run provenance survived locally. For an exact six-asset draft or
published release, the effect job downloads all six remote assets, revalidates
their API identities and bytes, manifest coverage, DSSE relationship, and
provider attestation, and only then stages the three verified provenance files
into its held effective set. Initial states instead require those three files to
be the bytes created during the current approved run. Published resumes also
require GitHub's `/releases/latest` endpoint to name the exact immutable release
before any reviewed yank proceeds.

The reviewed `ops/release/0.4.13.json` policy records the registry facts measured
for this release: the only live predecessor is `0.4.12`, its crates.io checksum
is `dcf2ff724aa2d0ec43173a2d1a7f225ea39efa8c5d61e43b02c82b26a4f7854d`, and it
is the only authorized yank target. Registry state is volatile, so the effect
job re-reads it before attestation, registry upload, and yanking and refuses any
extra, missing, or newer version.

`v0.4.12` predates the immutable six-asset baseline and has no GitHub Release.
The 0.4.13 policy contains one explicit `legacy-crate-tag` migration record. It
requires that absence, the exact unyanked crates.io trust-publisher tuple, the
exact lightweight tag, checksum, downloaded crate, bounded eleven-member archive
manifest, VCS SHA/path, and Cargo.toml.orig identity measured for 0.4.12. The
contract hard-codes that legacy mode as valid only for the exact 0.4.12 to 0.4.13
transition. 0.4.13 becomes the first immutable six-asset baseline; later policies
must use `immutable-six-asset`. This file does not authorize creating historical
evidence, a tag, release, registry upload, or yank.
