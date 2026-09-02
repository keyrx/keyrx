import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
    encoding="utf-8"
)
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
CURRENT_VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"][
    "version"
]


def load(name):
    path = ROOT / "ops" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


generate_sbom = load("generate_sbom")
registry_state = load("registry_state")
release_lookup = load("release_lookup")
release_state = load("release_state")


def workflow_run(name):
    """Return the exact shell body owned by a named shipping workflow step."""
    marker = f"      - name: {name}\n"
    start = WORKFLOW.index(marker) + len(marker)
    end = WORKFLOW.find("\n      - name: ", start)
    if end < 0:
        end = len(WORKFLOW)
    step = WORKFLOW[start:end]
    run_marker = "        run: |\n"
    body_start = step.index(run_marker) + len(run_marker)
    lines = []
    for line in step[body_start:].splitlines():
        if line.startswith("          "):
            lines.append(line[10:])
        elif not line:
            lines.append("")
        else:
            break
    if not lines:
        raise AssertionError(f"workflow step {name!r} has no shell body")
    return "\n".join(lines) + "\n"


def workflow_if(name):
    marker = f"      - name: {name}\n"
    start = WORKFLOW.index(marker) + len(marker)
    end = WORKFLOW.find("\n      - name: ", start)
    if end < 0:
        end = len(WORKFLOW)
    step = WORKFLOW[start:end]
    for line in step.splitlines():
        if line.startswith("        if: "):
            return line.removeprefix("        if: ")
    return "always"


def condition_applies(expression, release_state_value, predecessors):
    if expression == "always":
        return True
    for clause in expression.split(" || "):
        if clause.startswith("steps.release.outputs.state "):
            _, operator, expected = clause.rsplit(" ", 2)
            expected = expected.strip("'")
            result = release_state_value == expected
            if (operator == "==" and result) or (operator == "!=" and not result):
                return True
        elif clause in {
            "steps.registry.outputs.predecessors != '[]'",
        }:
            if predecessors:
                return True
        else:
            raise AssertionError(f"unsupported workflow condition {clause!r}")
    return False


def write_executable(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def write_fake_jq(path):
    write_executable(
        path,
        """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
mode = args.pop(0) if args and args[0] in ("-r", "-c", "-er") else ""
expression, source = args
with open(source, encoding="utf-8") as handle:
    value = json.load(handle)
if expression == ".state":
    print(value["state"])
elif expression == ".predecessor":
    print(value["predecessor"])
elif expression == ".predecessors":
    print(json.dumps(value["predecessors"], separators=(",", ":")))
elif expression == ".predecessors[]":
    for predecessor in value["predecessors"]:
        print(predecessor)
elif expression == ".release_id":
    print(value["release_id"])
elif expression == ".assets[] | [.id,.name,.url] | @tsv":
    for row in value["assets"]:
        print(f'{row["id"]}\\t{row["name"]}\\t{row["url"]}')
elif expression == ".dsseEnvelope":
    print(json.dumps(value["dsseEnvelope"], separators=(",", ":")))
else:
    raise SystemExit(f"unsupported fixture jq expression: {expression}")
""",
    )


class WorkflowShapeTests(unittest.TestCase):
    def test_release_is_tag_only_and_has_one_sequential_effect_lane(self):
        trigger = WORKFLOW.split("concurrency:", 1)[0]
        self.assertIn('tags: ["v*"]', trigger)
        self.assertNotIn("workflow_dispatch", trigger)
        self.assertEqual(WORKFLOW.count("\n  prepare:\n"), 1)
        self.assertEqual(WORKFLOW.count("\n  effect:\n"), 1)
        self.assertIn("    needs: prepare\n", WORKFLOW)
        self.assertIn("    environment: release\n", WORKFLOW)

    def test_one_off_recovery_and_admin_auth_are_gone(self):
        forbidden = (
            "GH_ADMIN_READ_TOKEN",
            "immutable-releases",
            "RECOVERY_BASE_SHA",
            "workflow_dispatch",
            "crates_upload.py",
            "crates-api-upload",
            "release_contract.py",
            "ops/release/0.4.13.json",
            "temporarily admit",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, WORKFLOW)
        self.assertNotRegex(WORKFLOW, r"\b0\.4\.(?:12|13)\b")

    def test_publish_uses_official_short_lived_token_and_cargo(self):
        auth = WORKFLOW.index("rust-lang/crates-io-auth-action@")
        publish = WORKFLOW.index("cargo publish --locked --no-verify --registry crates-io", auth)
        registry_verify = WORKFLOW.index(
            "Verify crates.io serves the exact prepared archive", publish
        )
        release = WORKFLOW.index("Create the inert draft", registry_verify)
        self.assertLess(auth, publish)
        self.assertLess(publish, registry_verify)
        self.assertLess(registry_verify, release)
        self.assertIn("CARGO_REGISTRY_TOKEN: ${{ steps.crates-auth.outputs.token }}", WORKFLOW)
        self.assertNotIn("secrets.CARGO_REGISTRY_TOKEN", WORKFLOW)
        self.assertIn(
            'cargo publish --dry-run --locked --registry crates-io',
            WORKFLOW,
        )
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(manifest["package"]["publish"], ["crates-io"])

    def test_effect_rechecks_live_tag_and_main_before_any_provider_effect(self):
        effect = WORKFLOW.split("\n  effect:\n", 1)[1]
        live_tag = effect.index("+refs/tags/$TAG:refs/keyrx-release/live-tag")
        ancestry = effect.index(
            'git merge-base --is-ancestor "$SOURCE_SHA" refs/remotes/origin/main',
            live_tag,
        )
        auth = effect.index("rust-lang/crates-io-auth-action@", ancestry)
        self.assertLess(live_tag, ancestry)
        self.assertLess(ancestry, auth)

    def test_privileges_are_narrow_and_builtin_github_token_is_used(self):
        prepare = WORKFLOW.split("  prepare:\n", 1)[1].split("\n  effect:\n", 1)[0]
        effect = WORKFLOW.split("\n  effect:\n", 1)[1]
        self.assertIn("      contents: read", prepare)
        self.assertNotIn("contents: write", prepare)
        self.assertIn("      contents: write", effect)
        self.assertIn("      actions: read", effect)
        self.assertIn("      id-token: write", effect)
        self.assertIn("      attestations: write", effect)
        self.assertNotIn("\n      GH_TOKEN: ${{ github.token }}\n", effect.split("    steps:", 1)[0])
        self.assertIn("GH_TOKEN: ${{ github.token }}", effect)
        self.assertNotIn("secrets.GITHUB_TOKEN", effect)
        for name in (
            "Reuse complete provenance from an exact prior run",
            "Publish the exact draft",
            "Verify the immutable release and every attached digest",
        ):
            with self.subTest(name=name):
                block = workflow_run(name)
                if "ops/" in block:
                    self.assertLess(block.index("unset GH_TOKEN"), block.index("ops/"))

    def test_release_is_drafted_validated_published_and_verified_immutable(self):
        draft = WORKFLOW.index("Create the inert draft")
        upload = WORKFLOW.index("Upload the complete asset set", draft)
        validate = WORKFLOW.index("Validate the complete draft", upload)
        publish = WORKFLOW.index("Publish the exact draft", validate)
        final = WORKFLOW.index("Verify the immutable release", publish)
        yank = WORKFLOW.index("Yank the exactly rebound predecessors", final)
        self.assertLess(draft, upload)
        self.assertLess(upload, validate)
        self.assertLess(validate, publish)
        self.assertLess(publish, final)
        self.assertLess(final, yank)
        self.assertIn("ops/release_state.py", WORKFLOW)
        self.assertIn("published release is not immutable", (ROOT / "ops/release_state.py").read_text())
        self.assertIn("gh attestation verify", WORKFLOW)
        self.assertIn('--source-digest "$SOURCE_SHA"', WORKFLOW)
        self.assertIn("gh release verify", WORKFLOW)
        self.assertIn('"$TAG" --repo "$GITHUB_REPOSITORY"', WORKFLOW)
        bind_final = WORKFLOW.index("Bind the final release identity", publish)
        self.assertLess(publish, bind_final)
        self.assertLess(bind_final, final)
        self.assertIn(
            "steps.final_identity.outputs.release_id",
            WORKFLOW[bind_final:yank],
        )
        publish_block = workflow_run("Publish the exact draft")
        self.assertIn("published-release.json", publish_block)
        self.assertIn("unset GH_TOKEN", publish_block)
        self.assertIn("ops/release_state.py", publish_block)

    def test_drafts_are_enumerated_and_fetched_by_release_id(self):
        enumerate_releases = WORKFLOW.index("Enumerate every release including inert drafts")
        select = WORKFLOW.index("Select the exact release tag from every page", enumerate_releases)
        fetch = WORKFLOW.index("Fetch the selected release by immutable API identity", select)
        inspect = WORKFLOW.index("Inspect any release left by an exact rerun", fetch)
        draft_identity = WORKFLOW.index("Select exactly one draft identity", inspect)
        empty_fetch = WORKFLOW.index(
            "Fetch the selected empty draft by immutable API identity", draft_identity
        )
        empty_validate = WORKFLOW.index(
            "Validate the selected draft is empty before upload", empty_fetch
        )
        upload = WORKFLOW.index(
            "Upload the complete asset set to the exact empty draft", empty_validate
        )
        draft_fetch = WORKFLOW.index("Fetch the complete draft by immutable API identity", draft_identity)
        draft_validate = WORKFLOW.index("Validate the complete draft before publication", draft_fetch)
        final = WORKFLOW.index("Verify the immutable release", draft_validate)
        self.assertLess(enumerate_releases, select)
        self.assertLess(select, fetch)
        self.assertLess(fetch, inspect)
        self.assertLess(draft_identity, empty_fetch)
        self.assertLess(empty_fetch, empty_validate)
        self.assertLess(empty_validate, upload)
        self.assertLess(upload, draft_fetch)
        self.assertLess(draft_identity, draft_fetch)
        self.assertLess(draft_fetch, draft_validate)
        self.assertIn("releases?per_page=100", WORKFLOW[enumerate_releases:select])
        self.assertRegex(
            WORKFLOW[enumerate_releases:select],
            r"(?m)^[ \t]*gh api --paginate(?:[ \t]|$)",
        )
        self.assertIn("ops/release_lookup.py", WORKFLOW[select:fetch])
        self.assertIn("releases/$release_id", WORKFLOW[fetch:inspect])
        self.assertIn("releases/$release_id", WORKFLOW[draft_fetch:draft_validate])
        upload_block = workflow_run("Upload the complete asset set to the exact empty draft")
        self.assertIn("releases/$release_id/assets", upload_block)
        self.assertIn("--data-binary", upload_block)
        self.assertNotIn("gh release upload", WORKFLOW)
        self.assertNotIn("releases/tags/$TAG", WORKFLOW[enumerate_releases:final])
        self.assertIn("releases/tags/$TAG", WORKFLOW[final:])

    def test_every_public_effect_follows_registry_and_release_admission(self):
        registry = WORKFLOW.index("Classify the registry before requesting publish authority")
        release = WORKFLOW.index("Inspect any release left by an exact rerun", registry)
        reuse = WORKFLOW.index("Reuse complete provenance from an exact prior run", release)
        auth = WORKFLOW.index("Obtain a short-lived crates.io publish token", reuse)
        publish = WORKFLOW.index("cargo publish --locked --no-verify --registry crates-io", auth)
        attest = WORKFLOW.index("Attest the exact registry archive", publish)
        draft = WORKFLOW.index("Create the inert draft", attest)
        self.assertLess(registry, release)
        self.assertLess(release, reuse)
        self.assertLess(reuse, auth)
        self.assertLess(auth, publish)
        self.assertLess(publish, attest)
        self.assertLess(attest, draft)

    def test_registry_identity_is_bound_before_release_and_before_yank(self):
        release = WORKFLOW.index("Reuse complete provenance")
        first = WORKFLOW.index("Verify crates.io serves the exact prepared archive", release)
        rebind = WORKFLOW.index(
            "Rebind the measured predecessors immediately before yank", first
        )
        yank_step = WORKFLOW.index("Yank the exactly rebound predecessors", rebind)
        yank = WORKFLOW.index(
            'cargo yank "$CRATE_NAME" --vers "$predecessor" --registry crates-io',
            rebind,
        )
        first_trust = WORKFLOW.index("--trusted-repository", first)
        second_trust = WORKFLOW.index("--trusted-repository", rebind)
        self.assertLess(release, first_trust)
        self.assertLess(first_trust, rebind)
        self.assertLess(second_trust, yank)
        self.assertLess(rebind, yank_step)
        self.assertNotIn("CARGO_YANK_TOKEN", WORKFLOW[rebind:yank_step])
        self.assertIn('"$GITHUB_REPOSITORY"', WORKFLOW[first_trust:rebind])
        self.assertIn('"$SOURCE_SHA"', WORKFLOW[first_trust:rebind])

    def test_exact_release_states_reuse_provenance_and_partial_refuses(self):
        inspect = WORKFLOW.index("Inspect any release left by an exact rerun")
        reuse = WORKFLOW.index("Reuse complete provenance from an exact prior run", inspect)
        attest = WORKFLOW.index("Attest the exact registry archive", reuse)
        self.assertLess(inspect, reuse)
        self.assertLess(reuse, attest)
        self.assertIn("draft-partial", WORKFLOW[inspect:reuse])
        self.assertIn("draft-exact", WORKFLOW[reuse:attest])
        self.assertIn("published", WORKFLOW[reuse:attest])
        self.assertIn("state == 'absent' || steps.release.outputs.state == 'draft-empty'", WORKFLOW)

    def test_release_state_conditions_select_the_exact_retry_path(self):
        steps = {
            "reuse": "Reuse complete provenance from an exact prior run",
            "attest": "Attest the exact registry archive when no complete release exists",
            "complete": "Complete and validate a new six-asset set",
            "create": "Create the inert draft when no release exists",
            "empty-fetch": "Fetch the selected empty draft by immutable API identity",
            "empty-validate": "Validate the selected draft is empty before upload",
            "upload": "Upload the complete asset set to the exact empty draft",
            "validate": "Validate the complete draft before publication",
            "publish": "Publish the exact draft",
            "final": "Verify the immutable release and every attached digest",
            "rebind": "Rebind the measured predecessors immediately before yank",
            "yank": "Yank the exactly rebound predecessors",
        }

        def selected(state, predecessors):
            return {
                key
                for key, name in steps.items()
                if condition_applies(workflow_if(name), state, predecessors)
            }

        self.assertEqual(
            selected("draft-exact", "1.2.2"),
            {"reuse", "validate", "publish", "final", "rebind", "yank"},
        )
        self.assertEqual(
            selected("published", "1.2.2"),
            {"reuse", "final", "rebind", "yank"},
        )
        self.assertEqual(selected("published", ""), {"reuse", "final"})
        self.assertEqual(
            selected("absent", "1.2.2"),
            {
                "attest",
                "complete",
                "create",
                "empty-fetch",
                "empty-validate",
                "upload",
                "validate",
                "publish",
                "final",
                "rebind",
                "yank",
            },
        )
        draft_empty_without_predecessors = {
            "attest",
            "complete",
            "empty-fetch",
            "empty-validate",
            "upload",
            "validate",
            "publish",
            "final",
        }
        self.assertEqual(
            selected("draft-empty", ""), draft_empty_without_predecessors
        )
        self.assertEqual(
            selected("draft-empty", "1.2.2"),
            draft_empty_without_predecessors | {"rebind", "yank"},
        )
        self.assertEqual(
            workflow_if("Yank the exactly rebound predecessors"),
            "steps.registry.outputs.predecessors != '[]'",
        )

    def test_exact_six_assets_are_named_once_by_the_validator(self):
        names = release_state.required_assets("1.2.3")
        self.assertEqual(len(names), 6)
        self.assertEqual(len(set(names)), 6)
        self.assertEqual(names[-1], "keyrx-1.2.3.SHA256SUMS")

    def test_preparation_and_ci_own_release_and_site_controls(self):
        self.assertIn("node tests/site_harness.js site/index.html", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s tests -p 'test_release_*.py'", WORKFLOW)
        self.assertIn("node tests/site_harness.js site/index.html", CI)
        self.assertIn("python3 -m unittest discover -s tests -p 'test_release_*.py'", CI)

    def test_only_yank_credential_remains_long_lived(self):
        secret_references = {
            line.strip()
            for line in WORKFLOW.splitlines()
            if "${{ secrets." in line
        }
        self.assertEqual(
            secret_references,
            {"CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_YANK_TOKEN }}"},
        )


class RegistryStateTests(unittest.TestCase):
    CHECKSUM = "a" * 64

    def payload(self, *rows):
        return {"versions": list(rows)}

    def row(self, version, *, yanked=False, checksum=None):
        return {"num": version, "yanked": yanked, "checksum": checksum}

    def test_absent_version_records_up_to_two_live_predecessors_newest_first(self):
        result = registry_state.classify(
            self.payload(
                self.row("1.2.2", checksum="b" * 64),
                self.row("1.2.0", yanked=True, checksum="d" * 64),
                self.row("1.2.1", checksum="c" * 64),
            ),
            "1.2.3",
            self.CHECKSUM,
        )
        self.assertEqual(
            result,
            {"state": "absent", "predecessors": ["1.2.2", "1.2.1"]},
        )

    def test_exact_existing_version_is_a_safe_rerun(self):
        result = registry_state.classify(
            self.payload(self.row("1.2.3", checksum=self.CHECKSUM)),
            "1.2.3",
            self.CHECKSUM,
        )
        self.assertEqual(result, {"state": "exact", "predecessors": []})

    def test_github_output_encodes_predecessor_set_as_compact_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "registry.json"
            output = root / "github-output"
            payload.write_text(
                json.dumps(
                    self.payload(
                        self.row("1.2.2", checksum="b" * 64),
                        self.row("1.2.1", checksum="c" * 64),
                    )
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                registry_state.main(
                    [str(payload), "1.2.3", self.CHECKSUM, "--github-output", str(output)]
                ),
                0,
            )
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                'state=absent\npredecessors=["1.2.2","1.2.1"]\n',
            )

    def test_wrong_current_newer_or_more_than_one_interrupted_release_is_refused(self):
        cases = (
            self.payload(self.row("1.2.3", checksum="b" * 64)),
            self.payload(
                self.row("1.2.2", checksum="b" * 64),
                self.row("1.2.1", checksum="c" * 64),
                self.row("1.2.0", checksum="d" * 64),
            ),
            self.payload(self.row("1.2.4", checksum="b" * 64)),
            self.payload(self.row("1.2.4", yanked=True, checksum="b" * 64)),
            self.payload(self.row("1.2.3", yanked=True, checksum=self.CHECKSUM)),
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(registry_state.RegistryError):
                registry_state.classify(payload, "1.2.3", self.CHECKSUM)

    def test_trusted_version_binds_registry_bytes_and_github_execution(self):
        payload = {
            "version": {
                "crate": "keyrx",
                "num": "1.2.3",
                "yanked": False,
                "checksum": self.CHECKSUM,
                "trustpub_data": {
                    "provider": "github",
                    "repository": "keyrx/keyrx",
                    "run_id": "123456",
                    "sha": "1" * 40,
                },
            }
        }
        self.assertEqual(
            registry_state.validate_trusted_version(
                payload,
                "1.2.3",
                self.CHECKSUM,
                "keyrx",
                "keyrx/keyrx",
                "1" * 40,
            ),
            {"state": "trusted", "run_id": "123456"},
        )
        mutations = (
            ("crate", "other"),
            ("num", "1.2.4"),
            ("yanked", True),
            ("checksum", "b" * 64),
        )
        for field, value in mutations:
            changed = copy.deepcopy(payload)
            changed["version"][field] = value
            with self.subTest(field=field), self.assertRaises(registry_state.RegistryError):
                registry_state.validate_trusted_version(
                    changed,
                    "1.2.3",
                    self.CHECKSUM,
                    "keyrx",
                    "keyrx/keyrx",
                    "1" * 40,
                )
        trust_mutations = (
            ("provider", "other"),
            ("repository", "other/repo"),
            ("run_id", "0"),
            ("run_id", 123456),
            ("sha", "2" * 40),
        )
        for field, value in trust_mutations:
            changed = copy.deepcopy(payload)
            changed["version"]["trustpub_data"][field] = value
            with self.subTest(trust_field=field), self.assertRaises(
                registry_state.RegistryError
            ):
                registry_state.validate_trusted_version(
                    changed,
                    "1.2.3",
                    self.CHECKSUM,
                    "keyrx",
                    "keyrx/keyrx",
                    "1" * 40,
                )

    def test_trusted_version_refuses_missing_identity(self):
        for payload in ({}, {"version": {}}, {"version": {"trustpub_data": {}}}):
            with self.subTest(payload=payload), self.assertRaises(
                registry_state.RegistryError
            ):
                registry_state.validate_trusted_version(
                    payload,
                    "1.2.3",
                    self.CHECKSUM,
                    "keyrx",
                    "keyrx/keyrx",
                    "1" * 40,
                )


class ReleaseLookupTests(unittest.TestCase):
    def test_draft_on_later_page_is_selected_and_unrelated_releases_are_ignored(self):
        pages = release_lookup.parse_pages(
            '[{"id":1,"tag_name":"v1.2.2"}]\n'
            '[{"id":42,"tag_name":"v1.2.3"}]\n'
        )
        self.assertEqual(release_lookup.select_release_id(pages, "v1.2.3"), 42)

    def test_missing_exact_tag_is_absent(self):
        pages = release_lookup.parse_pages('[{"id":1,"tag_name":"v1.2.2"}]\n[]\n')
        self.assertIsNone(release_lookup.select_release_id(pages, "v1.2.3"))

    def test_duplicate_exact_tag_is_refused_across_pages(self):
        pages = release_lookup.parse_pages(
            '[{"id":41,"tag_name":"v1.2.3"}]\n'
            '[{"id":42,"tag_name":"v1.2.3"}]\n'
        )
        with self.assertRaises(release_lookup.ReleaseLookupError):
            release_lookup.select_release_id(pages, "v1.2.3")

    def test_malformed_pagination_rows_tags_ids_and_trailing_bytes_refuse(self):
        malformed_pages = ("", "{}", "[] trailing", '[{"tag_name":"v1.2.3"')
        for text in malformed_pages:
            with self.subTest(text=text), self.assertRaises(
                release_lookup.ReleaseLookupError
            ):
                release_lookup.parse_pages(text)
        cases = (
            [["not an object"]],
            [[{"id": 42}]],
            [[{"id": 0, "tag_name": "v1.2.3"}]],
            [[{"id": True, "tag_name": "v1.2.3"}]],
            [[{"id": "42", "tag_name": "v1.2.3"}]],
        )
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaises(
                release_lookup.ReleaseLookupError
            ):
                release_lookup.select_release_id(pages, "v1.2.3")
        with self.assertRaises(release_lookup.ReleaseLookupError):
            release_lookup.select_release_id([[]], "1.2.3")

    def test_cli_writes_only_typed_state_and_positive_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pages = root / "pages.jsons"
            output = root / "github-output"
            pages.write_text('[{"id":42,"tag_name":"v1.2.3"}]\n', encoding="utf-8")
            self.assertEqual(
                release_lookup.main(
                    [str(pages), "v1.2.3", "--github-output", str(output)]
                ),
                0,
            )
            self.assertEqual(output.read_text(encoding="utf-8"), "state=found\nrelease_id=42\n")


class ReleaseStateTests(unittest.TestCase):
    VERSION = "1.2.3"
    SOURCE = "1" * 40
    NOTES = "- exact notes\n"

    def fixture(self, root, state="published"):
        assets = []
        for index, name in enumerate(release_state.required_assets(self.VERSION), 1):
            data = f"asset {index}\n".encode()
            (root / name).write_bytes(data)
            assets.append(
                {
                    "id": index,
                    "name": name,
                    "url": f"https://api.github.test/releases/assets/{index}",
                    "size": len(data),
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "state": "uploaded",
                }
            )
        return {
            "id": 42,
            "tag_name": f"v{self.VERSION}",
            "target_commitish": self.SOURCE,
            "name": f"keyrx {self.VERSION}",
            "body": self.NOTES,
            "draft": state == "draft",
            "prerelease": False,
            "immutable": state == "published",
            "published_at": None if state == "draft" else "2026-09-02T00:00:00Z",
            "assets": assets,
        }

    def test_exact_draft_and_published_release_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for state in ("draft", "published"):
                with self.subTest(state=state):
                    payload = self.fixture(root, state)
                    self.assertEqual(
                        release_state.validate_release(
                            payload, self.VERSION, self.SOURCE, self.NOTES, root, state
                        ),
                        42,
                    )

    def test_each_identity_or_asset_change_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = self.fixture(root)
            mutations = []
            for field, value in (
                ("tag_name", "v1.2.4"),
                ("target_commitish", "2" * 40),
                ("name", "wrong"),
                ("body", "wrong"),
                ("immutable", False),
                ("prerelease", True),
            ):
                changed = copy.deepcopy(canonical)
                changed[field] = value
                mutations.append(changed)
            missing = copy.deepcopy(canonical)
            missing["assets"].pop()
            mutations.append(missing)
            wrong_digest = copy.deepcopy(canonical)
            wrong_digest["assets"][0]["digest"] = "sha256:" + "0" * 64
            mutations.append(wrong_digest)
            wrong_size = copy.deepcopy(canonical)
            wrong_size["assets"][0]["size"] += 1
            mutations.append(wrong_size)
            duplicate_id = copy.deepcopy(canonical)
            duplicate_id["assets"][1]["id"] = duplicate_id["assets"][0]["id"]
            mutations.append(duplicate_id)
            duplicate_url = copy.deepcopy(canonical)
            duplicate_url["assets"][1]["url"] = duplicate_url["assets"][0]["url"]
            mutations.append(duplicate_url)
            for payload in mutations:
                with self.subTest(payload=payload), self.assertRaises(release_state.ReleaseError):
                    release_state.validate_release(
                        payload,
                        self.VERSION,
                        self.SOURCE,
                        self.NOTES,
                        root,
                        "published",
                    )

    def test_probe_classifies_empty_partial_complete_and_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            complete_draft = self.fixture(root, "draft")
            empty = copy.deepcopy(complete_draft)
            empty["assets"] = []
            partial = copy.deepcopy(complete_draft)
            partial["assets"] = partial["assets"][-1:]
            published = self.fixture(root, "published")
            cases = (
                (empty, "draft-empty"),
                (partial, "draft-partial"),
                (complete_draft, "draft-exact"),
                (published, "published"),
            )
            for payload, expected in cases:
                with self.subTest(expected=expected):
                    self.assertEqual(
                        release_state.probe_release(
                            payload, self.VERSION, self.SOURCE, self.NOTES, root
                        ),
                        {"release_id": 42, "state": expected},
                    )

    def test_probe_refuses_wrong_target_or_untrusted_asset_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = self.fixture(root, "draft")
            mutations = []
            wrong_target = copy.deepcopy(canonical)
            wrong_target["target_commitish"] = "2" * 40
            mutations.append(wrong_target)
            duplicate = copy.deepcopy(canonical)
            duplicate["assets"].append(copy.deepcopy(duplicate["assets"][0]))
            mutations.append(duplicate)
            unexpected = copy.deepcopy(canonical)
            unexpected["assets"][0]["name"] = "unexpected"
            mutations.append(unexpected)
            bad_identity = copy.deepcopy(canonical)
            bad_identity["assets"][0]["id"] = 0
            mutations.append(bad_identity)
            duplicate_id = copy.deepcopy(canonical)
            duplicate_id["assets"][1]["id"] = duplicate_id["assets"][0]["id"]
            mutations.append(duplicate_id)
            duplicate_url = copy.deepcopy(canonical)
            duplicate_url["assets"][1]["url"] = duplicate_url["assets"][0]["url"]
            mutations.append(duplicate_url)
            bad_stable_digest = copy.deepcopy(canonical)
            bad_stable_digest["assets"][0]["digest"] = "sha256:" + "0" * 64
            mutations.append(bad_stable_digest)
            for payload in mutations:
                with self.subTest(payload=payload), self.assertRaises(
                    release_state.ReleaseError
                ):
                    release_state.probe_release(
                        payload, self.VERSION, self.SOURCE, self.NOTES, root
                    )


class DraftDiscoveryShimTests(unittest.TestCase):
    VERSION = "1.2.3"
    SOURCE = "1" * 40
    TAG = "v1.2.3"

    def test_shipping_blocks_find_a_draft_on_a_later_page_by_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "runner"
            prepared = runner / "prepared"
            tools = root / "bin"
            prepared.mkdir(parents=True)
            tools.mkdir()
            notes = "- exact notes\n"
            (prepared / "release-notes.md").write_text(notes, encoding="utf-8")
            release = {
                "id": 42,
                "tag_name": self.TAG,
                "target_commitish": self.SOURCE,
                "name": f"keyrx {self.VERSION}",
                "body": notes,
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "published_at": None,
                "assets": [],
            }
            release_path = root / "release.json"
            release_path.write_text(json.dumps(release), encoding="utf-8")
            gh_log = root / "gh.log"
            write_executable(
                tools / "gh",
                """#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
endpoint = args[-1]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as log:
    log.write(endpoint + "\\n")
if endpoint.endswith("releases?per_page=100"):
    if args.count("--paginate") != 1:
        raise SystemExit(64)
    print(json.dumps([{"id": 1, "tag_name": "v1.2.2"}]))
    print(json.dumps([{"id": 42, "tag_name": "v1.2.3"}]))
elif endpoint.endswith("releases/42"):
    with open(os.environ["FAKE_RELEASE"], encoding="utf-8") as source:
        sys.stdout.write(source.read())
else:
    raise SystemExit(22)
""",
            )
            write_fake_jq(tools / "jq")
            lookup_output = root / "lookup-output"
            release_output = root / "release-output"
            env = os.environ.copy()
            env.update(
                {
                    "RUNNER_TEMP": str(runner),
                    "GITHUB_REPOSITORY": "keyrx/keyrx",
                    "GH_TOKEN": "fixture-token",
                    "TAG": self.TAG,
                    "VERSION": self.VERSION,
                    "SOURCE_SHA": self.SOURCE,
                    "FAKE_RELEASE": str(release_path),
                    "FAKE_GH_LOG": str(gh_log),
                    "PATH": str(tools) + os.pathsep + env["PATH"],
                }
            )
            enumerate_result = subprocess.run(
                ["bash", "-c", workflow_run("Enumerate every release including inert drafts")],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(enumerate_result.returncode, 0, enumerate_result.stderr)
            env["GITHUB_OUTPUT"] = str(lookup_output)
            select_result = subprocess.run(
                ["bash", "-c", workflow_run("Select the exact release tag from every page")],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(select_result.returncode, 0, select_result.stderr)
            self.assertEqual(
                lookup_output.read_text(encoding="utf-8"),
                "state=found\nrelease_id=42\n",
            )
            fetch = workflow_run("Fetch the selected release by immutable API identity").replace(
                "${{ steps.release_lookup.outputs.release_id }}", "42"
            )
            fetch_result = subprocess.run(
                ["bash", "-c", fetch], cwd=ROOT, env=env, capture_output=True, text=True
            )
            self.assertEqual(fetch_result.returncode, 0, fetch_result.stderr)
            env["GITHUB_OUTPUT"] = str(release_output)
            inspect = workflow_run("Inspect any release left by an exact rerun")
            inspect = inspect.replace("${{ steps.release_lookup.outputs.state }}", "found")
            inspect = inspect.replace("${{ steps.release_lookup.outputs.release_id }}", "42")
            inspect_result = subprocess.run(
                ["bash", "-c", inspect], cwd=ROOT, env=env, capture_output=True, text=True
            )
            self.assertEqual(inspect_result.returncode, 0, inspect_result.stderr)
            self.assertEqual(
                release_output.read_text(encoding="utf-8"),
                "state=draft-empty\nrelease_id=42\n",
            )
            endpoints = gh_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                endpoints,
                ["repos/keyrx/keyrx/releases?per_page=100", "repos/keyrx/keyrx/releases/42"],
            )
            self.assertFalse(any("releases/tags/" in endpoint for endpoint in endpoints))

            no_pagination = workflow_run(
                "Enumerate every release including inert drafts"
            ).replace("gh api --paginate", "gh api", 1)
            refused = subprocess.run(
                ["bash", "-c", no_pagination],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)


class DraftIdentityShimTests(unittest.TestCase):
    def test_exactly_one_existing_or_created_identity_is_required(self):
        block = workflow_run("Select exactly one draft identity")
        cases = (
            ("42", "", True),
            ("", "43", True),
            ("", "", False),
            ("42", "43", False),
            ("42", "42", False),
            ("not-an-id", "", False),
        )
        for existing, created, accepted in cases:
            with self.subTest(existing=existing, created=created):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "github-output"
                    env = os.environ.copy()
                    env.update(
                        {
                            "EXISTING_RELEASE_ID": existing,
                            "CREATED_RELEASE_ID": created,
                            "GITHUB_OUTPUT": str(output),
                        }
                    )
                    result = subprocess.run(
                        ["bash", "-c", block],
                        cwd=ROOT,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    if accepted:
                        expected = existing or created
                        self.assertEqual(
                            output.read_text(encoding="utf-8"),
                            f"release_id={expected}\n",
                        )
                    else:
                        self.assertFalse(output.exists() and output.read_bytes())

    def test_full_draft_validation_rejects_a_returned_id_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "runner"
            prepared = runner / "prepared"
            prepared.mkdir(parents=True)
            version = "1.2.3"
            source = "1" * 40
            notes = "- exact notes\n"
            (prepared / "release-notes.md").write_text(notes, encoding="utf-8")
            assets = []
            for index, name in enumerate(release_state.required_assets(version), 1):
                path = prepared / name
                path.write_bytes(f"asset {index}\n".encode())
                assets.append(
                    {
                        "id": 100 + index,
                        "name": name,
                        "url": f"https://api.github.test/releases/assets/{100 + index}",
                        "size": path.stat().st_size,
                        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                        "state": "uploaded",
                    }
                )
            payload = {
                "id": 42,
                "tag_name": f"v{version}",
                "target_commitish": source,
                "name": f"keyrx {version}",
                "body": notes,
                "draft": True,
                "prerelease": False,
                "published_at": None,
                "assets": assets,
            }
            (runner / "complete-draft.json").write_text(json.dumps(payload), encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "RUNNER_TEMP": str(runner),
                    "VERSION": version,
                    "SOURCE_SHA": source,
                    "GITHUB_OUTPUT": str(root / "github-output"),
                }
            )
            canonical = workflow_run("Validate the complete draft before publication").replace(
                "${{ steps.draft_identity.outputs.release_id }}", "42"
            )
            accepted = subprocess.run(
                ["bash", "-c", canonical],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            mismatch = workflow_run("Validate the complete draft before publication").replace(
                "${{ steps.draft_identity.outputs.release_id }}", "43"
            )
            env["GITHUB_OUTPUT"] = str(root / "mismatch-output")
            refused = subprocess.run(
                ["bash", "-c", mismatch],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse(
                Path(env["GITHUB_OUTPUT"]).exists()
                and Path(env["GITHUB_OUTPUT"]).read_bytes()
            )

    def test_selected_draft_is_still_empty_immediately_before_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "runner"
            prepared = runner / "prepared"
            tools = root / "bin"
            prepared.mkdir(parents=True)
            tools.mkdir()
            version = "1.2.3"
            source = "1" * 40
            notes = "- exact notes\n"
            (prepared / "release-notes.md").write_text(notes, encoding="utf-8")
            assets = []
            for index, name in enumerate(release_state.required_assets(version), 1):
                path = prepared / name
                path.write_bytes(f"asset {index}\n".encode())
                assets.append(
                    {
                        "id": 100 + index,
                        "name": name,
                        "url": f"https://api.github.test/releases/assets/{100 + index}",
                        "size": path.stat().st_size,
                        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                        "state": "uploaded",
                    }
                )
            payload = {
                "id": 42,
                "tag_name": f"v{version}",
                "target_commitish": source,
                "name": f"keyrx {version}",
                "body": notes,
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "published_at": None,
                "assets": [],
            }
            write_fake_jq(tools / "jq")
            env = os.environ.copy()
            env.update(
                {
                    "RUNNER_TEMP": str(runner),
                    "VERSION": version,
                    "SOURCE_SHA": source,
                    "PATH": str(tools) + os.pathsep + env["PATH"],
                    "NEXT_EFFECT_LEDGER": str(root / "next-effect.log"),
                }
            )
            block = workflow_run("Validate the selected draft is empty before upload")
            block = block.replace(
                "${{ steps.draft_identity.outputs.release_id }}", "42"
            )
            combined = block + 'printf "%s\\n" upload >> "$NEXT_EFFECT_LEDGER"\n'
            cases = (
                ("empty", [], True),
                ("partial", assets[:1], False),
                ("complete", assets, False),
            )
            for label, rows, accepted in cases:
                with self.subTest(label=label):
                    Path(env["NEXT_EFFECT_LEDGER"]).unlink(missing_ok=True)
                    payload["assets"] = rows
                    (runner / "empty-draft.json").write_text(
                        json.dumps(payload), encoding="utf-8"
                    )
                    result = subprocess.run(
                        ["bash", "-c", combined],
                        cwd=ROOT,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    ledger = Path(env["NEXT_EFFECT_LEDGER"])
                    self.assertEqual(ledger.exists(), accepted)
                    if accepted:
                        self.assertEqual(ledger.read_text(encoding="utf-8"), "upload\n")


class DraftUploadShimTests(unittest.TestCase):
    def test_shipping_upload_targets_only_the_selected_numeric_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "runner"
            prepared = runner / "prepared"
            tools = root / "bin"
            prepared.mkdir(parents=True)
            tools.mkdir()
            version = "1.2.3"
            names = release_state.required_assets(version)
            for index, name in enumerate(names, 1):
                (prepared / name).write_bytes(f"asset {index}\n".encode())
            empty = {
                "upload_url": (
                    "https://uploads.github.com/repos/keyrx/keyrx/"
                    "releases/42/assets{?name,label}"
                )
            }
            empty_path = runner / "empty-draft.json"
            empty_path.write_text(json.dumps(empty), encoding="utf-8")
            log = root / "curl.log"
            write_executable(
                tools / "curl",
                """#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys, urllib.parse
args = sys.argv[1:]
url = args[-1]
out = pathlib.Path(args[args.index("-o") + 1])
data = args[args.index("--data-binary") + 1]
if not data.startswith("@"):
    raise SystemExit(2)
path = pathlib.Path(data[1:])
name = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["name"][0]
digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
if os.environ.get("FAKE_WRONG_DIGEST"):
    digest = "sha256:" + "0" * 64
payload = {"id": 100, "name": name, "state": "uploaded",
           "size": path.stat().st_size, "digest": digest}
if os.environ.get("FAKE_WRONG_NAME"):
    payload["name"] += "-wrong"
if os.environ.get("FAKE_WRONG_ID"):
    payload["id"] = 0
out.write_text(json.dumps(payload), encoding="utf-8")
with open(os.environ["FAKE_CURL_LOG"], "a", encoding="utf-8") as handle:
    handle.write(url + "\\n")
""",
            )
            write_executable(
                tools / "jq",
                """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
if args[:2] == ["-er", ".upload_url"]:
    print(json.load(open(args[2], encoding="utf-8"))["upload_url"])
    raise SystemExit(0)
if not args or args[0] != "-e":
    raise SystemExit(2)
values = {}
index = 1
while index < len(args) and args[index] in ("--arg", "--argjson"):
    kind, key, value = args[index:index + 3]
    values[key] = int(value) if kind == "--argjson" else value
    index += 3
expr = args[index]
payload = json.load(open(args[index + 1], encoding="utf-8"))
known = (
    ".name == $name",
    '.state == "uploaded"',
    ".size == $size",
    ".digest == $digest",
    '.id | type == "number"',
    ". > 0",
)
if not any(fragment in expr for fragment in known):
    raise SystemExit(2)
ok = True
if ".name == $name" in expr:
    ok = ok and payload.get("name") == values["name"]
if '.state == "uploaded"' in expr:
    ok = ok and payload.get("state") == "uploaded"
if ".size == $size" in expr:
    ok = ok and payload.get("size") == values["size"]
if ".digest == $digest" in expr:
    ok = ok and payload.get("digest") == values["digest"]
if '.id | type == "number"' in expr:
    ok = ok and isinstance(payload.get("id"), int) and not isinstance(payload.get("id"), bool)
if ". > 0" in expr:
    ok = ok and isinstance(payload.get("id"), int) and payload["id"] > 0
raise SystemExit(0 if ok else 1)
""",
            )
            env = os.environ.copy()
            env.update(
                {
                    "RUNNER_TEMP": str(runner),
                    "CRATE_NAME": "keyrx",
                    "VERSION": version,
                    "GITHUB_REPOSITORY": "keyrx/keyrx",
                    "GH_TOKEN": "fixture-token",
                    "FAKE_CURL_LOG": str(log),
                    "PATH": str(tools) + os.pathsep + env["PATH"],
                }
            )
            block = workflow_run("Upload the complete asset set to the exact empty draft")
            block = block.replace("${{ steps.draft_identity.outputs.release_id }}", "42")
            accepted = subprocess.run(
                ["bash", "-c", block],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            urls = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(urls), 6)
            self.assertEqual(len(set(urls)), 6)
            self.assertTrue(
                all("/releases/42/assets?name=keyrx-1.2.3." in url for url in urls)
            )
            self.assertFalse(any("/tags/" in url for url in urls))

            empty["upload_url"] = empty["upload_url"].replace("releases/42/", "releases/43/")
            empty_path.write_text(json.dumps(empty), encoding="utf-8")
            before = log.read_bytes()
            wrong_id = subprocess.run(
                ["bash", "-c", block],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(wrong_id.returncode, 0)
            self.assertEqual(log.read_bytes(), before)

            empty["upload_url"] = empty["upload_url"].replace("releases/43/", "releases/42/")
            empty_path.write_text(json.dumps(empty), encoding="utf-8")
            for flag in ("FAKE_WRONG_NAME", "FAKE_WRONG_DIGEST", "FAKE_WRONG_ID"):
                with self.subTest(flag=flag):
                    for candidate in ("FAKE_WRONG_NAME", "FAKE_WRONG_DIGEST", "FAKE_WRONG_ID"):
                        env.pop(candidate, None)
                    env[flag] = "1"
                    wrong_response = subprocess.run(
                        ["bash", "-c", block],
                        cwd=ROOT,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(wrong_response.returncode, 0)

            env.pop("FAKE_WRONG_ID", None)
            env["FAKE_WRONG_DIGEST"] = "1"
            without_digest_guard = block.replace(
                ".digest == $digest and ", "", 1
            )
            self.assertNotEqual(without_digest_guard, block)
            mutation = subprocess.run(
                ["bash", "-c", without_digest_guard],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(mutation.returncode, 0, mutation.stderr)


class FinalIdentityShimTests(unittest.TestCase):
    VERSION = "1.2.3"
    SOURCE = "1" * 40
    TAG = "v1.2.3"

    def release_fixture(self, root, release_id):
        runner = root / "runner"
        prepared = runner / "prepared"
        prepared.mkdir(parents=True)
        notes = "- exact notes\n"
        (prepared / "release-notes.md").write_text(notes, encoding="utf-8")
        assets = []
        for index, name in enumerate(release_state.required_assets(self.VERSION), 1):
            path = prepared / name
            path.write_bytes(f"asset {index}\n".encode())
            assets.append(
                {
                    "id": 100 + index,
                    "name": name,
                    "url": f"https://api.github.test/releases/assets/{100 + index}",
                    "size": path.stat().st_size,
                    "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                    "state": "uploaded",
                }
            )
        payload = {
            "id": release_id,
            "tag_name": self.TAG,
            "target_commitish": self.SOURCE,
            "name": f"keyrx {self.VERSION}",
            "body": notes,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "published_at": "2026-09-02T00:00:00Z",
            "assets": assets,
        }
        payload_path = root / "published.json"
        payload_path.write_text(json.dumps(payload), encoding="utf-8")
        return runner, payload_path

    def test_final_identity_accepts_one_or_two_equal_sources_only(self):
        block = workflow_run("Bind the final release identity")
        cases = (
            ("42", "", True),
            ("", "42", True),
            ("42", "42", True),
            ("", "", False),
            ("42", "43", False),
            ("bad", "", False),
        )
        for discovered, validated, accepted in cases:
            with self.subTest(discovered=discovered, validated=validated):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "github-output"
                    env = os.environ.copy()
                    env.update(
                        {
                            "DISCOVERED_RELEASE_ID": discovered,
                            "VALIDATED_RELEASE_ID": validated,
                            "GITHUB_OUTPUT": str(output),
                        }
                    )
                    result = subprocess.run(
                        ["bash", "-c", block],
                        cwd=ROOT,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    if accepted:
                        self.assertEqual(output.read_text(encoding="utf-8"), "release_id=42\n")
                    else:
                        self.assertFalse(output.exists() and output.read_bytes())

    def test_patch_response_and_final_tag_lookup_must_keep_the_validated_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner, payload_path = self.release_fixture(root, 42)
            tools = root / "bin"
            tools.mkdir()
            write_executable(
                tools / "gh",
                """#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
endpoint = next((value for value in args if value.startswith("repos/")), "")
if args[:2] == ["api", "-H"] and "--method" in args:
    with open(os.environ["FAKE_PUBLISHED"], encoding="utf-8") as source:
        sys.stdout.write(source.read())
elif args[:2] == ["api", "-H"] and "releases/tags/" in endpoint:
    with open(os.environ["FAKE_PUBLISHED"], encoding="utf-8") as source:
        sys.stdout.write(source.read())
elif args[:2] == ["api", "-H"] and endpoint.endswith("releases/latest"):
    print(os.environ["TAG"])
elif args[:2] == ["release", "verify"]:
    pass
else:
    raise SystemExit(22)
""",
            )
            base_env = os.environ.copy()
            base_env.update(
                {
                    "RUNNER_TEMP": str(runner),
                    "VERSION": self.VERSION,
                    "SOURCE_SHA": self.SOURCE,
                    "TAG": self.TAG,
                    "GITHUB_REPOSITORY": "keyrx/keyrx",
                    "GH_TOKEN": "fixture-token",
                    "FAKE_PUBLISHED": str(payload_path),
                    "PATH": str(tools) + os.pathsep + base_env["PATH"],
                }
            )
            publish_env = base_env.copy()
            publish_env.update(
                {
                    "EXISTING_RELEASE_ID": "",
                    "CREATED_RELEASE_ID": "42",
                    "VALIDATED_RELEASE_ID": "42",
                }
            )
            publish_block = workflow_run("Publish the exact draft")
            canonical_publish = subprocess.run(
                ["bash", "-c", publish_block],
                cwd=ROOT,
                env=publish_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(canonical_publish.returncode, 0, canonical_publish.stderr)

            final_block = workflow_run("Verify the immutable release and every attached digest")
            final_block = final_block.replace(
                "${{ steps.final_identity.outputs.release_id }}", "42"
            )
            canonical_final = subprocess.run(
                ["bash", "-c", final_block],
                cwd=ROOT,
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(canonical_final.returncode, 0, canonical_final.stderr)

            changed = json.loads(payload_path.read_text(encoding="utf-8"))
            changed["id"] = 43
            payload_path.write_text(json.dumps(changed), encoding="utf-8")
            publish = subprocess.run(
                ["bash", "-c", publish_block],
                cwd=ROOT,
                env=publish_env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(publish.returncode, 0)

            final_result = subprocess.run(
                ["bash", "-c", final_block],
                cwd=ROOT,
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(final_result.returncode, 0)


class RegistryRebindShimTests(unittest.TestCase):
    VERSION = "1.2.3"
    SOURCE = "1" * 40
    REPOSITORY = "keyrx/keyrx"

    def run_rebind(
        self,
        *,
        predecessors=("1.2.2", "1.2.1"),
        expected_predecessors=None,
        detail_sha=None,
        fail_url="",
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        runner = root / "runner"
        prepared = runner / "prepared"
        tools = root / "bin"
        prepared.mkdir(parents=True)
        tools.mkdir()
        crate = prepared / f"keyrx-{self.VERSION}.crate"
        crate.write_bytes(b"exact crate bytes\n")
        checksum = hashlib.sha256(crate.read_bytes()).hexdigest()
        list_payload = {
            "versions": [
                {
                    "num": self.VERSION,
                    "yanked": False,
                    "checksum": checksum,
                },
                *[
                    {
                        "num": predecessor,
                        "yanked": False,
                        "checksum": str(index) * 64,
                    }
                    for index, predecessor in enumerate(predecessors, 2)
                ],
            ]
        }
        detail_payload = {
            "version": {
                "crate": "keyrx",
                "num": self.VERSION,
                "yanked": False,
                "checksum": checksum,
                "trustpub_data": {
                    "provider": "github",
                    "repository": self.REPOSITORY,
                    "run_id": "123456",
                    "sha": detail_sha or self.SOURCE,
                },
            }
        }
        list_path = root / "list.json"
        detail_path = root / "detail.json"
        list_path.write_text(json.dumps(list_payload), encoding="utf-8")
        detail_path.write_text(json.dumps(detail_payload), encoding="utf-8")
        curl_log = root / "curl.log"
        output = root / "github-output"
        write_executable(
            tools / "curl",
            """#!/usr/bin/env python3
import os, shutil, sys
args = sys.argv[1:]
url = args[-1]
with open(os.environ["FAKE_CURL_LOG"], "a", encoding="utf-8") as log:
    log.write(url + "\\n")
if os.environ.get("FAKE_CURL_FAIL") and os.environ["FAKE_CURL_FAIL"] in url:
    raise SystemExit(22)
out = args[args.index("-o") + 1]
source = os.environ["FAKE_DETAIL"] if url.endswith("/" + os.environ["VERSION"]) else os.environ["FAKE_LIST"]
shutil.copyfile(source, out)
""",
        )
        write_fake_jq(tools / "jq")
        env = os.environ.copy()
        env.update(
            {
                "RUNNER_TEMP": str(runner),
                "CRATE_NAME": "keyrx",
                "VERSION": self.VERSION,
                "SOURCE_SHA": self.SOURCE,
                "GITHUB_REPOSITORY": self.REPOSITORY,
                "PREDECESSORS": json.dumps(
                    list(expected_predecessors or predecessors), separators=(",", ":")
                ),
                "GITHUB_OUTPUT": str(output),
                "FAKE_LIST": str(list_path),
                "FAKE_DETAIL": str(detail_path),
                "FAKE_CURL_LOG": str(curl_log),
                "FAKE_CURL_FAIL": fail_url,
                "PATH": str(tools) + os.pathsep + env["PATH"],
            }
        )
        result = subprocess.run(
            ["bash", "-c", workflow_run("Rebind the measured predecessors immediately before yank")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        return result, output, curl_log

    def test_exact_registry_and_trusted_publisher_are_rebound(self):
        result, output, curl_log = self.run_rebind()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "predecessor_count=2\n")
        self.assertEqual(
            (output.parent / "runner" / "predecessors").read_text(encoding="utf-8"),
            "1.2.2\n1.2.1\n",
        )
        urls = curl_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            urls,
            [
                "https://crates.io/api/v1/crates/keyrx",
                "https://crates.io/api/v1/crates/keyrx/1.2.3",
            ],
        )

    def test_changed_predecessors_wrong_publisher_or_failed_read_refuses(self):
        cases = (
            {"expected_predecessors": ("1.2.2",)},
            {"detail_sha": "2" * 40},
            {"fail_url": "/keyrx/1.2.3"},
        )
        for options in cases:
            with self.subTest(options=options):
                result, output, _ = self.run_rebind(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists() and output.read_bytes())

    def test_yank_step_receives_only_the_exact_rebound_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            ledger = root / "cargo.log"
            write_executable(
                tools / "cargo",
                """#!/usr/bin/env bash
set -euo pipefail
test -n "$CARGO_REGISTRY_TOKEN"
printf '%s\\n' "$*" >> "$FAKE_CARGO_LOG"
""",
            )
            env = os.environ.copy()
            runner = root / "runner"
            runner.mkdir()
            (runner / "predecessors").write_text("1.2.2\n1.2.1\n", encoding="utf-8")
            env.update(
                {
                    "CARGO_REGISTRY_TOKEN": "fixture-yank-token",
                    "CRATE_NAME": "keyrx",
                    "PREDECESSOR_COUNT": "2",
                    "RUNNER_TEMP": str(runner),
                    "FAKE_CARGO_LOG": str(ledger),
                    "PATH": str(tools) + os.pathsep + env["PATH"],
                }
            )
            block = workflow_run("Yank the exactly rebound predecessors")
            result = subprocess.run(
                ["bash", "-c", block], cwd=ROOT, env=env, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                ledger.read_text(encoding="utf-8"),
                "yank keyrx --vers 1.2.2 --registry crates-io\n"
                "yank keyrx --vers 1.2.1 --registry crates-io\n",
            )
            env["CARGO_REGISTRY_TOKEN"] = ""
            ledger.unlink()
            refused = subprocess.run(
                ["bash", "-c", block], cwd=ROOT, env=env, capture_output=True, text=True
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse(ledger.exists())


class ReleaseReuseShimTests(unittest.TestCase):
    VERSION = CURRENT_VERSION
    SOURCE = "1" * 40
    REPOSITORY = "keyrx/keyrx"
    NOTES = "- exact notes\n"

    def fixture(self, state, tamper=""):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        runner = root / "runner"
        prepared = runner / "prepared"
        remote = root / "remote"
        tools = root / "bin"
        prepared.mkdir(parents=True)
        remote.mkdir()
        tools.mkdir()
        names = release_state.required_assets(self.VERSION)
        stable = {
            names[0]: b"exact crate bytes\n",
            names[1]: b"crate checksum sidecar\n",
            names[2]: b'{"bomFormat":"CycloneDX"}\n',
        }
        for name, data in stable.items():
            (prepared / name).write_bytes(data)
            (remote / name).write_bytes(data)
        (prepared / "release-notes.md").write_text(self.NOTES, encoding="utf-8")
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": "e30=",
            "signatures": [{"sig": "fixture"}],
        }
        bundle = {"dsseEnvelope": envelope}
        (remote / names[3]).write_text(json.dumps(bundle), encoding="utf-8")
        (remote / names[4]).write_text(
            json.dumps(envelope, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        manifest_rows = []
        for name in names[:5]:
            manifest_rows.append(
                f"{hashlib.sha256((remote / name).read_bytes()).hexdigest()}  {name}"
            )
        (remote / names[5]).write_text("\n".join(manifest_rows) + "\n", encoding="utf-8")
        if tamper == "intoto":
            (remote / names[4]).write_text('{}\n', encoding="utf-8")
            rows = (remote / names[5]).read_text(encoding="utf-8").splitlines()
            rows[4] = (
                hashlib.sha256((remote / names[4]).read_bytes()).hexdigest()
                + rows[4][64:]
            )
            (remote / names[5]).write_text("\n".join(rows) + "\n", encoding="utf-8")
        elif tamper == "manifest":
            rows = (remote / names[5]).read_text(encoding="utf-8").splitlines()
            rows[0] = "0" * 64 + rows[0][64:]
            (remote / names[5]).write_text("\n".join(rows) + "\n", encoding="utf-8")
        elif tamper == "stable":
            (remote / names[0]).write_bytes(b"different crate bytes\n")
        api = "https://api.github.test"
        assets = []
        id_map = {}
        for index, name in enumerate(names, 1):
            path = remote / name
            asset_id = 100 + index
            id_map[str(asset_id)] = str(path)
            assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "url": f"{api}/repos/{self.REPOSITORY}/releases/assets/{asset_id}",
                    "size": path.stat().st_size,
                    "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                    "state": "uploaded",
                }
            )
        payload = {
            "id": 42,
            "tag_name": f"v{self.VERSION}",
            "target_commitish": self.SOURCE,
            "name": f"keyrx {self.VERSION}",
            "body": self.NOTES,
            "draft": state == "draft-exact",
            "prerelease": False,
            "immutable": state == "published",
            "published_at": None if state == "draft-exact" else "2026-09-02T00:00:00Z",
            "assets": assets,
        }
        (runner / "release-before.json").write_text(json.dumps(payload), encoding="utf-8")
        curl_log = root / "curl.log"
        gh_log = root / "gh.log"
        write_executable(
            tools / "curl",
            """#!/usr/bin/env python3
import json, os, shutil, sys
args = sys.argv[1:]
url = args[-1]
with open(os.environ["FAKE_CURL_LOG"], "a", encoding="utf-8") as log:
    log.write(url + "\\n")
out = args[args.index("-o") + 1]
asset_id = url.rsplit("/", 1)[-1]
source = json.loads(os.environ["FAKE_ASSET_MAP"])[asset_id]
shutil.copyfile(source, out)
""",
        )
        write_executable(
            tools / "gh",
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
test "$1 $2" = 'attestation verify'
""",
        )
        write_fake_jq(tools / "jq")
        env = os.environ.copy()
        env.update(
            {
                "RUNNER_TEMP": str(runner),
                "CRATE_NAME": "keyrx",
                "VERSION": self.VERSION,
                "SOURCE_SHA": self.SOURCE,
                "GITHUB_API_URL": api,
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_REPOSITORY": self.REPOSITORY,
                "GH_TOKEN": "fixture-token",
                "FAKE_ASSET_MAP": json.dumps(id_map),
                "FAKE_CURL_LOG": str(curl_log),
                "FAKE_GH_LOG": str(gh_log),
                "PATH": str(tools) + os.pathsep + env["PATH"],
            }
        )
        block = workflow_run("Reuse complete provenance from an exact prior run").replace(
            "${{ steps.release.outputs.state }}", state
        )
        result = subprocess.run(
            ["bash", "-c", block], cwd=ROOT, env=env, capture_output=True, text=True
        )
        return result, prepared, remote, curl_log, gh_log

    def test_complete_draft_and_published_release_reuse_exact_provenance(self):
        for state in ("draft-exact", "published"):
            with self.subTest(state=state):
                result, prepared, remote, curl_log, gh_log = self.fixture(state)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in release_state.required_assets(self.VERSION):
                    self.assertEqual((prepared / name).read_bytes(), (remote / name).read_bytes())
                urls = curl_log.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(urls), 6)
                self.assertEqual(len(set(urls)), 6)
                invocation = gh_log.read_text(encoding="utf-8")
                self.assertIn("attestation verify", invocation)
                self.assertIn(f"--source-digest {self.SOURCE}", invocation)
                self.assertIn(
                    "--signer-workflow github.com/keyrx/keyrx/.github/workflows/publish.yml",
                    invocation,
                )

    def test_tampered_prior_assets_refuse_before_provenance_copy(self):
        for tamper in ("intoto", "manifest", "stable"):
            with self.subTest(tamper=tamper):
                result, prepared, _, _, _ = self.fixture("draft-exact", tamper)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(
                    (prepared / f"keyrx-{self.VERSION}.crate.sigstore.json").exists()
                )


class SbomTests(unittest.TestCase):
    def test_sbom_is_deterministic_and_binds_lock_dependencies(self):
        manifest = {"package": {"name": "keyrx", "version": "1.2.3", "license": "MIT"}}
        lock = {
            "package": [
                {"name": "keyrx", "version": "1.2.3", "dependencies": ["dep 2.0.0"]},
                {
                    "name": "dep",
                    "version": "2.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "checksum": "a" * 64,
                },
            ]
        }
        first = generate_sbom.build_sbom(manifest, lock, "1.2.3", "1" * 40)
        second = generate_sbom.build_sbom(manifest, lock, "1.2.3", "1" * 40)
        self.assertEqual(first, second)
        self.assertEqual(first["metadata"]["component"]["name"], "keyrx")
        self.assertEqual(first["components"][0]["name"], "dep")
        self.assertEqual(
            first["components"][0]["hashes"],
            [{"alg": "SHA-256", "content": "a" * 64}],
        )
        root_dependencies = next(
            row for row in first["dependencies"] if row["ref"] == "pkg:cargo/keyrx@1.2.3"
        )
        self.assertEqual(root_dependencies["dependsOn"], ["pkg:cargo/dep@2.0.0"])


if __name__ == "__main__":
    unittest.main()
