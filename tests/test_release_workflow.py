from pathlib import Path
import json
import hashlib
import io
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
import uuid
import zlib


ROOT = Path(__file__).parents[1]
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"


def tag_workflow_names(directory):
    paths = sorted(set(directory.glob("*.yml")) | set(directory.glob("*.yaml")))
    return [
        path.name
        for path in paths
        if re.search(r"^\s+tags\s*:", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]


def assert_immutable_dependencies(testcase, text):
    uses = re.findall(r"^\s+(?:-\s+)?uses:\s*([^\s#]+)", text, re.MULTILINE)
    testcase.assertTrue(uses)
    for value in uses:
        testcase.assertRegex(value, r"^[^@\s]+@[0-9a-f]{40}$")


def inline_python(marker):
    text = PUBLISH.read_text(encoding="utf-8")
    block = text.split(f"# {marker}_BEGIN\n", 1)[1].split(
        f"# {marker}_END", 1
    )[0]
    body = block.split("<<'PY'\n", 1)[1].rsplit("\n          PY", 1)[0]
    return "\n".join(line[10:] if line.startswith("          ") else line for line in body.splitlines())


def run_inline(marker, *args):
    return subprocess.run(
        ["python3", "-", *map(str, args)],
        input=inline_python(marker),
        text=True,
        capture_output=True,
        check=False,
    )


def inline_shell(marker):
    text = PUBLISH.read_text(encoding="utf-8")
    block = text.split(f"# {marker}_BEGIN\n", 1)[1].split(f"# {marker}_END", 1)[0]
    return "set -euo pipefail\n" + "\n".join(
        line[10:] if line.startswith("          ") else line for line in block.splitlines()
    )


class RecoveryDispatchTests(unittest.TestCase):
    def make_lineage(self, root, *, extra=False, omit_test_change=False):
        subprocess.run(["git", "init", "-q", root], check=True)
        subprocess.run(
            ["git", "-C", root, "config", "user.email", "recovery@test.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", root, "config", "user.name", "recovery control"],
            check=True,
        )
        workflow = root / ".github" / "workflows" / "publish.yml"
        test = root / "tests" / "test_release_workflow.py"
        workflow.parent.mkdir(parents=True)
        test.parent.mkdir(parents=True)
        workflow.write_text("source workflow\n", encoding="utf-8")
        test.write_text("source test\n", encoding="utf-8")
        subprocess.run(["git", "-C", root, "add", "."], check=True)
        subprocess.run(["git", "-C", root, "commit", "-qm", "source"], check=True)
        source = subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD"], text=True
        ).strip()
        workflow.write_text("recovery workflow\n", encoding="utf-8")
        if not omit_test_change:
            test.write_text("recovery test\n", encoding="utf-8")
        if extra:
            (root / "extra").write_text("not allowed\n", encoding="utf-8")
        subprocess.run(["git", "-C", root, "add", "."], check=True)
        subprocess.run(["git", "-C", root, "commit", "-qm", "recovery base"], check=True)
        recovery_base = subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD"], text=True
        ).strip()
        workflow.write_text("recovery repair workflow\n", encoding="utf-8")
        if not omit_test_change:
            test.write_text("recovery repair test\n", encoding="utf-8")
        subprocess.run(["git", "-C", root, "add", "."], check=True)
        subprocess.run(["git", "-C", root, "commit", "-qm", "ceremony"], check=True)
        ceremony = subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD"], text=True
        ).strip()
        return source, recovery_base, ceremony

    def identity(self, root, base_source, base_recovery, base_ceremony, **overrides):
        values = {
            "event": "workflow_dispatch",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "ref_name": "main",
            "event_sha": base_ceremony,
            "ceremony": base_ceremony,
            "source": base_source,
            "recovery_base": base_recovery,
        }
        values.update(overrides)
        return run_inline(
            "INLINE_RECOVERY_IDENTITY_VALIDATOR",
            root,
            values["event"],
            values["ref"],
            values["ref_type"],
            values["ref_name"],
            values["event_sha"],
            values["ceremony"],
            values["source"],
            values["recovery_base"],
        )

    def test_exact_two_commit_recovery_with_exact_two_file_diff_is_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, recovery_base, ceremony = self.make_lineage(root)
            self.assertEqual(
                self.identity(root, source, recovery_base, ceremony).returncode, 0
            )

    def test_tag_push_mode_remains_admitted_without_recovery_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "-C", root, "config", "user.email", "tag@test.invalid"], check=True)
            subprocess.run(["git", "-C", root, "config", "user.name", "tag control"], check=True)
            (root / "source").write_text("tag source\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "source"], check=True)
            source = subprocess.check_output(
                ["git", "-C", root, "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(["git", "-C", root, "tag", "v0.4.13"], check=True)
            result = self.identity(
                root,
                source,
                source,
                source,
                event="push",
                ref="refs/tags/v0.4.13",
                ref_type="tag",
                ref_name="v0.4.13",
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_dispatch_ref_event_sha_parent_diff_and_cleanliness_are_load_bearing(self):
        cases = (
            "event", "ref", "ref_type", "ref_name", "event_sha", "source",
            "recovery_base", "dirty",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, recovery_base, ceremony = self.make_lineage(root)
                if case == "dirty":
                    (root / "untracked").write_text("dirty\n", encoding="utf-8")
                    result = self.identity(root, source, recovery_base, ceremony)
                else:
                    mutations = {
                        "event": {"event": "schedule"},
                        "ref": {"ref": "refs/heads/recovery"},
                        "ref_type": {"ref_type": "tag"},
                        "ref_name": {"ref_name": "release"},
                        "event_sha": {"event_sha": source},
                        "source": {"source": "f" * 40},
                        "recovery_base": {"recovery_base": source},
                    }
                    result = self.identity(
                        root, source, recovery_base, ceremony, **mutations[case]
                    )
                self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_extra_or_missing_allowed_path_is_rejected_by_actual_validator(self):
        for extra, omit in ((True, False), (False, True)):
            with self.subTest(extra=extra, omit=omit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, recovery_base, ceremony = self.make_lineage(
                    root, extra=extra, omit_test_change=omit
                )
                result = self.identity(root, source, recovery_base, ceremony)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("changed-path set differs", result.stderr)

    def test_third_recovery_commit_is_admitted_when_lineage_and_paths_stay_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, recovery_base, ceremony = self.make_lineage(root)
            (root / ".github" / "workflows" / "publish.yml").write_text(
                "later ceremony\n", encoding="utf-8"
            )
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "later"], check=True)
            later = subprocess.check_output(
                ["git", "-C", root, "rev-parse", "HEAD"], text=True
            ).strip()
            result = self.identity(root, source, recovery_base, later)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_remote_validator_binds_both_exact_refs(self):
        source, ceremony = "1" * 40, "2" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "main.json"
            tag = root / "tag.json"
            def write(path, ref, sha):
                path.write_text(
                    json.dumps({"ref": ref, "object": {"sha": sha, "type": "commit", "url": "https://api.invalid/object"}}),
                    encoding="utf-8",
                )
            write(main, "refs/heads/main", ceremony)
            write(tag, "refs/tags/v0.4.13", source)
            self.assertEqual(
                run_inline("INLINE_RECOVERY_REMOTE_VALIDATOR", main, tag, ceremony, source).returncode,
                0,
            )
            for target, ref, sha in (
                (main, "refs/heads/main", source),
                (main, "refs/heads/recovery", ceremony),
                (tag, "refs/tags/v0.4.13", ceremony),
                (tag, "refs/tags/v0.4.12", source),
            ):
                write(main, "refs/heads/main", ceremony)
                write(tag, "refs/tags/v0.4.13", source)
                write(target, ref, sha)
                self.assertNotEqual(
                    run_inline("INLINE_RECOVERY_REMOTE_VALIDATOR", main, tag, ceremony, source).returncode,
                    0,
                )

    def test_effect_validator_rederives_lineage_diff_main_and_tag(self):
        source, recovery_base, ceremony = "1" * 40, "2" * 40, "3" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                name: root / f"{name}.json"
                for name in ("commit", "comparison", "main", "tag")
            }
            records = {
                "commit": {
                    "sha": ceremony,
                    "parents": [{"sha": recovery_base, "url": "https://api.invalid/p", "html_url": "https://invalid/p"}],
                },
                "comparison": {
                    "status": "ahead", "ahead_by": 2, "behind_by": 0, "total_commits": 2,
                    "commits": [
                        {"sha": recovery_base, "parents": [{"sha": source}]},
                        {"sha": ceremony, "parents": [{"sha": recovery_base}]},
                    ],
                    "files": [
                        {"status": "modified", "filename": ".github/workflows/publish.yml"},
                        {"status": "modified", "filename": "tests/test_release_workflow.py"},
                    ],
                },
                "main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": ceremony}},
                "tag": {"ref": "refs/tags/v0.4.13", "object": {"type": "commit", "sha": source}},
            }
            def run(current):
                for name, value in current.items():
                    paths[name].write_text(json.dumps(value), encoding="utf-8")
                return run_inline(
                    "INLINE_RECOVERY_EFFECT_VALIDATOR",
                    paths["commit"], paths["comparison"], paths["main"], paths["tag"],
                    source, recovery_base, ceremony,
                )
            self.assertEqual(run(records).returncode, 0)
            mutations = (
                ("commit", "parents", []),
                ("comparison", "ahead_by", 3),
                ("comparison", "commits", [{"sha": ceremony, "parents": [{"sha": source}]}]),
                ("comparison", "files", records["comparison"]["files"] + [{"status": "modified", "filename": "src/main.rs"}]),
                ("main", "ref", "refs/heads/recovery"),
                ("main", "object", {"type": "commit", "sha": source}),
                ("tag", "ref", "refs/tags/v0.4.12"),
                ("tag", "object", {"type": "commit", "sha": ceremony}),
            )
            for name, key, value in mutations:
                with self.subTest(name=name, key=key):
                    hostile = json.loads(json.dumps(records))
                    hostile[name][key] = value
                    self.assertNotEqual(run(hostile).returncode, 0)

    def test_artifact_validator_requires_this_run_and_ceremony(self):
        artifact_id, run_id = "41", "77"
        digest, ceremony = "sha256:" + "a" * 64, "b" * 40
        name = "keyrx-release-" + "c" * 40
        exact = {
            "id": int(artifact_id),
            "name": name,
            "expired": False,
            "digest": digest,
            "workflow_run": {"id": int(run_id), "head_sha": ceremony},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            def check(record, *args):
                path.write_text(json.dumps(record), encoding="utf-8")
                return run_inline(
                    "INLINE_CURRENT_ARTIFACT_VALIDATOR", path,
                    *(args or (artifact_id, digest, run_id, ceremony, name)),
                )
            self.assertEqual(check(exact).returncode, 0)
            for key, value in (
                ("id", 42), ("name", name + "-other"), ("expired", True),
                ("digest", "sha256:" + "d" * 64),
                ("workflow_run", {"id": 78, "head_sha": ceremony}),
                ("workflow_run", {"id": int(run_id), "head_sha": "e" * 40}),
            ):
                with self.subTest(key=key, value=value):
                    hostile = json.loads(json.dumps(exact))
                    hostile[key] = value
                    self.assertNotEqual(check(hostile).returncode, 0)
            for args in (
                ("0", digest, run_id, ceremony, name),
                (artifact_id, digest.removeprefix("sha256:"), run_id, ceremony, name),
                (artifact_id, digest, "0", ceremony, name),
                (artifact_id, digest, run_id, "f" * 39, name),
            ):
                self.assertNotEqual(check(exact, *args).returncode, 0)


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = PUBLISH.read_text(encoding="utf-8")
        cls.prepare = cls.workflow.split("  prepare:\n", 1)[1].split("  effect:\n", 1)[0]
        cls.effect = cls.workflow.split("  effect:\n", 1)[1]
        cls._package_workspace = tempfile.TemporaryDirectory(
            prefix="keyrx-release-workflow-package-"
        )
        target = Path(cls._package_workspace.name) / "target"
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(target)
        package = subprocess.run(
            [
                "cargo",
                "+1.85.0",
                "package",
                "--locked",
                "--no-verify",
                "--offline",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if package.returncode != 0:
            raise AssertionError(
                "cannot create the isolated release-control crate:\n"
                + package.stderr
            )
        isolated_crate = target / "package" / "keyrx-0.4.13.crate"
        if not isolated_crate.is_file():
            raise AssertionError(
                f"isolated release-control crate is absent: {isolated_crate}"
            )
        supplied = os.environ.get("KEYRX_REAL_CRATE")
        if supplied is None:
            cls.real_crate = isolated_crate
            cls.uses_preserved_crate = False
        else:
            supplied_crate = Path(supplied)
            try:
                resolved = supplied_crate.resolve(strict=True)
                supplied_stat = os.lstat(supplied_crate)
            except OSError as error:
                raise AssertionError(
                    f"cannot resolve the preserved release-control crate: {error}"
                ) from error
            if (
                not supplied_crate.is_absolute()
                or supplied_crate != resolved
                or supplied_crate.name != "keyrx-0.4.13.crate"
                or not stat.S_ISREG(supplied_stat.st_mode)
                or supplied_stat.st_nlink != 1
            ):
                raise AssertionError(
                    "preserved release-control crate is not one canonical regular file"
                )
            if supplied_crate.read_bytes() != isolated_crate.read_bytes():
                raise AssertionError(
                    "preserved release-control crate differs from the isolated package"
                )
            cls.real_crate = supplied_crate
            cls.uses_preserved_crate = True

    @classmethod
    def tearDownClass(cls):
        if cls._package_workspace is not None:
            cls._package_workspace.cleanup()

    def test_publish_is_the_only_tag_release_orchestrator(self):
        self.assertFalse((PUBLISH.parent / "release.yml").exists())
        self.assertFalse((PUBLISH.parent / "reproducible.yml").exists())
        self.assertFalse((PUBLISH.parent / "yank.yml").exists())
        self.assertEqual(tag_workflow_names(PUBLISH.parent), ["publish.yml"])
        for path in sorted(PUBLISH.parent.glob("*.y*ml")):
            if path != PUBLISH:
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("crates.io/api/v1/crates/new", text, path.name)
                self.assertNotIn("cargo yank", text, path.name)

    def test_release_controls_own_an_isolated_package_prerequisite(self):
        workspace = Path(self._package_workspace.name)
        if self.uses_preserved_crate:
            self.assertEqual(self.real_crate, Path(os.environ["KEYRX_REAL_CRATE"]))
        else:
            self.assertIn(workspace, self.real_crate.parents)
            self.assertNotIn(ROOT / "target", self.real_crate.parents)
        self.assertEqual(self.real_crate.name, "keyrx-0.4.13.crate")

    def test_yaml_suffix_cannot_hide_a_second_tag_publisher(self):
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "safe.yml").write_text(
                "on:\n  push:\n    tags: ['v*']\n", encoding="utf-8"
            )
            (workflows / "evil.yaml").write_text(
                "on:\n  push:\n    tags: ['v*']\n", encoding="utf-8"
            )
            self.assertEqual(tag_workflow_names(workflows), ["evil.yaml", "safe.yml"])

    def test_release_actions_are_sha_pinned_and_dispatch_is_one_fixed_recovery(self):
        self.assertRegex(self.workflow, r"(?m)^  workflow_dispatch:\s*$")
        dispatch = self.workflow.split("  workflow_dispatch:\n", 1)[1].split(
            "\nconcurrency:", 1
        )[0]
        self.assertEqual(dispatch, "")
        self.assertIn(
            "source_sha=04df92e2f7a4ab56ad596c7fbe494e202d6c37b3",
            self.prepare,
        )
        self.assertIn(
            "RECOVERY_BASE_SHA: 008090445faeec52f84044ac73ed14fce93d58c4",
            self.workflow,
        )
        self.assertIn("fetch-depth: 0", self.prepare)
        self.assertIn('test "$RECOVERY_MODE" = true', self.prepare)
        self.assertIn("-- --test-threads=1", self.prepare)
        assert_immutable_dependencies(self, self.workflow)

    def test_two_jobs_separate_unprivileged_candidate_work_from_effects(self):
        jobs_tail = self.workflow.split("jobs:\n", 1)[1]
        self.assertEqual(
            re.findall(r"^  ([a-zA-Z0-9_-]+):\s*$", jobs_tail, re.MULTILINE),
            ["prepare", "effect"],
        )
        self.assertIn("permissions:\n      contents: read", self.prepare)
        self.assertNotIn("id-token: write", self.prepare)
        self.assertNotIn("attestations: write", self.prepare)
        self.assertIn("environment: release", self.effect)
        self.assertIn("actions: read", self.effect)
        self.assertIn("contents: write", self.effect)
        self.assertIn("id-token: write", self.effect)
        self.assertIn("attestations: write", self.effect)
        self.assertNotIn("actions/checkout", self.effect)
        for forbidden in (
            "python3 ops/",
            "node tests/",
            "cargo test",
            "cargo clippy",
            "cargo publish --dry-run",
        ):
            self.assertNotIn(forbidden, self.effect)
        self.assertEqual(self.effect.count('cargo package --locked --no-verify'), 1)
        self.assertIn('INLINE_RAW_SOURCE_MATERIALIZER_BEGIN', self.effect)
        self.assertNotIn('sparse-checkout', self.effect)
        self.assertIn('repository executable is allowed here', self.effect)

    def test_prepare_python_sequence_leaves_fresh_initialized_copy_exactly_clean(self):
        self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', self.workflow)
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "clone"
            shutil.copytree(
                ROOT,
                clone,
                ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
            )
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            for command in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "test@invalid"],
                ["git", "config", "user.name", "release-control"],
                ["git", "add", "-A"],
                ["git", "commit", "-qm", "fixture"],
                ["python3", "ops/release_contract.py", "ops/release/0.4.13.json"],
                ["python3", "ops/release_preflight.py", "0.4.13"],
                ["python3", "ops/release_preflight.py", "0.4.13", "--notes"],
            ):
                result = subprocess.run(command, cwd=clone, env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, (command, result.stderr.decode()))
            status = subprocess.check_output(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=clone, env=env
            )
            self.assertEqual(status, b"")

    def test_concurrency_schema_is_valid_and_scoped_to_the_exact_tag(self):
        self.assertIn("group: publish-${{ github.repository }}-${{ github.ref }}", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertNotIn("queue:", self.workflow)

    def test_effects_are_behind_preconditions_assets_and_attestation(self):
        markers = [
            "environment: release",
            "Bind every prepared byte before any public effect",
            "Prove external prerequisites before requesting an attestation",
            "Attest the archive before any draft or registry effect",
            "Validate and stage new provenance without candidate code",
            "Create one inert draft after provenance is green",
            "Upload exactly six validated assets to the draft",
            "Verify exact draft bytes and provenance before crates.io",
            "Obtain one short-lived trusted-publisher token",
            "Upload the preserved crate only when absent",
            "Require crates.io to hold the exact prepared archive",
            "Publish the already-proven draft as immutable",
            "Verify immutable release and exact asset API identities",
            "Rebind refs and require exact reviewed yank inputs",
            "Yank only the exact reviewed predecessor set",
        ]
        positions = [self.workflow.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("continue-on-error", self.workflow)
        self.assertNotIn("|| true", self.workflow)

    def test_exact_source_and_remote_authorization_are_rechecked_at_effect_boundaries(self):
        self.assertGreaterEqual(self.effect.count("git/ref/heads/main"), 4)
        self.assertGreaterEqual(self.effect.count("commits/$TAG"), 3)
        self.assertIn("git/ref/$ref", self.effect)
        self.assertIn("tags/v$predecessor", self.effect)
        self.assertEqual(self.effect.count("immutable-releases"), 5)
        self.assertEqual(self.effect.count('test "$immutable_status" = 200'), 5)
        self.assertEqual(
            self.effect.count(
                '.enabled == true and (.enforced_by_owner | type) == "boolean"'
            ),
            5,
        )
        self.assertNotIn('keys == ["enabled"]', self.effect)
        self.assertIn("GH_ADMIN_READ_TOKEN", self.effect)

    def test_asset_upload_uses_and_pins_the_release_api_upload_template(self):
        self.assertNotIn("GITHUB_UPLOAD_URL", self.workflow)
        self.assertIn(
            'get "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/releases/$release_id" > "$release_json"',
            self.effect,
        )
        self.assertIn('upload_template="$(jq -er .upload_url "$release_json")"', self.effect)
        self.assertIn(
            'expected_upload_template="https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets{?name,label}"',
            self.effect,
        )
        self.assertIn('test "$upload_template" = "$expected_upload_template"', self.effect)
        self.assertIn('"$upload_url?name=$name"', self.effect)

    def test_actual_asset_upload_block_reuses_empty_draft_and_posts_exact_six(self):
        names = [
            "keyrx-0.4.13.crate",
            "keyrx-0.4.13.crate.sha256",
            "keyrx-0.4.13.cdx.json",
            "keyrx-0.4.13.crate.sigstore.json",
            "keyrx-0.4.13.crate.intoto.jsonl",
            "keyrx-0.4.13.SHA256SUMS",
        ]
        curl_shim = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, urllib.parse

args = sys.argv[1:]
url = args[-1]
method = args[args.index("-X") + 1] if "-X" in args else "GET"
output = pathlib.Path(args[args.index("-o") + 1]) if "-o" in args else None
log = pathlib.Path(os.environ["CURL_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"method": method, "url": url}, sort_keys=True) + "\n")

api = os.environ["GITHUB_API_URL"]
repo = os.environ["GITHUB_REPOSITORY"]
release_id = os.environ["OLD_RELEASE_ID"]
mode = os.environ["UPLOAD_FIXTURE"]

def emit(value):
    data = json.dumps(value, separators=(",", ":")) + "\n"
    if output is None:
        sys.stdout.write(data)
    else:
        output.write_text(data, encoding="utf-8")

if method == "GET" and url == f"{api}/repos/{repo}/git/ref/heads/main":
    emit({"object": {"sha": os.environ["CEREMONY_SHA"]}})
elif method == "GET" and url == f"{api}/repos/{repo}/git/ref/tags/{os.environ['TAG']}":
    emit({"object": {"sha": os.environ["SOURCE_SHA"]}})
elif method == "GET" and url == f"{api}/repos/{repo}/commits/{os.environ['TAG']}":
    emit({"sha": os.environ["SOURCE_SHA"]})
elif method == "GET" and url == f"{api}/repos/{repo}/releases/{release_id}":
    template = f"https://uploads.github.com/repos/{repo}/releases/{release_id}/assets{{?name,label}}"
    if mode == "missing":
        emit({"id": int(release_id)})
    elif mode == "wrong-host":
        emit({"id": int(release_id), "upload_url": template.replace("uploads.github.com", "invalid.example")})
    elif mode == "wrong-template":
        emit({"id": int(release_id), "upload_url": template.replace("{?name,label}", "{?name}")})
    else:
        emit({"id": int(release_id), "upload_url": template})
elif method == "POST":
    parsed = urllib.parse.urlsplit(url)
    expected_path = f"/repos/{repo}/releases/{release_id}/assets"
    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    if (parsed.scheme, parsed.netloc, parsed.path) != ("https", "uploads.github.com", expected_path) or set(query) != {"name"} or len(query["name"]) != 1:
        raise SystemExit(91)
    prior = [json.loads(line) for line in log.read_text("utf-8").splitlines()]
    asset_id = 1000 + sum(item["method"] == "POST" for item in prior)
    name = query["name"][0]
    emit({"id": asset_id, "name": name, "state": "uploaded", "url": f"{api}/repos/{repo}/releases/assets/{asset_id}"})
else:
    raise SystemExit(92)
'''
        jq_shim = r'''#!/usr/bin/env python3
import json, pathlib, sys

args = sys.argv[1:]
raw = any("r" in item for item in args if item.startswith("-"))
variables = {}
while "--arg" in args:
    index = args.index("--arg")
    variables[args[index + 1]] = args[index + 2]
    del args[index:index + 3]
args = [item for item in args if not item.startswith("-")]
expression = args[0]
value = json.loads(pathlib.Path(args[1]).read_text("utf-8")) if len(args) > 1 else json.load(sys.stdin)
if expression == ".object.sha":
    answer = value.get("object", {}).get("sha")
elif expression == ".sha":
    answer = value.get("sha")
elif expression == ".upload_url":
    answer = value.get("upload_url")
elif expression == ".id":
    answer = value.get("id")
elif ".name == $name" in expression and ".state == \"uploaded\"" in expression:
    answer = value.get("name") == variables.get("name") and value.get("state") == "uploaded" and value.get("url") == variables.get("url")
else:
    raise SystemExit(93)
if answer is None or answer is False:
    raise SystemExit(1)
if answer is not True:
    print(answer if raw else json.dumps(answer, separators=(",", ":")))
'''

        def execute(mode):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prepared = root / "prepared"
                binary = root / "bin"
                prepared.mkdir()
                binary.mkdir()
                for name in names:
                    (prepared / name).write_bytes(b"fixture")
                shim = binary / "curl"
                shim.write_text(curl_shim, encoding="utf-8")
                shim.chmod(0o700)
                shim = binary / "jq"
                shim.write_text(jq_shim, encoding="utf-8")
                shim.chmod(0o700)
                log = root / "curl.jsonl"
                env = {
                    **os.environ,
                    "PATH": f"{binary}:{os.environ['PATH']}",
                    "CURL_LOG": str(log),
                    "UPLOAD_FIXTURE": mode,
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_REPOSITORY": "keyrx/keyrx",
                    "GH_TOKEN": "fixture-token",
                    "CEREMONY_SHA": "3" * 40,
                    "SOURCE_SHA": "1" * 40,
                    "TAG": "v0.4.13",
                    "NEW_RELEASE_ID": "",
                    "OLD_RELEASE_ID": "381520377",
                    "RUNNER_TEMP": str(root),
                    "CRATE_NAME": "keyrx",
                    "VERSION": "0.4.13",
                }
                result = subprocess.run(
                    ["bash", "-c", inline_shell("INLINE_DRAFT_ASSET_UPLOAD")],
                    cwd=root, env=env, text=True, capture_output=True, check=False,
                )
                records = [
                    json.loads(line)
                    for line in log.read_text("utf-8").splitlines()
                ] if log.exists() else []
                return result, records

        result, records = execute("exact")
        self.assertEqual(result.returncode, 0, result.stderr)
        posts = [item["url"] for item in records if item["method"] == "POST"]
        self.assertEqual(
            posts,
            [
                f"https://uploads.github.com/repos/keyrx/keyrx/releases/381520377/assets?name={name}"
                for name in names
            ],
        )
        self.assertIn(
            {"method": "GET", "url": "https://api.github.com/repos/keyrx/keyrx/releases/381520377"},
            records,
        )
        for mode in ("missing", "wrong-host", "wrong-template"):
            with self.subTest(mode=mode):
                result, records = execute(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(item["method"] == "POST" for item in records))

    def test_immutable_response_policy_accepts_documented_and_additive_shapes(self):
        predicate = '.enabled == true and (.enforced_by_owner | type) == "boolean"'
        self.assertEqual(
            re.findall(r"jq -e '([^']*\.enforced_by_owner[^']*)'", self.effect),
            [predicate] * 5,
        )

        def admitted(value):
            return (
                isinstance(value, dict)
                and value.get("enabled") is True
                and type(value.get("enforced_by_owner")) is bool
            )

        documented = {"enabled": True, "enforced_by_owner": False}
        self.assertTrue(admitted(documented))
        self.assertTrue(admitted({**documented, "future_field": {"value": 1}}))
        self.assertTrue(admitted({"enabled": True, "enforced_by_owner": True}))
        for hostile in (
            {"enabled": True},
            {"enabled": False, "enforced_by_owner": False},
            {"enabled": True, "enforced_by_owner": "false"},
        ):
            self.assertFalse(admitted(hostile))

        old_policy = lambda value: set(value) == {"enabled"} and value["enabled"] is True
        self.assertFalse(old_policy(documented))

    def test_source_and_ceremony_own_distinct_release_identities(self):
        self.assertIn("SOURCE_SHA: ${{ needs.prepare.outputs.source_sha }}", self.effect)
        self.assertIn("CEREMONY_SHA: ${{ needs.prepare.outputs.ceremony_sha }}", self.effect)
        self.assertIn('run.get("head_sha") != ceremony', self.effect)
        self.assertNotIn('--source-digest "$SOURCE_SHA"', self.effect)
        self.assertEqual(self.effect.count('--source-digest "$CEREMONY_SHA"'), 4)
        self.assertGreaterEqual(
            self.effect.count('--arg sha "$CEREMONY_SHA"'), 6
        )
        self.assertIn('--arg sha "$SOURCE_SHA" --arg title "$TITLE"', self.effect)
        self.assertGreaterEqual(
            self.effect.count('commits/$TAG" | jq -er .sha)" = "$SOURCE_SHA"'),
            8,
        )

    def test_reviewed_manifest_not_dynamic_registry_discovery_owns_yanks(self):
        policy = (ROOT / "ops" / "release" / "0.4.13.json").read_text(encoding="utf-8")
        self.assertIn('"expectedLiveBefore"', policy)
        self.assertIn('"yankTargets"', policy)
        self.assertIn('"0.4.12"', policy)
        self.assertIn(
            "dcf2ff724aa2d0ec43173a2d1a7f225ea39efa8c5d61e43b02c82b26a4f7854d",
            policy,
        )
        self.assertIn(".expectedLiveBefore", self.effect)
        self.assertIn(".yankTargets", self.effect)
        self.assertNotIn("release_state.py yank-plan", self.workflow)
        self.assertNotRegex(self.effect, r"cargo yank.*\$\(.*versions")

    def test_actual_inline_policy_validator_rejects_future_legacy_policy(self):
        policy = json.loads((ROOT / "ops" / "release" / "0.4.13.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            self.assertEqual(
                run_inline("INLINE_POLICY_VALIDATOR", path, "0.4.13", "v0.4.13").returncode,
                0,
            )
            policy["version"] = "0.4.14"
            policy["tag"] = "v0.4.14"
            path.write_text(json.dumps(policy), encoding="utf-8")
            result = run_inline("INLINE_POLICY_VALIDATOR", path, "0.4.14", "v0.4.14")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not the reviewed 0.4.13", result.stderr)

    def test_actual_inline_upload_validator_blocks_mutated_metadata_before_token_or_put(self):
        version = "0.4.13"
        root = f"keyrx-{version}"
        manifest = (ROOT / "Cargo.toml").read_bytes()
        lock = (ROOT / "Cargo.lock").read_bytes()
        readme = (ROOT / "README.md").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            crate = directory / f"keyrx-{version}.crate"
            with tarfile.open(crate, "w:gz") as archive:
                for name, data in (("Cargo.toml.orig", manifest), ("Cargo.lock", lock), ("README.md", readme)):
                    member = tarfile.TarInfo(f"{root}/{name}")
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            # Obtain the exact expected object once from the shipping validator's
            # diagnostic boundary by matching the candidate helper's output; the
            # validator independently reconstructs it from the archive.
            metadata_json = directory / "metadata.json"
            metadata = json.loads(
                subprocess.check_output(
                    ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                    cwd=ROOT,
                    text=True,
                )
            )
            helper = ROOT / "ops" / "crates_upload.py"
            body = directory / "body"
            subprocess.run(
                ["python3", str(helper), version, str(crate), str(directory / "cargo.json"), str(body)],
                check=False,
                capture_output=True,
            )
            # Write cargo metadata and build again; the first deliberately
            # missing-input call above must not affect the actual control.
            (directory / "cargo.json").write_text(json.dumps(metadata), encoding="utf-8")
            subprocess.run(
                ["python3", str(helper), version, str(crate), str(directory / "cargo.json"), str(body)],
                check=True,
                capture_output=True,
            )
            raw = body.read_bytes()
            size = struct.unpack("<I", raw[:4])[0]
            candidate = json.loads(raw[4 : 4 + size])
            metadata_json.write_text(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"), sort_keys=True), encoding="utf-8")
            self.assertEqual(
                run_inline("INLINE_UPLOAD_METADATA_VALIDATOR", crate, metadata_json, version).returncode,
                0,
            )
            canonical_bytes = metadata_json.read_bytes()
            metadata_json.write_bytes(b" " + canonical_bytes)
            self.assertNotEqual(run_inline("INLINE_UPLOAD_METADATA_VALIDATOR", crate, metadata_json, version).returncode, 0)
            metadata_json.write_text(json.dumps(candidate, separators=(",", ":"), sort_keys=False), encoding="utf-8")
            self.assertNotEqual(run_inline("INLINE_UPLOAD_METADATA_VALIDATOR", crate, metadata_json, version).returncode, 0)
            duplicate = canonical_bytes.replace(b'{"authors":', b'{"name":"keyrx","authors":', 1)
            metadata_json.write_bytes(duplicate)
            self.assertNotEqual(run_inline("INLINE_UPLOAD_METADATA_VALIDATOR", crate, metadata_json, version).returncode, 0)
            candidate["repository"] = "https://attacker.invalid/repo"
            metadata_json.write_text(json.dumps(candidate), encoding="utf-8")
            effects = []
            result = run_inline("INLINE_UPLOAD_METADATA_VALIDATOR", crate, metadata_json, version)
            if result.returncode == 0:
                effects.extend(["oidc-token", "crates-put"])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(effects, [])

    def test_actual_prepared_manifest_validator_rejects_extra_missing_and_checksum_lines(self):
        version = "0.4.13"
        names = [f"keyrx-{version}.crate", f"keyrx-{version}.crate.sha256", f"keyrx-{version}.cdx.json", f"keyrx-{version}.crates-api-upload", "release-notes.md", "release-policy.json"]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for name in names:
                (directory / name).write_bytes(("bytes:" + name).encode())
            crate = directory / names[0]
            (directory / names[1]).write_text(f"{hashlib.sha256(crate.read_bytes()).hexdigest()}  {names[0]}\n", encoding="ascii")
            manifest = directory / "PREPARED_SHA256SUMS"
            def rows(selected=names):
                manifest.write_text("".join(f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n" for name in selected), encoding="ascii")
            def check(): return subprocess.run(["python3", "-", manifest.name, version], input=inline_python("INLINE_PREPARED_MANIFEST_VALIDATOR"), text=True, cwd=directory, capture_output=True)
            rows(); self.assertEqual(check().returncode, 0)
            rows(names[:-1]); self.assertNotEqual(check().returncode, 0)
            (directory / "extra").write_bytes(b"x"); rows(names + ["extra"]); self.assertNotEqual(check().returncode, 0)
            rows(); (directory / names[1]).write_text((directory / names[1]).read_text() + "extra\n", encoding="ascii"); rows()
            self.assertNotEqual(check().returncode, 0)

    def test_actual_source_binder_rejects_source_notes_and_cdx_substitution(self):
        version, source_sha = "0.4.13", "1" * 40
        original = b'''[package]\nname="keyrx"\nversion="0.4.13"\nedition="2021"\nrust-version="1.85"\ndescription="d"\nhomepage="https://keyrx.tech"\nreadme="README.md"\nkeywords=[]\ncategories=[]\nlicense="MIT"\nrepository="https://github.com/keyrx/keyrx"\ninclude=["/src/**","/Cargo.toml","/Cargo.lock","/README.md","/LICENSE","/TRADEMARK.md","/CHANGELOG.md"]\n[[bin]]\nname="keyrx"\npath="src/main.rs"\n[dependencies]\nfoo="1.2"\n[profile.release]\nopt-level=3\n'''
        generated = b"# THIS FILE IS AUTOMATICALLY GENERATED BY CARGO\n" + original.replace(
            b"[[bin]]", b"build=false\nautolib=false\nautobins=false\nautoexamples=false\nautotests=false\nautobenches=false\n[[bin]]", 1
        )
        lock = b'''version = 3\n[[package]]\nname="keyrx"\nversion="0.4.13"\ndependencies=["foo"]\n[[package]]\nname="foo"\nversion="1.2.3"\n'''
        source_values = {
            "Cargo.toml": original, "Cargo.lock": lock,
            "CHANGELOG.md": b"# Changelog\n\n## 0.4.13 - 2026-09-02\n\n- Exact notes.\n\n## 0.4.12 - 2026-08-24\n\n- Old.\n",
            "LICENSE": b"license\n", "README.md": b"readme\n", "TRADEMARK.md": b"mark\n",
            "src/evm.rs": b"evm\n", "src/main.rs": b"main\n", "src/ui.rs": b"ui\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); source = directory / "source"; source.mkdir()
            for name, data in source_values.items():
                path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            root = f"keyrx-{version}"; crate = directory / f"keyrx-{version}.crate"
            members = {
                f"{root}/Cargo.toml.orig": original, f"{root}/Cargo.toml": generated,
                f"{root}/.cargo_vcs_info.json": json.dumps({"git": {"sha1": source_sha}, "path_in_vcs": ""}).encode(),
            }
            for name, data in source_values.items():
                if name != "Cargo.toml": members[f"{root}/{name}"] = data
            order = [f"{root}/{name}" for name in (".cargo_vcs_info.json", "CHANGELOG.md", "Cargo.lock", "Cargo.toml", "Cargo.toml.orig", "LICENSE", "README.md", "TRADEMARK.md", "src/evm.rs", "src/main.rs", "src/ui.rs")]
            generated_names = {f"{root}/.cargo_vcs_info.json", f"{root}/Cargo.lock", f"{root}/Cargo.toml"}
            def write_crate(values=None, order_override=None, mode_override=None):
                values = members if values is None else values
                with tarfile.open(crate, "w:gz") as archive:
                    for name in order if order_override is None else order_override:
                        data = values[name]
                        member = tarfile.TarInfo(name); member.size = len(data)
                        member.mode = mode_override if mode_override and name == order[0] else 0o644
                        member.uid = member.gid = 0; member.uname = member.gname = ""
                        member.mtime = 1 if name in generated_names else 1700000000
                        archive.addfile(member, io.BytesIO(data))
            write_crate()
            notes = directory / "notes.md"; notes.write_text("- Exact notes.\n", encoding="utf-8")
            cdx = directory / "cdx.json"
            root_ref, foo_ref = f"pkg:cargo/keyrx@{version}", "pkg:cargo/foo@1.2.3"
            serial = str(uuid.UUID(hashlib.sha256((source_sha + "\0keyrx-cdx-1.5").encode()).hexdigest()[:32]))
            valid_cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{serial}", "version": 1,
                "metadata": {"component": {"type": "application", "bom-ref": root_ref, "name": "keyrx", "version": version, "purl": root_ref, "licenses": [{"license": {"id": "MIT"}}]}},
                "components": [{"type": "library", "bom-ref": foo_ref, "name": "foo", "version": "1.2.3", "purl": foo_ref}],
                "dependencies": [{"ref": root_ref, "dependsOn": [foo_ref]}, {"ref": foo_ref, "dependsOn": []}]}
            def write_cdx(value=valid_cdx):
                cdx.write_bytes(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            write_cdx()
            def check(): return run_inline("INLINE_SOURCE_BINDER", crate, source, notes, cdx, source_sha, version)
            self.assertEqual(check().returncode, 0, check().stderr)
            hostile = dict(members); hostile[f"{root}/src/main.rs"] = b"hostile\n"; write_crate(hostile)
            # Model a hostile prepare job recomputing both its framed upload and
            # handoff digest around the substituted archive. The effect-side
            # source binder still owns admission before any public effect.
            fake_metadata = b'{"name":"keyrx","vers":"0.4.13"}'
            hostile_upload = struct.pack("<I", len(fake_metadata)) + fake_metadata + struct.pack("<I", crate.stat().st_size) + crate.read_bytes()
            self.assertEqual(hostile_upload[-crate.stat().st_size :], crate.read_bytes())
            self.assertRegex(hashlib.sha256(hostile_upload).hexdigest(), r"^[0-9a-f]{64}$")
            effects = []
            result = check()
            if result.returncode == 0: effects.append("write-provider-attestation")
            self.assertIn("differs from Git blob", result.stderr)
            self.assertEqual(effects, [])
            write_crate(); notes.write_text("hostile\n", encoding="utf-8")
            self.assertIn("release notes differ", check().stderr)
            notes.write_text("- Exact notes.\n", encoding="utf-8")
            hostile_cdx = json.loads(json.dumps(valid_cdx)); hostile_cdx["components"] = []
            write_cdx(hostile_cdx)
            self.assertIn("SBOM component set differs", check().stderr)
            write_cdx(); crate.write_bytes(crate.read_bytes() + b"trailer")
            self.assertIn("gzip is not one fully-consumed member", check().stderr)
            write_crate(mode_override=0o755)
            self.assertIn("unsafe/non-canonical crate metadata", check().stderr)
            write_crate(order_override=list(reversed(order)))
            self.assertIn("crate member set differs", check().stderr)

            write_crate(); write_cdx()
            variants = []
            false_license = json.loads(json.dumps(valid_cdx)); false_license["metadata"]["component"]["licenses"] = [{"license": {"id": "Apache-2.0"}}]; variants.append(false_license)
            duplicate_component = json.loads(json.dumps(valid_cdx)); duplicate_component["components"].append(duplicate_component["components"][0]); variants.append(duplicate_component)
            wrong_spec = json.loads(json.dumps(valid_cdx)); wrong_spec["specVersion"] = "1.6"; variants.append(wrong_spec)
            false_hash = json.loads(json.dumps(valid_cdx)); false_hash["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "0" * 64}]; variants.append(false_hash)
            vulnerabilities = json.loads(json.dumps(valid_cdx)); vulnerabilities["vulnerabilities"] = []; variants.append(vulnerabilities)
            arbitrary = json.loads(json.dumps(valid_cdx)); arbitrary["surprise"] = True; variants.append(arbitrary)
            for variant in variants:
                write_cdx(variant)
                self.assertNotEqual(check().returncode, 0)
            cdx.write_bytes(cdx.read_bytes().replace(b'"version":1', b'"version":1,"version":1', 1))
            self.assertIn("CDX duplicate key", check().stderr)

            write_cdx()
            hostile_original = original.replace(b'foo="1.2"', b'foo={version="1.2",path="../foo"}')
            hostile_generated = b"# THIS FILE IS AUTOMATICALLY GENERATED BY CARGO\n" + hostile_original.replace(
                b"[[bin]]", b"build=false\nautolib=false\nautobins=false\nautoexamples=false\nautotests=false\nautobenches=false\n[[bin]]", 1
            )
            (source / "Cargo.toml").write_bytes(hostile_original)
            hostile_manifest = dict(members)
            hostile_manifest[f"{root}/Cargo.toml.orig"] = hostile_original
            hostile_manifest[f"{root}/Cargo.toml"] = hostile_generated
            write_crate(hostile_manifest)
            self.assertIn("dependency has forbidden/unknown keys", check().stderr)
            (source / "Cargo.toml").write_bytes(original)

            write_cdx()
            canonical_changelog = source_values["CHANGELOG.md"]
            def changelog_control(value, expected=None):
                (source / "CHANGELOG.md").write_bytes(value)
                changed = dict(members); changed[f"{root}/CHANGELOG.md"] = value
                write_crate(changed)
                result = check()
                if expected is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertIn(expected, result.stderr)
            changelog_control(canonical_changelog.replace(
                b"## 0.4.12", b"## 0.4.13 - 2026-09-01\n\n- duplicate.\n\n## 0.4.12"
            ), "release headings are not unique")
            changelog_control(canonical_changelog.replace(b"## 0.4.12 - 2026-08-24", b"## 0.4.x - soon"), "malformed release heading")
            changelog_control(b"# Changelog\n\n## 0.4.14 - 2026-09-03\n\n- Newer.\n\n" + canonical_changelog.split(b"# Changelog\n\n", 1)[1], "release is not unique newest")
            changelog_control(canonical_changelog.replace(b"2026-09-02", b"2026-99-99"), "invalid release date")
            hidden = canonical_changelog.replace(
                b"- Exact notes.\n", b"- Exact notes.\n\n```text <!-- literal\n## 9.9.9 - malformed\n```\n\n<!-- ## 8.8.8 - malformed -->\n"
            )
            notes.write_text("- Exact notes.\n\n```text <!-- literal\n## 9.9.9 - malformed\n```\n\n<!-- ## 8.8.8 - malformed -->\n", encoding="utf-8")
            changelog_control(hidden)

    def test_real_cargo_crate_source_substitution_stays_red_after_candidate_rehash(self):
        version = "0.4.13"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            original_crate = self.real_crate
            hostile_crate = directory / original_crate.name
            with tarfile.open(original_crate, "r:gz") as source_archive, tarfile.open(hostile_crate, "w:gz") as hostile_archive:
                for member in source_archive.getmembers():
                    stream = source_archive.extractfile(member)
                    data = stream.read() if stream else b""
                    if member.name == f"keyrx-{version}/src/main.rs":
                        data += b"\n// hostile candidate substitution\n"
                        member.size = len(data)
                    hostile_archive.addfile(member, io.BytesIO(data))
            source_sha = json.loads(
                subprocess.check_output(
                    ["tar", "-xOf", str(original_crate), f"keyrx-{version}/.cargo_vcs_info.json"], text=True
                )
            )["git"]["sha1"]
            notes = directory / "release-notes.md"
            notes.write_text(subprocess.check_output(
                ["python3", str(ROOT / "ops/release_preflight.py"), version, "--notes"], cwd=ROOT, text=True
            ), encoding="utf-8")
            cdx = directory / f"keyrx-{version}.cdx.json"; cdx.write_text("{}", encoding="utf-8")
            crate_sha = hashlib.sha256(hostile_crate.read_bytes()).hexdigest()
            crate_sha_file = directory / f"keyrx-{version}.crate.sha256"
            crate_sha_file.write_text(f"{crate_sha}  {hostile_crate.name}\n", encoding="ascii")
            metadata = b'{"name":"keyrx","vers":"0.4.13"}'
            upload = struct.pack("<I", len(metadata)) + metadata + struct.pack("<I", hostile_crate.stat().st_size) + hostile_crate.read_bytes()
            upload_file = directory / f"keyrx-{version}.crates-api-upload"; upload_file.write_bytes(upload)
            policy_file = directory / "release-policy.json"
            policy_file.write_bytes((ROOT / "ops/release/0.4.13.json").read_bytes())
            handoff = directory / "PREPARED_SHA256SUMS"
            prepared = (hostile_crate, crate_sha_file, cdx, upload_file, notes, policy_file)
            handoff.write_text("".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in prepared
            ), encoding="ascii")
            self.assertEqual(hashlib.sha256(hostile_crate.read_bytes()).hexdigest(), crate_sha)
            self.assertEqual(upload[-hostile_crate.stat().st_size:], hostile_crate.read_bytes())
            for row, path in zip(handoff.read_text("ascii").splitlines(), prepared):
                self.assertEqual(row, f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
            effects = []
            result = run_inline("INLINE_SOURCE_BINDER", hostile_crate, ROOT, notes, cdx, source_sha, version)
            if result.returncode == 0:
                effects.append("provider-attestation")
            self.assertIn("differs from Git blob", result.stderr)
            self.assertEqual(effects, [])

    def test_exact_crate_binder_rejects_every_archive_encoding_substitution_after_rehash(self):
        version = "0.4.13"
        expected = self.real_crate
        canonical = expected.read_bytes()
        self.assertEqual(run_inline("INLINE_EXACT_CRATE_BINDER", expected, expected).returncode, 0)
        name_end = canonical.index(b"\0", 10) + 1
        raw_tar = zlib.decompress(canonical, 16 + zlib.MAX_WBITS)
        def gzip_with_zlib(payload, strategy=zlib.Z_DEFAULT_STRATEGY):
            header = canonical[:name_end]
            compressor = zlib.compressobj(
                9, zlib.DEFLATED, -15, zlib.DEF_MEM_LEVEL, strategy
            )
            return header + compressor.compress(payload) + compressor.flush() + struct.pack(
                "<II", zlib.crc32(payload) & 0xffffffff, len(payload) & 0xffffffff
            )
        def rebuilt_tar(mutator):
            output = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as source, tarfile.open(fileobj=output, mode="w:") as target:
                for member in source.getmembers():
                    stream = source.extractfile(member); data = stream.read() if stream else b""
                    member, data = mutator(member, data)
                    member.size = len(data); target.addfile(member, io.BytesIO(data))
            return output.getvalue()
        variants = {}
        value = bytearray(canonical); value[4] ^= 1; variants["gzip-mtime"] = bytes(value)
        value = bytearray(canonical); value[10] = ord("K"); variants["gzip-fname"] = bytes(value)
        value = bytearray(canonical); value[8] ^= 1; variants["gzip-xfl"] = bytes(value)
        value = bytearray(canonical); value[9] ^= 1; variants["gzip-os"] = bytes(value)
        variants["gzip-extra"] = canonical[:3] + bytes([canonical[3] | 4]) + canonical[4:10] + b"\x02\x00zz" + canonical[10:]
        variants["gzip-comment"] = canonical[:3] + bytes([canonical[3] | 16]) + canonical[4:name_end] + b"comment\0" + canonical[name_end:]
        hcrc_header = canonical[:3] + bytes([canonical[3] | 2]) + canonical[4:name_end]
        variants["gzip-hcrc"] = hcrc_header + struct.pack("<H", zlib.crc32(hcrc_header) & 0xffff) + canonical[name_end:]
        variants["deflate-stream"] = gzip_with_zlib(raw_tar, zlib.Z_FIXED)
        padded = bytearray(raw_tar); padded[1023] = 1; variants["tar-padding"] = gzip_with_zlib(bytes(padded))
        variants["tar-header-representation"] = gzip_with_zlib(rebuilt_tar(lambda member, data: (member, data)))
        def changed_mtime(member, data):
            if member.name.endswith("/CHANGELOG.md"): member.mtime += 1
            return member, data
        variants["common-source-mtime"] = gzip_with_zlib(rebuilt_tar(changed_mtime))
        def changed_manifest(member, data):
            if member.name.endswith("/Cargo.toml"): data += b"\n# semantically inert\n"
            return member, data
        variants["generated-toml-comment"] = gzip_with_zlib(rebuilt_tar(changed_manifest))
        def changed_vcs(member, data):
            if member.name.endswith("/.cargo_vcs_info.json"):
                value = json.loads(data); sha = value["git"]["sha1"]
                data = ('{ "git": {"sha1":"%s","sha1":"%s"}, "path_in_vcs":"" }' % (sha, sha)).encode()
            return member, data
        variants["vcs-json-duplicate-whitespace"] = gzip_with_zlib(rebuilt_tar(changed_vcs))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            cargo_metadata = directory / "cargo-metadata.json"
            cargo_metadata.write_bytes(subprocess.check_output(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT
            ))
            for label, payload in variants.items():
                with self.subTest(label=label):
                    self.assertNotEqual(
                        payload, canonical, f"{label} did not change the crate bytes"
                    )
                    variant_dir = directory / label; variant_dir.mkdir()
                    candidate = variant_dir / f"keyrx-{version}.crate"; candidate.write_bytes(payload)
                    checksum = variant_dir / f"keyrx-{version}.crate.sha256"
                    checksum.write_text(f"{hashlib.sha256(payload).hexdigest()}  {candidate.name}\n", encoding="ascii")
                    upload = variant_dir / f"keyrx-{version}.crates-api-upload"
                    built = subprocess.run(
                        ["python3", str(ROOT / "ops/crates_upload.py"), version, str(candidate), str(cargo_metadata), str(upload)],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(built.returncode, 0, built.stderr)
                    cdx = variant_dir / f"keyrx-{version}.cdx.json"; cdx.write_bytes(b"{}")
                    notes = variant_dir / "release-notes.md"; notes.write_bytes(b"notes\n")
                    policy = variant_dir / "release-policy.json"; policy.write_bytes((ROOT / "ops/release/0.4.13.json").read_bytes())
                    ancillary = [checksum, cdx, upload, notes, policy]
                    manifest = "".join(
                        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                        for path in (candidate, *ancillary)
                    )
                    self.assertEqual(len(manifest.splitlines()), 6)
                    effects = []
                    result = run_inline("INLINE_EXACT_CRATE_BINDER", candidate, expected)
                    if result.returncode == 0: effects.append("provider-attestation")
                    self.assertIn("candidate bytes differ", result.stderr)
                    self.assertEqual(effects, [])

    def test_source_tree_response_is_bound_to_requested_tree_sha(self):
        expected = "1" * 40
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tree.json"
            def check(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                return run_inline("INLINE_TREE_RESPONSE_VALIDATOR", path, expected)
            self.assertEqual(check({"sha": expected, "truncated": False, "tree": []}).returncode, 0)
            result = check({"sha": "2" * 40, "truncated": False, "tree": []})
            self.assertIn("response identity", result.stderr)
            self.assertNotEqual(check({"sha": expected, "truncated": True, "tree": []}).returncode, 0)

    def test_hostile_fetched_manifest_refuses_before_cargo_or_any_effect_boundary(self):
        version = "0.4.13"
        safe_crate = self.real_crate
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            safe_copy = directory / safe_crate.name; safe_copy.write_bytes(safe_crate.read_bytes())
            metadata = directory / "metadata.json"
            metadata.write_bytes(subprocess.check_output(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT
            ))
            upload = directory / f"keyrx-{version}.crates-api-upload"
            subprocess.run(
                ["python3", str(ROOT / "ops/crates_upload.py"), version, str(safe_copy), str(metadata), str(upload)],
                check=True, capture_output=True,
            )
            ancillary = []
            checksum = directory / f"keyrx-{version}.crate.sha256"
            checksum.write_text(f"{hashlib.sha256(safe_copy.read_bytes()).hexdigest()}  {safe_copy.name}\n", encoding="ascii")
            for name, data in ((f"keyrx-{version}.cdx.json", b"{}"), ("release-notes.md", b"notes\n"), ("release-policy.json", (ROOT / "ops/release/0.4.13.json").read_bytes())):
                path = directory / name; path.write_bytes(data); ancillary.append(path)
            prepared = (safe_copy, checksum, directory / f"keyrx-{version}.cdx.json", upload, *ancillary[1:])
            handoff = directory / "PREPARED_SHA256SUMS"
            handoff.write_text("".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in prepared
            ), encoding="ascii")
            self.assertEqual(len(handoff.read_text("ascii").splitlines()), 6)

            base_manifest = (ROOT / "Cargo.toml").read_text("utf-8")
            lock = directory / "Cargo.lock"; lock.write_bytes((ROOT / "Cargo.lock").read_bytes())
            tree = directory / "tree.json"
            fixed_paths = ("CHANGELOG.md", "Cargo.lock", "Cargo.toml", "LICENSE", "README.md", "TRADEMARK.md", "src/evm.rs", "src/main.rs", "src/ui.rs")
            safe_tree = [{"path": path, "type": "blob", "mode": "100644"} for path in fixed_paths]
            tree.write_text(json.dumps({"tree": safe_tree}), encoding="utf-8")
            mutations = {
                "git": base_manifest.replace('sha3 = "0.10"', 'sha3 = { version = "0.10", git = "https://candidate.invalid/privileged-probe" }'),
                "path": base_manifest.replace('sha3 = "0.10"', 'sha3 = { version = "0.10", path = "../probe" }'),
                "registry": base_manifest.replace('sha3 = "0.10"', 'sha3 = { version = "0.10", registry = "probe" }'),
                "source": base_manifest.replace('sha3 = "0.10"', 'sha3 = { version = "0.10", source = "candidate" }'),
                "workspace-dependency": base_manifest.replace('sha3 = "0.10"', 'sha3 = { workspace = true }'),
                "workspace-section": base_manifest + "\n[workspace]\nmembers = []\n",
                "patch": base_manifest + '\n[patch.crates-io]\nsha3 = { git = "https://candidate.invalid/patch" }\n',
                "replace": base_manifest + '\n[replace]\n"sha3:0.10.0" = { git = "https://candidate.invalid/replace" }\n',
                "build-script": base_manifest.replace('[package]\n', '[package]\nbuild = "build.rs"\n', 1),
                "unknown-section": base_manifest + "\n[surprise]\nendpoint = \"https://candidate.invalid\"\n",
            }
            manifest = directory / "Cargo.toml"
            self.assertEqual(
                run_inline("INLINE_SOURCE_POLICY_VALIDATOR", ROOT / "Cargo.toml", ROOT / "Cargo.lock", tree, version).returncode,
                0,
            )
            for label, hostile in mutations.items():
                with self.subTest(label=label):
                    manifest.write_text(hostile, encoding="utf-8")
                    ledger = []
                    result = run_inline("INLINE_SOURCE_POLICY_VALIDATOR", manifest, lock, tree, version)
                    if result.returncode == 0:
                        ledger.extend(("cargo-invocation", "candidate-network", "provider-attestation"))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(ledger, [])
            manifest.write_text(base_manifest, encoding="utf-8")
            controls = (
                ".cargo/config.toml", ".gitattributes", "nested/.gitattributes",
                ".GITATTRIBUTES", "nested/.LfScOnFiG", ".gitmodules",
                "nested/.GITMODULES",
            )
            for path in controls:
                with self.subTest(control_path=path):
                    tree.write_text(json.dumps({"tree": safe_tree + [{"path": path, "type": "blob", "mode": "100644"}]}), encoding="utf-8")
                    result = run_inline("INLINE_SOURCE_POLICY_VALIDATOR", manifest, lock, tree, version)
                    self.assertIn("configuration/build hook", result.stderr)

    def test_raw_blob_materializer_never_invokes_configured_git_filter(self):
        marker = inline_python("INLINE_RAW_SOURCE_MATERIALIZER")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); source = directory / "source"; target = directory / "target"
            source.mkdir(); target.mkdir(); (source / "src").mkdir()
            expected = ("Cargo.toml", "Cargo.lock", "CHANGELOG.md", "LICENSE", "README.md", "TRADEMARK.md", "src/evm.rs", "src/main.rs", "src/ui.rs")
            for name in expected:
                path = source / name; path.write_bytes(("raw:" + name).encode())
            # These are hostile control-plane bytes beside the admitted inputs.
            # The materializer has no Git invocation and ignores both.
            (source / ".gitattributes").write_text("src/main.rs filter=probe\n", encoding="utf-8")
            probe = directory / "filter-ran"
            environment = {**os.environ, "FILTER_PROBE_MARKER": str(probe)}
            result = subprocess.run(["python3", "-", source, target], input=marker, text=True, capture_output=True, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(probe.exists())
            self.assertFalse((target / ".gitattributes").exists())
            for name in expected:
                self.assertEqual((target / name).read_bytes(), (source / name).read_bytes())
                self.assertEqual((target / name).stat().st_mode & 0o777, 0o644)
            (source / "Cargo.toml").unlink()
            (source / "Cargo.toml").symlink_to("Cargo.lock")
            second = directory / "second"; second.mkdir()
            hostile = subprocess.run(["python3", "-", source, second], input=marker, text=True, capture_output=True, env=environment)
            self.assertNotEqual(hostile.returncode, 0)
            self.assertFalse(probe.exists())

    def test_source_admission_precedes_the_only_constrained_cargo_boundary(self):
        policy = self.effect.index("# INLINE_SOURCE_POLICY_VALIDATOR_BEGIN")
        source = self.effect.index("# INLINE_SOURCE_BINDER_BEGIN")
        cargo = self.effect.index("# CARGO_INVOCATION_BOUNDARY")
        attestation = self.effect.index("Attest the archive before any draft or registry effect")
        self.assertLess(policy, source)
        self.assertLess(source, cargo)
        self.assertLess(cargo, attestation)
        before_cargo = self.effect[:cargo]
        self.assertNotIn("rustup toolchain install", before_cargo)
        self.assertNotIn("cargo package", before_cargo)
        self.assertIn("env -i", self.effect[cargo:])
        self.assertIn("sparse+https://index.crates.io/", self.effect[cargo:])
        self.assertNotRegex(self.effect[source:cargo], r"(?m)^\s*git .* checkout(?:\s|$)")

    def test_actual_draft_close_validator_rejects_metadata_and_asset_races(self):
        version, tag, title = "0.4.13", "v0.4.13", "keyrx 0.4.13"
        api, repository = "https://api.github.test", "keyrx/keyrx"
        suffixes = (".crate", ".crate.sha256", ".cdx.json", ".crate.sigstore.json", ".crate.intoto.jsonl", ".SHA256SUMS")
        assets = []
        for index, suffix in enumerate(suffixes, 10):
            assets.append({
                "id": index,
                "name": f"keyrx-{version}{suffix}",
                "url": f"{api}/repos/{repository}/releases/assets/{index}",
                "digest": "sha256:" + f"{index:064x}",
                "state": "uploaded",
            })
        release = {
            "tag_name": tag, "name": title, "body": "notes\n", "draft": True,
            "prerelease": False, "immutable": False, "assets": assets,
        }
        identities = sorted(
            [{key: asset[key] for key in ("id", "name", "url", "digest", "state")} for asset in assets],
            key=lambda item: item["name"],
        )
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            release_path, identity_path, notes_path = (
                directory / "release.json", directory / "identities.json", directory / "notes.md"
            )
            identity_path.write_text(json.dumps(identities), encoding="utf-8")
            notes_path.write_text("notes\n", encoding="utf-8")
            def check(value):
                release_path.write_text(json.dumps(value), encoding="utf-8")
                return run_inline(
                    "INLINE_DRAFT_CLOSE_VALIDATOR", release_path, identity_path, notes_path,
                    version, tag, title, api, repository,
                )
            self.assertEqual(check(release).returncode, 0)
            hostile = json.loads(json.dumps(release))
            hostile["name"] = "changed"
            self.assertNotEqual(check(hostile).returncode, 0)
            hostile = json.loads(json.dumps(release))
            hostile["assets"][0]["digest"] = "sha256:" + "f" * 64
            self.assertNotEqual(check(hostile).returncode, 0)

    def test_shipping_draft_subset_classifier_holds_exact_prefixes_for_manual_recovery(self):
        version, tag, title = "0.4.13", "v0.4.13", "keyrx 0.4.13"
        api, repository = "https://api.github.test", "keyrx/keyrx"
        suffixes = (".crate", ".crate.sha256", ".cdx.json", ".crate.sigstore.json", ".crate.intoto.jsonl", ".SHA256SUMS")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); release_path = directory / "release.json"; notes = directory / "notes.md"
            notes.write_text("notes\n", encoding="utf-8")
            def asset(index, suffix):
                return {"id": index, "name": f"keyrx-{version}{suffix}",
                        "url": f"{api}/repos/{repository}/releases/assets/{index}",
                        "digest": "sha256:" + f"{index:064x}", "state": "uploaded"}
            all_assets = [asset(index, suffix) for index, suffix in enumerate(suffixes, 10)]
            def check(assets):
                release_path.write_text(json.dumps({"tag_name": tag, "name": title, "body": "notes\n", "draft": True, "prerelease": False, "assets": assets}), encoding="utf-8")
                return run_inline("INLINE_DRAFT_SUBSET_VALIDATOR", release_path, notes, version, tag, title, api, repository)
            for count in (1, 5):
                result = check(all_assets[:count]); self.assertEqual(result.stdout.strip(), "draft-partial-manual")
            self.assertEqual(check([]).stdout.strip(), "draft-empty")
            self.assertEqual(check(all_assets).stdout.strip(), "draft-exact")
            hostile = [all_assets[1]]
            self.assertNotEqual(check(hostile).returncode, 0)
            lost_response = json.loads(json.dumps(all_assets[:1])); lost_response[0]["state"] = "starter"
            self.assertNotEqual(check(lost_response).returncode, 0)

    def test_fresh_seven_file_handoff_rehydrates_only_verified_remote_provenance(self):
        block = self.effect.split("Verify exact draft bytes and provenance before crates.io", 1)[1].split(
            "Rebind refs and registry immediately before registry authority", 1
        )[0]
        attestation = block.index("gh attestation verify")
        staging = block.index('if test "$RELEASE_STATE" = draft-exact')
        self.assertLess(attestation, staging)
        self.assertIn('test "$RELEASE_STATE" = draft-exact || test "$RELEASE_STATE" = published-exact', block)
        self.assertIn('cp -- "$dir/$CRATE_NAME-$VERSION.crate.sigstore.json"', block)
        self.assertIn('test "$RELEASE_STATE" = absent || test "$RELEASE_STATE" = draft-empty', block)
        self.assertIn('cmp -s "$dir/$name" "$RUNNER_TEMP/prepared/$name"', block)
        final = self.effect.split("Verify immutable release and exact asset API identities", 1)[1]
        for suffix in (".crate", ".crate.sha256", ".cdx.json", ".crate.sigstore.json", ".crate.intoto.jsonl", ".SHA256SUMS"):
            self.assertIn(f'$CRATE_NAME-$VERSION{suffix}', final)

    def test_existing_registry_state_mints_no_oidc_token_and_performs_no_put(self):
        auth = self.effect.split("Obtain one short-lived trusted-publisher token", 1)[1].split(
            "Upload the preserved crate only when absent", 1
        )[0]
        upload = self.effect.split("Upload the preserved crate only when absent", 1)[1].split(
            "Require crates.io to hold", 1
        )[0]
        condition = "if: steps.prerequisite.outputs.registry_authorization == 'issue-token'"
        self.assertIn(condition, auth)
        self.assertIn(condition, upload)
        self.assertIn("steps.crates_auth.outputs.token", upload)

    def test_crates_upload_uses_the_declared_keyrx_user_agent(self):
        upload = self.effect.split("Upload the preserved crate only when absent", 1)[1].split(
            "Require crates.io to hold", 1
        )[0]
        self.assertIn(
            "-A 'keyrx release workflow (dev@keyrx.tech)' -X PUT",
            upload,
        )
        self.assertIn("'https://crates.io/api/v1/crates/new'", upload)

    def test_actual_asset_set_validator_rejects_manifest_and_intoto_substitution(self):
        version = "0.4.13"
        suffixes = (".crate", ".crate.sha256", ".cdx.json", ".crate.sigstore.json", ".crate.intoto.jsonl")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            envelope = {"payloadType": "application/vnd.in-toto+json", "payload": "e30=", "signatures": []}
            for suffix in suffixes:
                (directory / f"keyrx-{version}{suffix}").write_bytes(b"asset:" + suffix.encode())
            bundle = directory / f"keyrx-{version}.crate.sigstore.json"
            bundle.write_text(json.dumps({"dsseEnvelope": envelope}), encoding="utf-8")
            intoto = directory / f"keyrx-{version}.crate.intoto.jsonl"
            intoto.write_text(json.dumps(envelope, separators=(",", ":")) + "\n", encoding="utf-8")
            names = [f"keyrx-{version}{suffix}" for suffix in suffixes]
            manifest = directory / f"keyrx-{version}.SHA256SUMS"
            def write_manifest(rows=names):
                manifest.write_text("".join(
                    f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
                    for name in rows
                ), encoding="ascii")
            write_manifest()
            self.assertEqual(run_inline("INLINE_ASSET_SET_VALIDATOR", directory, version).returncode, 0)
            for rows in (names[:-1], names + [names[0]], names + ["extra"]):
                if "extra" in rows:
                    (directory / "extra").write_bytes(b"extra")
                write_manifest(rows)
                self.assertNotEqual(run_inline("INLINE_ASSET_SET_VALIDATOR", directory, version).returncode, 0)
            write_manifest()
            intoto.write_text(json.dumps({**envelope, "payload": "evil"}, separators=(",", ":")) + "\n", encoding="utf-8")
            # Keep the manifest internally valid: the failure must be the bundle
            # relationship, not a stale digest.
            write_manifest()
            self.assertNotEqual(run_inline("INLINE_ASSET_SET_VALIDATOR", directory, version).returncode, 0)

    def test_actual_current_registry_validator_rejects_yanked_newer_and_extra_live(self):
        version, checksum, repo, source = "0.4.13", "a" * 64, "keyrx/keyrx", "b" * 40
        current = {"version": {"num": version, "yanked": False, "checksum": checksum,
                               "trustpub_data": {"provider": "github", "repository": repo, "sha": source}}}
        policy = {"yankTargets": ["0.4.12"]}
        registry = {"versions": [{"num": "0.4.12", "yanked": False}, {"num": version, "yanked": False, "checksum": checksum}]}
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            paths = [directory / name for name in ("registry.json", "current.json", "policy.json")]
            def check(registry_value=registry, current_value=current):
                for path, value in zip(paths, (registry_value, current_value, policy)):
                    path.write_text(json.dumps(value), encoding="utf-8")
                return run_inline("INLINE_CURRENT_REGISTRY_VALIDATOR", *paths, version, checksum, repo, source)
            self.assertEqual(check().returncode, 0)
            yanked = json.loads(json.dumps(current)); yanked["version"]["yanked"] = True
            self.assertNotEqual(check(current_value=yanked).returncode, 0)
            list_yanked = json.loads(json.dumps(registry)); list_yanked["versions"][1]["yanked"] = True
            self.assertIn("current list row differs", check(registry_value=list_yanked).stderr)
            list_checksum = json.loads(json.dumps(registry)); list_checksum["versions"][1]["checksum"] = "f" * 64
            self.assertIn("current list row differs", check(registry_value=list_checksum).stderr)
            newer = {"versions": registry["versions"] + [{"num": "0.4.14", "yanked": True}]}
            self.assertNotEqual(check(registry_value=newer).returncode, 0)
            extra_live = {"versions": registry["versions"] + [{"num": "0.4.11", "yanked": False}]}
            self.assertNotEqual(check(registry_value=extra_live).returncode, 0)

    def test_actual_latest_validator_rejects_newer_published_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releases.jsonl"
            def check(items):
                path.write_text("".join(json.dumps(item) + "\n" for item in items), encoding="utf-8")
                return run_inline("INLINE_LATEST_VALIDATOR", path, "0.4.13")
            older = [{"tag_name": "v0.4.12", "draft": False, "prerelease": False, "immutable": True}]
            self.assertEqual(check(older).returncode, 0)
            newer = older + [{"tag_name": "v0.4.14", "draft": False, "prerelease": False, "immutable": True}]
            self.assertNotEqual(check(newer).returncode, 0)
            duplicate = older + older
            self.assertNotEqual(check(duplicate).returncode, 0)

    def test_actual_latest_id_validator_binds_exact_published_release(self):
        release_id, tag = "314", "v0.4.13"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "latest.json"
            def check(value, expected_tag=tag):
                path.write_text(json.dumps(value), encoding="utf-8")
                return run_inline("INLINE_LATEST_ID_VALIDATOR", path, release_id, expected_tag)
            exact = {"id": 314, "tag_name": tag, "draft": False, "prerelease": False, "immutable": True}
            self.assertEqual(check(exact).returncode, 0)
            for hostile in (
                {**exact, "id": 315}, {**exact, "tag_name": "v0.4.12"},
                {**exact, "draft": True}, {**exact, "immutable": False},
            ):
                self.assertNotEqual(check(hostile).returncode, 0)
            self.assertNotEqual(check(exact, "v01.4.13").returncode, 0)

    def test_actual_main_ancestry_validator_allows_only_exact_initial_or_proven_descendant(self):
        source, main = "1" * 40, "2" * 40
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compare.json"
            def check(value, state, main_sha=main):
                path.write_text(json.dumps(value), encoding="utf-8")
                return run_inline("INLINE_MAIN_ANCESTRY_VALIDATOR", path, source, main_sha, state)
            identical = {"status": "identical", "merge_base_commit": {"sha": source}, "base_commit": {"sha": source}, "commits": []}
            ahead = {"status": "ahead", "merge_base_commit": {"sha": source}, "base_commit": {"sha": source}, "commits": [{"sha": main}]}
            self.assertEqual(check(identical, "absent", source).returncode, 0)
            self.assertNotEqual(check(ahead, "absent").returncode, 0)
            self.assertEqual(check(ahead, "exact").returncode, 0)
            divergent = {**ahead, "merge_base_commit": {"sha": "3" * 40}}
            self.assertNotEqual(check(divergent, "exact").returncode, 0)

    def test_whole_shipping_prerequisite_admits_only_exact_initial_or_terminal(self):
        version, checksum, repo, source = "0.4.13", "a" * 64, "keyrx/keyrx", "b" * 40
        pred_checksum = "dcf2ff724aa2d0ec43173a2d1a7f225ea39efa8c5d61e43b02c82b26a4f7854d"
        pred_source = "9b4725a0e8b160ccacad0d7b858793ba8dee4a89"
        policy = json.loads((ROOT / "ops/release/0.4.13.json").read_text())
        def predecessor(yanked):
            return {"version": {"num": "0.4.12", "yanked": yanked, "checksum": pred_checksum,
                    "trustpub_data": {"provider": "github", "repository": repo, "sha": pred_source}}}
        current = {"version": {"num": version, "yanked": False, "checksum": checksum,
                   "trustpub_data": {"provider": "github", "repository": repo, "sha": source}}}
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            paths = {name: directory / f"{name}.json" for name in ("registry", "predecessor", "current", "policy")}
            paths["policy"].write_text(json.dumps(policy), encoding="utf-8")
            def check(registry, pred, detail, release_state):
                paths["registry"].write_text(json.dumps(registry), encoding="utf-8")
                paths["predecessor"].write_text(json.dumps(pred), encoding="utf-8")
                detail_arg = "-"
                if detail is not None:
                    paths["current"].write_text(json.dumps(detail), encoding="utf-8"); detail_arg = str(paths["current"])
                return run_inline(
                    "INLINE_PREREQUISITE_STATE_VALIDATOR", paths["registry"], paths["predecessor"],
                    detail_arg, paths["policy"], version, checksum, repo, source, release_state,
                )
            initial_registry = {"versions": [{"num": "0.4.12", "yanked": False, "checksum": pred_checksum}]}
            initial = check(initial_registry, predecessor(False), None, "absent")
            self.assertEqual(json.loads(initial.stdout), {"registry_state": "absent", "yank_state": "initial"})
            terminal_registry = {"versions": [
                {"num": "0.4.12", "yanked": True, "checksum": pred_checksum},
                {"num": version, "yanked": False, "checksum": checksum},
            ]}
            terminal = check(terminal_registry, predecessor(True), current, "published-exact")
            self.assertEqual(json.loads(terminal.stdout), {"registry_state": "exact", "yank_state": "terminal"})
            mismatch = check(initial_registry, predecessor(True), None, "absent")
            self.assertNotEqual(mismatch.returncode, 0)
            bad_terminal = check(terminal_registry, predecessor(True), current, "draft-exact")
            self.assertNotEqual(bad_terminal.returncode, 0)
            newer = {"versions": terminal_registry["versions"] + [{"num": "0.4.14", "yanked": True, "checksum": "c" * 64}]}
            self.assertNotEqual(check(newer, predecessor(True), current, "published-exact").returncode, 0)

    def test_prepared_enumeration_rejects_every_non_top_level_regular_entry(self):
        bind = self.effect.split("Bind every prepared byte before any public effect", 1)[1].split(
            "Prove external prerequisites", 1
        )[0]
        self.assertIn("find . -mindepth 1 -printf '%P\\t%y\\n'", bind)
        self.assertIn("printf '%s\\tf\\n'", bind)
        self.assertIn('test "${entries[*]}" = "${expected_entries[*]}"', bind)
        version = "0.4.13"
        names = (
            "PREPARED_SHA256SUMS", f"keyrx-{version}.cdx.json", f"keyrx-{version}.crate",
            f"keyrx-{version}.crate.sha256", f"keyrx-{version}.crates-api-upload",
            "release-notes.md", "release-policy.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for name in names:
                (directory / name).write_bytes(b"x")
            def run():
                return subprocess.run(
                    ["bash", "-c", inline_shell("PREPARED_ENUMERATOR")], cwd=directory,
                    env={**__import__("os").environ, "CRATE_NAME": "keyrx", "VERSION": version},
                    capture_output=True, text=True,
                )
            self.assertEqual(run().returncode, 0)
            (directory / "nested").mkdir()
            (directory / "nested" / "carrier").write_bytes(b"x")
            self.assertNotEqual(run().returncode, 0)
            (directory / "nested" / "carrier").unlink(); (directory / "nested").rmdir()
            (directory / "link").symlink_to(names[0])
            self.assertNotEqual(run().returncode, 0)
            (directory / "link").unlink()
            __import__("os").mkfifo(directory / "fifo")
            self.assertNotEqual(run().returncode, 0)

    def test_package_is_bound_to_git_blobs_and_cross_job_digest(self):
        self.assertIn(
            'CARGO_TARGET_DIR="$RUNNER_TEMP/publish-dry-run-target" cargo publish --dry-run --locked',
            self.prepare,
        )
        self.assertIn('package_target="$RUNNER_TEMP/package-target"', self.prepare)
        self.assertIn('CARGO_TARGET_DIR="$package_target" cargo package --locked', self.prepare)
        package_tail = self.prepare.split(
            'CARGO_TARGET_DIR="$package_target" cargo package --locked', 1
        )[1]
        for forbidden in ("cargo run", "cargo test", "cargo clippy"):
            self.assertNotIn(forbidden, package_tail)
        self.assertIn("--git-source", self.prepare)
        self.assertIn("PREPARED_SHA256SUMS", self.workflow)
        self.assertIn("prepared_set_sha256", self.workflow)
        self.assertIn("artifact-digest", self.workflow)
        self.assertIn('record.get("digest") != digest', self.effect)
        self.assertIn('run.get("id") != int(run_id)', self.effect)
        preflight = (ROOT / "ops" / "release_preflight.py").read_text(encoding="utf-8")
        self.assertIn('"ls-tree", "-z", source_sha', preflight)
        self.assertIn('"cat-file", "blob", object_id', preflight)
        self.assertIn("O_NOFOLLOW", preflight)

    def test_predecessor_is_rederived_not_accepted_from_shape_alone(self):
        for marker in (
            ".trustpub_data.provider == \"github\"",
            ".trustpub_data.repository == $repo",
            ".trustpub_data.sha",
            "predecessor_checksum",
            "predecessor.crate",
            "predecessor-members.txt",
            "predecessor-vcs.json",
            "predecessor-Cargo.toml.orig",
            "legacy-crate-tag",
            "predecessor-releases.json",
            "sha256sum --check --strict",
            "gh attestation verify",
            "gh release verify",
        ):
            self.assertIn(marker, self.effect)
        self.assertIn('test "$(jq \'length\' "$RUNNER_TEMP/predecessor-releases.json")" -eq 0', self.effect)

    def test_asset_api_urls_are_reconstructed_from_numeric_ids(self):
        marker = "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/releases/assets/$id"
        self.assertGreaterEqual(self.effect.count(marker), 4)
        self.assertNotIn('curl -fsSL "$url"', self.effect)

    def test_shipping_boundary_controls_are_part_of_shipping_test_gate(self):
        self.assertIn("test_release_*.py", self.prepare)
        controls = (ROOT / "tests" / "test_release_workflow.py").read_text(encoding="utf-8")
        for name in (
            "actual_source_binder_rejects_source_notes_and_cdx_substitution",
            "whole_shipping_prerequisite_admits_only_exact_initial_or_terminal",
            "actual_current_registry_validator_rejects_yanked_newer_and_extra_live",
            "actual_draft_close_validator_rejects_metadata_and_asset_races",
            "actual_latest_id_validator_binds_exact_published_release",
        ):
            self.assertIn(name, controls)
        contract = (ROOT / "ops" / "release_contract.py").read_text(encoding="utf-8")
        self.assertIn("neither models nor authorizes provider effects", contract)
        self.assertNotIn("planned_public_effects", contract)

    def test_latest_and_yank_boundaries_recheck_current_exact_and_no_newer(self):
        release = self.effect.split("Publish the already-proven draft as immutable", 1)[1].split(
            "Verify immutable release", 1
        )[0]
        before_yank = self.effect.split("Rebind refs and require exact reviewed yank inputs", 1)[1].split(
            "Yank only the exact reviewed predecessor set", 1
        )[0]
        yank = self.effect.split("Yank only the exact reviewed predecessor set", 1)[1]
        for block in (release, before_yank, yank):
            self.assertIn(".yanked == false", block)
            self.assertIn(".trustpub_data.sha == $sha", block)
            self.assertIn("select((.num | key) > ($current | key))] | length == 0", block)
        self.assertIn("make_latest:\"true\"", release)
        for field in ('tag_name:$tag', 'target_commitish:$sha', 'name:$title', 'body:$body'):
            self.assertIn(field, release)
        self.assertIn("INLINE_LATEST_VALIDATOR_BEGIN", release)
        self.assertIn("draft-asset-identities.json", release)
        self.assertIn("steps.prerequisite.outputs.yank_state != 'terminal'", yank)


if __name__ == "__main__":
    unittest.main()
