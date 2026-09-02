import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "ops" / "release_preflight.py"
SPEC = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
release_preflight = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release_preflight)


VERSION = "0.4.13"
SHA = "1" * 40
EXPECTED_INSTALL_SURFACE_SHA256 = {
    "README.md": "3560c937f95fa18ed444061f0e5095f939e99f4bfd8bf117369203998365996c",
    "docs/README.md": "08c7f2f863dfc2cf31086adf8c3e8cabe6009458901dd0c2c3fcd01f74dc3ccb",
    "site/llms.txt": "43e9048be98a308971793efbb29a61fb52753b91924b30a39f7fbea38c7e047f",
    "site/index.html": "0d832a349967000e8774a6e2a4925176a68c1a779fe3e3073c987be437409c93",
}


def repository_files(version=VERSION):
    files = {
        "Cargo.toml": f'[package]\nname = "keyrx"\nversion = "{version}"\n',
        "Cargo.lock": (
            'version = 4\n\n[[package]]\nname = "keyrx"\n'
            f'version = "{version}"\n'
        ),
        "CHANGELOG.md": (
            f"# Changelog\n\n## {version} - 2026-09-02\n\n"
            "- Safe release orchestration.\n\n## 0.4.12 - 2026-08-23\n\n- Earlier.\n"
        ),
        "LICENSE": "test license\n",
        "TRADEMARK.md": "test trademark\n",
        "src/main.rs": "fn main() {}\n",
    }
    repository_root = SCRIPT.parents[1]
    for relative in EXPECTED_INSTALL_SURFACE_SHA256:
        files[relative] = (repository_root / relative).read_text(encoding="utf-8")
    return files


def write_repository(root, files=None):
    for name, contents in (files or repository_files()).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")


def add_tar_text(archive, name, text):
    data = text.encode("utf-8")
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mtime = 0
    archive.addfile(member, io.BytesIO(data))


def write_crate(path, *, sha=SHA, dirty=None, extra_name=None):
    root = f"keyrx-{VERSION}"
    files = repository_files()
    with tarfile.open(path, "w:gz") as archive:
        add_tar_text(archive, f"{root}/Cargo.toml", files["Cargo.toml"])
        add_tar_text(archive, f"{root}/Cargo.toml.orig", files["Cargo.toml"])
        add_tar_text(archive, f"{root}/Cargo.lock", files["Cargo.lock"])
        add_tar_text(archive, f"{root}/CHANGELOG.md", files["CHANGELOG.md"])
        for relative in ("README.md", "LICENSE", "TRADEMARK.md", "src/main.rs"):
            add_tar_text(archive, f"{root}/{relative}", files[relative])
        git = {"sha1": sha}
        if dirty is not None:
            git["dirty"] = dirty
        add_tar_text(
            archive,
            f"{root}/.cargo_vcs_info.json",
            json.dumps({"git": git, "path_in_vcs": ""}),
        )
        if extra_name:
            add_tar_text(archive, extra_name, "unexpected")


class RepositoryPreflightTests(unittest.TestCase):
    def test_matching_release_is_accepted_and_notes_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            notes = release_preflight.validate_repository(root, VERSION)
            self.assertEqual(notes, "- Safe release orchestration.\n")

    def test_install_surface_manifest_is_independently_pinned(self):
        self.assertEqual(
            release_preflight.INSTALL_SURFACE_SHA256,
            EXPECTED_INSTALL_SURFACE_SHA256,
        )

    def test_every_install_surface_is_bound_to_exact_reviewed_bytes(self):
        corruptions = {
            "cargo install --locked keyrx": "cargo install --locked keyrx-malicious",
            "cargo install --locked --path .": "cargo install --locked --path ..",
        }
        for relative in EXPECTED_INSTALL_SURFACE_SHA256:
            for canonical, corruption in corruptions.items():
                with (
                    self.subTest(relative=relative, canonical=canonical),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    files = repository_files()
                    files[relative] = files[relative].replace(canonical, corruption, 1)
                    write_repository(root, files)
                    with self.assertRaisesRegex(
                        release_preflight.PreflightError, "byte digest differs"
                    ):
                        release_preflight.validate_repository(root, VERSION)

    def test_an_extra_unlocked_install_cannot_hide_behind_canonical_copy(self):
        hostile = (
            "cargo install keyrx",
            "cargo install keyrx # --locked",
            "cargo install keyrx || echo --locked",
            "cargo install keyrx && cargo install --locked keyrx",
            "cargo install --path . --locked",
            '"cargo" install keyrx',
            "'cargo' install keyrx",
            "cargo 'install' keyrx",
            'cargo "install" keyrx',
            "cargo " + "\\" + "\n  install keyrx",
            "cargo\n  install keyrx",
            "cargo +stable install keyrx",
            "cargo --color=always install keyrx",
            "c'a'rgo install keyrx",
            "cargo in'st'all keyrx",
            "xcargo install --locked keyrx",
            'cargo install --locked keyrx"-malicious"',
            'cargo install --locked --path ."."',
            "cargo install --locked --path .,malicious",
        )
        for relative in EXPECTED_INSTALL_SURFACE_SHA256:
            for command in hostile:
                with (
                    self.subTest(relative=relative, command=command),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    files = repository_files()
                    files[relative] += f"\n{command}\n"
                    write_repository(root, files)
                    with self.assertRaisesRegex(
                        release_preflight.PreflightError,
                        "byte digest differs",
                    ):
                        release_preflight.validate_repository(root, VERSION)

    def test_every_version_carrier_must_agree(self):
        mutations = {
            "Cargo.toml": '[package]\nname = "keyrx"\nversion = "0.4.12"\n',
            "Cargo.lock": 'version = 4\n\n[[package]]\nname = "keyrx"\nversion = "0.4.12"\n',
            "site/index.html": (
                "<script>var VERSION='0.4.12';</script>\n"
                "cargo install --locked keyrx\n"
                "commandRows('cargo install --locked keyrx','install');\n"
                "var INSTALL='cargo install --locked keyrx';\n"
                "cargo install --locked --path .\n"
            ),
        }
        for name, replacement in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                files = repository_files()
                files[name] = replacement
                write_repository(root, files)
                with self.assertRaisesRegex(
                    release_preflight.PreflightError, "version disagreement"
                ):
                    release_preflight.validate_repository(root, VERSION)

    def test_changelog_section_must_be_newest_unique_dated_and_nonempty(self):
        bad_changelogs = [
            "# Changelog\n\n## 0.4.12 - 2026-08-23\n\n- Earlier.\n",
            (
                f"# Changelog\n\n## {VERSION} - 2026-09-02\n\n- One.\n\n"
                f"## {VERSION} - 2026-09-01\n\n- Two.\n"
            ),
            f"# Changelog\n\n## {VERSION} - 2026-99-99\n\n- Bad date.\n",
            f"# Changelog\n\n## {VERSION} - 2026-09-02\n\n## 0.4.12 - 2026-08-23\n",
        ]
        for changelog in bad_changelogs:
            with self.subTest(changelog=changelog), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                files = repository_files()
                files["CHANGELOG.md"] = changelog
                write_repository(root, files)
                with self.assertRaises(release_preflight.PreflightError):
                    release_preflight.validate_repository(root, VERSION)

    def test_malformed_newer_release_heading_is_not_ignored(self):
        malformed_headings = (
            "## 0.4.14",
            "## 0.4.14- 2026-09-03",
            "## Release 0.4.14 - 2026-09-03",
            "## Version 0.4.14 - 2026-09-03",
            "## (0.4.14) - 2026-09-03",
        )
        for heading in malformed_headings:
            with self.subTest(heading=heading), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                files = repository_files()
                files["CHANGELOG.md"] = (
                    f"# Changelog\n\n{heading}\n\n- Malformed newer release.\n\n"
                    + files["CHANGELOG.md"]
                )
                write_repository(root, files)
                with self.assertRaisesRegex(
                    release_preflight.PreflightError, "malformed"
                ):
                    release_preflight.validate_repository(root, VERSION)

    def test_release_headings_must_be_strictly_descending(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = repository_files()
            files["CHANGELOG.md"] = (
                f"# Changelog\n\n## {VERSION} - 2026-09-02\n\n- Current.\n\n"
                "## 0.4.14 - 2026-09-03\n\n- Misordered newer release.\n"
            )
            write_repository(root, files)
            with self.assertRaisesRegex(
                release_preflight.PreflightError, "strictly descending"
            ):
                release_preflight.validate_repository(root, VERSION)

    def test_non_version_h2_stays_in_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = repository_files()
            files["CHANGELOG.md"] = (
                f"# Changelog\n\n## {VERSION} - 2026-09-02\n\n- Lead.\n\n"
                "## Migration details\n\nKeep this too.\n\n"
                "## 0.4.12 - 2026-08-23\n\n- Earlier.\n"
            )
            write_repository(root, files)
            notes = release_preflight.validate_repository(root, VERSION)
            self.assertIn("## Migration details\n\nKeep this too.", notes)

    def test_headings_in_fences_and_comments_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = repository_files()
            files["CHANGELOG.md"] = (
                f"# Changelog\n\n## {VERSION} - 2026-09-02\n\n"
                "```md\n## 9.9.9 - 2099-01-01\n```\n"
                "<!--\n## 8.8.8 - 2088-01-01\n-->\n"
                "- Real notes.\n\n## 0.4.12 - 2026-08-23\n\n- Earlier.\n"
            )
            write_repository(root, files)
            notes = release_preflight.validate_repository(root, VERSION)
            self.assertIn("## 9.9.9", notes)
            self.assertIn("## 8.8.8", notes)

    def test_comment_marker_inside_fence_does_not_hide_later_release(self):
        fenced_blocks = ("```text\n<!--\n```\n", "```html <!--\ncontent\n```\n")
        for fenced_block in fenced_blocks:
            with self.subTest(fenced_block=fenced_block), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                files = repository_files()
                files["CHANGELOG.md"] = (
                    f"# Changelog\n\n## {VERSION} - 2026-09-02\n\n- Current.\n\n"
                    f"{fenced_block}\n"
                    "## 0.4.12 - 2026-08-23\n\n- Earlier.\n"
                )
                write_repository(root, files)
                notes = release_preflight.validate_repository(root, VERSION)
                self.assertEqual(notes, f"- Current.\n\n{fenced_block}")

    def test_version_must_be_canonical_three_part_release(self):
        for version in ("v0.4.13", "0.4", "00.4.13", "0.4.13-rc.1"):
            with self.subTest(version=version), self.assertRaises(
                release_preflight.PreflightError
            ):
                release_preflight.require_release_version(version)


class PackagePreflightTests(unittest.TestCase):
    def make_git_repository(self, root):
        write_repository(root)
        subprocess.run(["git", "init", "-q", root], check=True)
        subprocess.run(["git", "-C", root, "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", root, "config", "user.name", "release test"], check=True)
        subprocess.run(["git", "-C", root, "add", "."], check=True)
        subprocess.run(["git", "-C", root, "commit", "-qm", "source"], check=True)
        return subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD"], text=True
        ).strip()

    def test_package_is_bound_to_version_and_clean_source_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate)
            release_preflight.validate_crate(crate, VERSION, SHA, root)

    def test_dirty_or_wrong_source_is_rejected(self):
        for sha, dirty in (("2" * 40, False), (SHA, True)):
            with self.subTest(sha=sha, dirty=dirty), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_repository(root)
                crate = root / f"keyrx-{VERSION}.crate"
                write_crate(crate, sha=sha, dirty=dirty)
                with self.assertRaisesRegex(release_preflight.PreflightError, "package source"):
                    release_preflight.validate_crate(crate, VERSION, SHA, root)

    def test_archive_member_outside_package_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate, extra_name="../escape")
            with self.assertRaisesRegex(release_preflight.PreflightError, "unsafe"):
                release_preflight.validate_crate(crate, VERSION, SHA, root)

    def test_archive_alias_of_validated_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate, extra_name=f"keyrx-{VERSION}/./Cargo.toml")
            with self.assertRaisesRegex(release_preflight.PreflightError, "aliasing"):
                release_preflight.validate_crate(crate, VERSION, SHA, root)

    def test_package_source_bytes_must_match_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate)
            (root / "src/main.rs").write_text("fn main() { panic!() }\n", encoding="utf-8")
            with self.assertRaisesRegex(release_preflight.PreflightError, "differs byte-for-byte"):
                release_preflight.validate_crate(crate, VERSION, SHA, root)

    def test_package_can_be_bound_directly_to_exact_git_blobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_sha = self.make_git_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate, sha=source_sha)
            release_preflight.validate_crate(
                crate, VERSION, source_sha, root, require_git_source=True
            )

    def test_git_source_mode_rejects_a_committed_symlink_and_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            (root / "README.md").unlink()
            (root / "README.md").symlink_to("LICENSE")
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "-C", root, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", root, "config", "user.name", "release test"], check=True)
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "source"], check=True)
            source_sha = subprocess.check_output(
                ["git", "-C", root, "rev-parse", "HEAD"], text=True
            ).strip()
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate, sha=source_sha)
            with self.assertRaisesRegex(release_preflight.PreflightError, "not a regular file"):
                release_preflight.validate_crate(
                    crate, VERSION, source_sha, root, require_git_source=True
                )

    def test_held_checkout_read_refuses_replacement_between_lstat_and_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source"
            replacement = root / "replacement"
            path.write_bytes(b"reviewed")
            replacement.write_bytes(b"replacement")
            real_open = release_preflight.os.open

            def replace_then_open(target, flags, *args, **kwargs):
                if target == "source":
                    replacement.replace(path)
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(
                release_preflight.os, "open", side_effect=replace_then_open
            ), self.assertRaisesRegex(release_preflight.PreflightError, "changed before open"):
                release_preflight._held_checkout_bytes(root, "source")

    def test_held_checkout_read_refuses_same_inode_same_size_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source"
            path.write_bytes(b"reviewed")
            real_read = release_preflight.os.read
            mutated = False

            def mutate_after_first_read(descriptor, size):
                nonlocal mutated
                data = real_read(descriptor, size)
                if data and not mutated:
                    mutated = True
                    path.write_bytes(b"reviewex")
                return data

            with mock.patch.object(
                release_preflight.os, "read", side_effect=mutate_after_first_read
            ), self.assertRaisesRegex(
                release_preflight.PreflightError, "changed during stable read"
            ):
                release_preflight._held_checkout_bytes(root, "source")

    def test_held_checkout_read_refuses_mutation_before_fresh_rewalk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source"
            path.write_bytes(b"reviewed")
            real_lstat = release_preflight.os.lstat
            root_lookups = 0

            def mutate_before_second_root_lookup(target):
                nonlocal root_lookups
                if Path(target) == root:
                    root_lookups += 1
                    if root_lookups == 2:
                        path.write_bytes(b"reviewex")
                return real_lstat(target)

            with mock.patch.object(
                release_preflight.os,
                "lstat",
                side_effect=mutate_before_second_root_lookup,
            ), self.assertRaises(release_preflight.PreflightError):
                release_preflight._held_checkout_bytes(root, "source")

    def test_held_checkout_read_refuses_mutation_during_fresh_leaf_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source"
            path.write_bytes(b"reviewed")
            real_open = release_preflight.os.open
            leaf_opens = 0

            def mutate_before_second_leaf_open(target, flags, *args, **kwargs):
                nonlocal leaf_opens
                if target == "source":
                    leaf_opens += 1
                    if leaf_opens == 2:
                        path.write_bytes(b"reviewex")
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(
                release_preflight.os,
                "open",
                side_effect=mutate_before_second_leaf_open,
            ), self.assertRaises(release_preflight.PreflightError):
                release_preflight._held_checkout_bytes(root, "source")

    def test_fresh_descriptor_byte_comparison_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_bytes(b"reviewed")
            calls = {}
            original_descriptor = None
            fresh_descriptor = None

            def controlled_reads(descriptor, _size):
                nonlocal original_descriptor, fresh_descriptor
                if original_descriptor is None:
                    original_descriptor = descriptor
                elif descriptor != original_descriptor and fresh_descriptor is None:
                    fresh_descriptor = descriptor
                index = calls.get(descriptor, 0)
                calls[descriptor] = index + 1
                if descriptor == original_descriptor:
                    values = (b"reviewed", b"", b"reviewed", b"")
                elif descriptor == fresh_descriptor:
                    values = (b"reviewex", b"")
                else:
                    raise AssertionError("read came from an unheld descriptor")
                if index >= len(values):
                    raise AssertionError("descriptor was read more times than its role permits")
                return values[index]

            with mock.patch.object(
                release_preflight.os,
                "read",
                side_effect=controlled_reads,
            ), self.assertRaisesRegex(
                release_preflight.PreflightError, "changed during final path read"
            ):
                release_preflight._held_checkout_bytes(root, "source")
            self.assertIsNotNone(original_descriptor)
            self.assertIsNotNone(fresh_descriptor)
            self.assertNotEqual(fresh_descriptor, original_descriptor)
            self.assertEqual(calls, {original_descriptor: 4, fresh_descriptor: 2})

    def test_held_checkout_read_refuses_a_symlinked_parent_component(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "README.md").write_bytes(b"reviewed")
            (root / "docs").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                release_preflight.PreflightError, "non-directory or symlink parent"
            ):
                release_preflight._held_checkout_bytes(root, "docs/README.md")

    def test_held_checkout_parent_open_failure_closes_every_descriptor(self):
        descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("descriptor census requires procfs")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parent").mkdir()
            (root / "parent" / "source").write_bytes(b"reviewed")
            real_fstat = release_preflight.os.fstat
            calls = 0

            def fail_child_directory_fstat(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("controlled child-directory failure")
                return real_fstat(descriptor)

            before = len(tuple(descriptor_directory.iterdir()))
            with mock.patch.object(
                release_preflight.os,
                "fstat",
                side_effect=fail_child_directory_fstat,
            ), self.assertRaisesRegex(
                release_preflight.PreflightError, "cannot safely read"
            ):
                release_preflight._held_checkout_bytes(root, "parent/source")
            after = len(tuple(descriptor_directory.iterdir()))
            self.assertEqual(after, before)

    def test_held_checkout_close_failure_still_attempts_every_descriptor(self):
        descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("descriptor census requires procfs")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parent").mkdir()
            (root / "parent" / "source").write_bytes(b"reviewed")
            real_close = release_preflight.os.close
            calls = 0

            def close_then_fail_once(descriptor):
                nonlocal calls
                calls += 1
                real_close(descriptor)
                if calls == 1:
                    raise OSError("controlled close failure")

            before = len(tuple(descriptor_directory.iterdir()))
            with mock.patch.object(
                release_preflight.os,
                "close",
                side_effect=close_then_fail_once,
            ), self.assertRaisesRegex(
                release_preflight.PreflightError, "cannot close all checkout descriptors"
            ):
                release_preflight._held_checkout_bytes(root, "parent/source")
            after = len(tuple(descriptor_directory.iterdir()))
            self.assertEqual(calls, 6)
            self.assertEqual(after, before)

    def test_held_checkout_interrupt_during_open_closes_partial_chain(self):
        descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("descriptor census requires procfs")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parent").mkdir()
            (root / "parent" / "source").write_bytes(b"reviewed")
            real_fstat = release_preflight.os.fstat
            calls = 0

            def interrupt_child_directory_fstat(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt("controlled open interrupt")
                return real_fstat(descriptor)

            before = len(tuple(descriptor_directory.iterdir()))
            with mock.patch.object(
                release_preflight.os,
                "fstat",
                side_effect=interrupt_child_directory_fstat,
            ), self.assertRaises(KeyboardInterrupt):
                release_preflight._held_checkout_bytes(root, "parent/source")
            after = len(tuple(descriptor_directory.iterdir()))
            self.assertEqual(after, before)

    def test_held_checkout_interrupt_during_close_still_attempts_every_descriptor(self):
        descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("descriptor census requires procfs")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parent").mkdir()
            (root / "parent" / "source").write_bytes(b"reviewed")
            real_close = release_preflight.os.close
            calls = 0

            def close_then_interrupt_once(descriptor):
                nonlocal calls
                calls += 1
                real_close(descriptor)
                if calls == 1:
                    raise KeyboardInterrupt("controlled close interrupt")

            before = len(tuple(descriptor_directory.iterdir()))
            with mock.patch.object(
                release_preflight.os,
                "close",
                side_effect=close_then_interrupt_once,
            ), self.assertRaises(KeyboardInterrupt):
                release_preflight._held_checkout_bytes(root, "parent/source")
            after = len(tuple(descriptor_directory.iterdir()))
            self.assertEqual(calls, 6)
            self.assertEqual(after, before)

    def test_held_checkout_system_exit_during_close_remains_top_level(self):
        descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("descriptor census requires procfs")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parent").mkdir()
            (root / "parent" / "source").write_bytes(b"reviewed")
            real_close = release_preflight.os.close
            calls = 0

            def close_then_exit_once(descriptor):
                nonlocal calls
                calls += 1
                real_close(descriptor)
                if calls == 1:
                    raise SystemExit(23)

            before = len(tuple(descriptor_directory.iterdir()))
            with mock.patch.object(
                release_preflight.os,
                "close",
                side_effect=close_then_exit_once,
            ), self.assertRaises(SystemExit) as caught:
                release_preflight._held_checkout_bytes(root, "parent/source")
            after = len(tuple(descriptor_directory.iterdir()))
            self.assertEqual(caught.exception.code, 23)
            self.assertEqual(calls, 6)
            self.assertEqual(after, before)

    def test_package_member_count_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            write_crate(crate)
            # Rebuild with enough harmless entries to cross the parser's cap.
            root_name = f"keyrx-{VERSION}"
            with tarfile.open(crate, "w:gz") as archive:
                for index in range(release_preflight.MAX_ARCHIVE_MEMBERS + 1):
                    add_tar_text(archive, f"{root_name}/extra-{index}", "")
            with self.assertRaisesRegex(release_preflight.PreflightError, "archive members"):
                release_preflight.validate_crate(crate, VERSION, SHA, root)

    def test_package_member_size_is_bounded_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            crate = root / f"keyrx-{VERSION}.crate"
            root_name = f"keyrx-{VERSION}"
            oversized = "x" * (release_preflight.MAX_MEMBER_BYTES + 1)
            with tarfile.open(crate, "w:gz") as archive:
                add_tar_text(archive, f"{root_name}/README.md", oversized)
            with self.assertRaisesRegex(release_preflight.PreflightError, "unsafe size"):
                release_preflight.validate_crate(crate, VERSION, SHA, root)


class ChecksumManifestTests(unittest.TestCase):
    def valid_manifest(self):
        names = (
            f"keyrx-{VERSION}.crate",
            f"keyrx-{VERSION}.crate.sha256",
            f"keyrx-{VERSION}.cdx.json",
            f"keyrx-{VERSION}.crate.sigstore.json",
            f"keyrx-{VERSION}.crate.intoto.jsonl",
        )
        return "".join(f"{index:064x}  {name}\n" for index, name in enumerate(names, 1))

    def test_exact_unique_asset_coverage_is_accepted(self):
        result = release_preflight.validate_checksum_manifest(
            self.valid_manifest(), VERSION, "SHA256SUMS"
        )
        self.assertEqual(len(result), 5)

    def test_duplicate_entry_cannot_substitute_for_a_missing_asset(self):
        lines = self.valid_manifest().splitlines()
        lines[-1] = lines[0]
        with self.assertRaisesRegex(release_preflight.PreflightError, "duplicate"):
            release_preflight.validate_checksum_manifest(
                "\n".join(lines) + "\n", VERSION, "SHA256SUMS"
            )

    def test_noncanonical_or_unexpected_checksum_entry_is_rejected(self):
        hostile = (
            self.valid_manifest().replace("0" * 63 + "1", "A" * 64, 1),
            self.valid_manifest().replace(f"keyrx-{VERSION}.crate", "unrelated.bin", 1),
        )
        for manifest in hostile:
            with self.subTest(manifest=manifest), self.assertRaises(
                release_preflight.PreflightError
            ):
                release_preflight.validate_checksum_manifest(
                    manifest, VERSION, "SHA256SUMS"
                )


if __name__ == "__main__":
    unittest.main()
