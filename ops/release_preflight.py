#!/usr/bin/env python3
"""Read-only release agreement and package checks for keyrx.

The release workflow is intentionally thin around this script so the checks can
also run locally and be covered by ordinary unit tests. This program never
writes files and never contacts GitHub or crates.io.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tomllib


CRATE_NAME = "keyrx"
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SITE_VERSION_RE = re.compile(r"\bvar\s+VERSION\s*=\s*(['\"])([^'\"]+)\1\s*;")
CHANGELOG_RELEASE_RE = re.compile(
    r"((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
    r"\s+-\s+(\d{4}-\d{2}-\d{2})\Z"
)
CHANGELOG_VERSION_LIKE_RE = re.compile(
    r"(?:\[?v?[0-9]+\.[0-9]+\.[0-9]+|"
    r"(?:release|version)\s+v?[0-9]+\.[0-9]+\.[0-9]+|"
    r"\(v?[0-9]+\.[0-9]+\.[0-9]+\))",
    re.IGNORECASE,
)
CHECKSUM_LINE_RE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)\Z")
MAX_CRATE_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
REQUIRED_PACKAGE_PATHS = {
    "Cargo.toml",
    "Cargo.toml.orig",
    "Cargo.lock",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "TRADEMARK.md",
    "src/main.rs",
}
class PreflightError(RuntimeError):
    """A release input is incomplete, ambiguous, or inconsistent."""


def require_release_version(version: str) -> None:
    if not VERSION_RE.fullmatch(version):
        raise PreflightError(
            f"release version must be canonical MAJOR.MINOR.PATCH, got {version!r}"
        )


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PreflightError(f"cannot read UTF-8 file {path}: {exc}") from exc


def parse_toml(text: str, source: str) -> dict:
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PreflightError(f"invalid TOML in {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise PreflightError(f"invalid top-level TOML value in {source}")
    return value


def manifest_version(text: str, source: str) -> str:
    package = parse_toml(text, source).get("package")
    if not isinstance(package, dict):
        raise PreflightError(f"{source} has no [package] table")
    if package.get("name") != CRATE_NAME:
        raise PreflightError(
            f"{source} package name is {package.get('name')!r}, expected {CRATE_NAME!r}"
        )
    version = package.get("version")
    if not isinstance(version, str):
        raise PreflightError(f"{source} has no string package.version")
    return version


def lock_version(text: str, source: str) -> str:
    packages = parse_toml(text, source).get("package")
    if not isinstance(packages, list):
        raise PreflightError(f"{source} has no [[package]] entries")
    matches = [p for p in packages if isinstance(p, dict) and p.get("name") == CRATE_NAME]
    if len(matches) != 1 or not isinstance(matches[0].get("version"), str):
        raise PreflightError(
            f"{source} must contain exactly one versioned {CRATE_NAME!r} package entry"
        )
    return matches[0]["version"]


def site_version(text: str, source: str) -> str:
    matches = SITE_VERSION_RE.findall(text)
    if len(matches) != 1:
        raise PreflightError(
            f"{source} must contain exactly one JavaScript VERSION assignment; found {len(matches)}"
        )
    return matches[0][1]


def _visible_h2_headings(text: str) -> list[tuple[int, int, str]]:
    """Return Markdown H2s outside fenced code and HTML comments."""
    headings = []
    offset = 0
    fence_char = None
    fence_width = 0
    in_comment = False
    opening_fence_re = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
    closing_fence_re = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
    h2_re = re.compile(r"^ {0,3}##[ \t]+(.+?)[ \t]*#*[ \t]*$")

    def opening_fence(line: str) -> str | None:
        match = opening_fence_re.match(line)
        if not match:
            return None
        marker, suffix = match.groups()
        # CommonMark forbids a backtick in a backtick-fence info string;
        # tilde-fence info strings have no equivalent restriction.
        if marker[0] == "`" and "`" in suffix:
            return None
        return marker

    for line_with_ending in text.splitlines(keepends=True):
        line = line_with_ending.rstrip("\r\n")

        # Comment markers are literal text inside a fenced block. Handle only
        # a valid closing fence there, before looking for HTML comments.
        if fence_char is not None:
            fence = closing_fence_re.match(line)
            if fence:
                marker = fence.group(1)
                if marker[0] == fence_char and len(marker) >= fence_width:
                    fence_char, fence_width = None, 0
            offset += len(line_with_ending)
            continue

        # A comment marker in an opening fence's info string is literal. Give
        # a raw opening fence precedence when no earlier comment is active.
        marker = opening_fence(line) if not in_comment else None
        if marker:
            fence_char, fence_width = marker[0], len(marker)
            offset += len(line_with_ending)
            continue

        visible = ""
        rest = line
        while rest:
            if in_comment:
                end = rest.find("-->")
                if end < 0:
                    rest = ""
                    break
                in_comment = False
                rest = rest[end + 3 :]
                continue
            start = rest.find("<!--")
            if start < 0:
                visible += rest
                break
            visible += rest[:start]
            rest = rest[start + 4 :]
            in_comment = True

        marker = opening_fence(visible) if not in_comment else None
        if marker:
            fence_char, fence_width = marker[0], len(marker)
            offset += len(line_with_ending)
            continue

        if fence_char is None:
            match = h2_re.match(visible)
            if match:
                headings.append((offset, offset + len(line), match.group(1).strip()))
        offset += len(line_with_ending)
    return headings


def changelog_notes(text: str, version: str, source: str) -> str:
    require_release_version(version)
    version_headings = []
    for start, end, title in _visible_h2_headings(text):
        if not CHANGELOG_VERSION_LIKE_RE.match(title):
            continue
        release = CHANGELOG_RELEASE_RE.fullmatch(title)
        if not release:
            raise PreflightError(f"{source} has malformed release heading '## {title}'")
        try:
            dt.date.fromisoformat(release.group(2))
        except ValueError as exc:
            raise PreflightError(
                f"{source} has invalid date {release.group(2)!r} for {release.group(1)}"
            ) from exc
        version_headings.append((start, end, release.group(1)))

    parsed_versions = [
        tuple(map(int, heading[2].split("."))) for heading in version_headings
    ]
    for newer, older in zip(parsed_versions, parsed_versions[1:]):
        if newer <= older:
            raise PreflightError(
                f"{source} release headings must be unique and strictly descending; "
                f"found {'.'.join(map(str, newer))} before {'.'.join(map(str, older))}"
            )

    matches = [heading for heading in version_headings if heading[2] == version]
    if len(matches) != 1:
        raise PreflightError(
            f"{source} must contain exactly one '## {version} - YYYY-MM-DD' heading; "
            f"found {len(matches)}"
        )
    if not version_headings or version_headings[0] != matches[0]:
        first = version_headings[0][2] if version_headings else "none"
        raise PreflightError(
            f"{source} newest version is {first!r}, expected release {version!r}"
        )

    heading = matches[0]
    later = [candidate for candidate in version_headings if candidate[0] > heading[0]]
    end = later[0][0] if later else len(text)
    notes = text[heading[1] : end].strip()
    if not notes:
        raise PreflightError(f"{source} section for {version} is empty")
    return notes + "\n"


def validate_repository(root: Path, version: str) -> str:
    require_release_version(version)
    manifest = manifest_version(read_text(root / "Cargo.toml"), "Cargo.toml")
    lock = lock_version(read_text(root / "Cargo.lock"), "Cargo.lock")
    site = site_version(read_text(root / "site" / "index.html"), "site/index.html")
    notes = changelog_notes(read_text(root / "CHANGELOG.md"), version, "CHANGELOG.md")
    versions = {
        "Cargo.toml package.version": manifest,
        "Cargo.lock keyrx version": lock,
        "site/index.html VERSION": site,
        "release version": version,
    }
    disagreements = [f"{name}={value!r}" for name, value in versions.items() if value != version]
    if disagreements:
        raise PreflightError("release version disagreement: " + ", ".join(disagreements))
    return notes


def validate_checksum_manifest(text: str, version: str, source: str) -> dict[str, str]:
    """Require one canonical checksum for each non-manifest release asset."""
    require_release_version(version)
    expected = {
        f"{CRATE_NAME}-{version}.crate",
        f"{CRATE_NAME}-{version}.crate.sha256",
        f"{CRATE_NAME}-{version}.cdx.json",
        f"{CRATE_NAME}-{version}.crate.sigstore.json",
        f"{CRATE_NAME}-{version}.crate.intoto.jsonl",
    }
    checksums: dict[str, str] = {}
    lines = text.splitlines()
    for line_number, line in enumerate(lines, 1):
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if not match:
            raise PreflightError(
                f"{source} line {line_number} is not a canonical sha256sum entry"
            )
        digest, name = match.groups()
        if name in checksums:
            raise PreflightError(f"{source} contains duplicate entry {name!r}")
        checksums[name] = digest
    if set(checksums) != expected:
        missing = sorted(expected - set(checksums))
        extra = sorted(set(checksums) - expected)
        raise PreflightError(
            f"{source} does not cover the exact release assets; missing={missing}, extra={extra}"
        )
    return checksums


def _archive_bytes(archive: tarfile.TarFile, member_name: str) -> bytes:
    member = archive.getmember(member_name)
    if member.size > MAX_MEMBER_BYTES:
        raise PreflightError(
            f"package member {member_name!r} is {member.size} bytes; limit is {MAX_MEMBER_BYTES}"
        )
    extracted = archive.extractfile(member)
    if extracted is None:
        raise PreflightError(f"package member {member_name!r} is not a regular file")
    data = extracted.read(MAX_MEMBER_BYTES + 1)
    if len(data) != member.size or len(data) > MAX_MEMBER_BYTES:
        raise PreflightError(f"package member {member_name!r} exceeds its safe read bound")
    return data


def _archive_text(archive: tarfile.TarFile, member_name: str) -> str:
    try:
        return _archive_bytes(archive, member_name).decode("utf-8")
    except UnicodeError as exc:
        raise PreflightError(f"package member {member_name!r} is not UTF-8") from exc


def _git_blob(repository_root: Path, source_sha: str, relative: str) -> bytes:
    """Read one regular blob from the exact commit, rejecting symlink modes."""
    try:
        record = subprocess.run(
            ["git", "-C", str(repository_root), "ls-tree", "-z", source_sha, "--", relative],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PreflightError(f"cannot resolve git source {source_sha}:{relative}: {exc}") from exc
    records = [item for item in record.split(b"\0") if item]
    if len(records) != 1:
        raise PreflightError(
            f"git source {source_sha}:{relative} resolved to {len(records)} entries"
        )
    try:
        header, raw_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        decoded_path = raw_path.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise PreflightError(f"malformed git tree record for {relative!r}") from exc
    if decoded_path != relative or object_type != "blob" or mode not in {"100644", "100755"}:
        raise PreflightError(
            f"git source {relative!r} is not the exact regular blob requested "
            f"(path={decoded_path!r}, mode={mode!r}, type={object_type!r})"
        )
    try:
        return subprocess.run(
            ["git", "-C", str(repository_root), "cat-file", "blob", object_id],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PreflightError(f"cannot read git blob {object_id} for {relative}: {exc}") from exc


def _held_checkout_bytes(repository_root: Path, relative: str) -> bytes:
    """Read stable bytes beneath a held, symlink-free directory chain."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise PreflightError("platform lacks the no-follow directory opens release validation needs")
    pure = PurePosixPath(relative)
    parts = pure.parts
    if (
        pure.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or "/".join(parts) != relative
    ):
        raise PreflightError(f"checkout source path is not canonical and relative: {relative!r}")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    def state(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def close_chain(directories: list[int], leaf: int | None) -> tuple[BaseException, ...]:
        errors = []
        descriptors = ([leaf] if leaf is not None else []) + list(reversed(directories))
        for item in descriptors:
            try:
                os.close(item)
            except BaseException as exc:
                errors.append(exc)
        return tuple(errors)

    def open_chain() -> tuple[list[int], int, tuple[tuple[int, ...], ...]]:
        directories: list[int] = []
        leaf: int | None = None
        before_states: list[tuple[int, ...]] = []
        try:
            root_before = os.lstat(repository_root)
            if not stat.S_ISDIR(root_before.st_mode):
                raise PreflightError("repository root is not a real directory")
            root_descriptor = os.open(repository_root, directory_flags)
            directories.append(root_descriptor)
            root_held = os.fstat(root_descriptor)
            if state(root_before) != state(root_held) or not stat.S_ISDIR(root_held.st_mode):
                raise PreflightError("repository root changed before its held open")
            before_states.append(state(root_before))

            for component in parts[:-1]:
                before = os.stat(component, dir_fd=directories[-1], follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise PreflightError(
                        f"checkout source {relative!r} has a non-directory or symlink parent"
                    )
                descriptor = os.open(component, directory_flags, dir_fd=directories[-1])
                directories.append(descriptor)
                held = os.fstat(descriptor)
                if state(before) != state(held) or not stat.S_ISDIR(held.st_mode):
                    raise PreflightError(
                        f"checkout source {relative!r} parent changed before open"
                    )
                before_states.append(state(before))

            before = os.stat(parts[-1], dir_fd=directories[-1], follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise PreflightError(f"checkout source {relative!r} is not a regular file")
            leaf = os.open(parts[-1], file_flags, dir_fd=directories[-1])
            held = os.fstat(leaf)
            if state(before) != state(held) or not stat.S_ISREG(held.st_mode):
                raise PreflightError(f"checkout source {relative!r} changed before open")
            before_states.append(state(before))
            return directories, leaf, tuple(before_states)
        except BaseException as exc:
            errors = close_chain(directories, leaf)
            control = next(
                (item for item in (exc, *errors) if not isinstance(item, Exception)),
                None,
            )
            if control is not None:
                if errors:
                    control.add_note(
                        f"checkout cleanup also reported {len(errors)} error(s)"
                    )
                raise control
            if errors:
                exc.add_note(
                    f"checkout cleanup also reported {len(errors)} ordinary error(s)"
                )
            raise

    def read_once(descriptor: int, expected_size: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MEMBER_BYTES:
                raise PreflightError(f"checkout source {relative!r} exceeds its safe read bound")
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != expected_size:
            raise PreflightError(f"checkout source {relative!r} changed length while read")
        return data

    directories: list[int] = []
    descriptor: int | None = None
    fresh_directories: list[int] = []
    fresh_descriptor: int | None = None
    result: bytes | None = None
    primary: BaseException | None = None
    try:
        directories, descriptor, before_states = open_chain()
        expected_size = before_states[-1][6]
        if expected_size > MAX_MEMBER_BYTES:
            raise PreflightError(f"checkout source {relative!r} exceeds its safe read bound")
        first = read_once(descriptor, expected_size)
        middle_states = tuple(state(os.fstat(item)) for item in (*directories, descriptor))
        second = read_once(descriptor, expected_size)
        after_states = tuple(state(os.fstat(item)) for item in (*directories, descriptor))
        if first != second or before_states != middle_states or before_states != after_states:
            raise PreflightError(f"checkout source {relative!r} changed during stable read")

        fresh_directories, fresh_descriptor, fresh_states = open_chain()
        if fresh_states != before_states:
            raise PreflightError(f"checkout source {relative!r} path changed during validation")
        fresh_bytes = read_once(fresh_descriptor, expected_size)
        fresh_after_states = tuple(
            state(os.fstat(item)) for item in (*fresh_directories, fresh_descriptor)
        )
        if fresh_bytes != first or fresh_after_states != fresh_states:
            raise PreflightError(f"checkout source {relative!r} changed during final path read")
        result = first
    except BaseException as exc:
        primary = exc

    fresh_errors = close_chain(fresh_directories, fresh_descriptor)
    held_errors = close_chain(directories, descriptor)
    cleanup_errors = (*fresh_errors, *held_errors)
    control = next(
        (
            item
            for item in ((primary,) if primary is not None else ()) + cleanup_errors
            if not isinstance(item, Exception)
        ),
        None,
    )
    if control is not None:
        if cleanup_errors:
            control.add_note(
                "checkout cleanup completed after "
                f"{len(cleanup_errors)} reported close error(s)"
            )
        raise control
    if primary is not None:
        if cleanup_errors:
            primary.add_note(
                f"checkout cleanup also reported {len(cleanup_errors)} ordinary error(s)"
            )
        if isinstance(primary, OSError):
            raise PreflightError(
                f"cannot safely read checkout source {relative!r}: {primary}"
            ) from primary
        raise primary
    if cleanup_errors:
        raise PreflightError(
            "cannot close all checkout descriptors after validation "
            f"(fresh={len(fresh_errors)}, held={len(held_errors)})"
        ) from cleanup_errors[0]
    if result is None:
        raise PreflightError(f"checkout source {relative!r} produced no stable read")
    return result


def validate_crate(
    crate_path: Path,
    version: str,
    source_sha: str,
    repository_root: Path = Path("."),
    require_git_source: bool = False,
) -> None:
    """Validate a locally built package against its checkout and event SHA.

    `.cargo_vcs_info.json` is archive-controlled metadata, so it is never used
    alone as provenance. Every packaged source byte is also compared with the
    checkout; the workflow then compares this archive's external SHA-256 with
    crates.io and GitHub's asset digest.
    """
    require_release_version(version)
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise PreflightError(f"source SHA must be 40 lowercase hex characters, got {source_sha!r}")
    if crate_path.name != f"{CRATE_NAME}-{version}.crate":
        raise PreflightError(
            f"package filename is {crate_path.name!r}, expected {CRATE_NAME}-{version}.crate"
        )
    if not crate_path.is_file():
        raise PreflightError(f"package does not exist as a regular file: {crate_path}")
    crate_size = crate_path.stat().st_size
    if crate_size <= 0 or crate_size > MAX_CRATE_BYTES:
        raise PreflightError(
            f"package is {crate_size} bytes; expected 1..{MAX_CRATE_BYTES} bytes"
        )

    root = f"{CRATE_NAME}-{version}"
    try:
        with tarfile.open(crate_path, "r:gz") as archive:
            members = []
            expanded_bytes = 0
            for member in archive:
                members.append(member)
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise PreflightError(
                        f"package has more than {MAX_ARCHIVE_MEMBERS} archive members"
                    )
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise PreflightError(
                        f"package member {member.name!r} has unsafe size {member.size}"
                    )
                expanded_bytes += member.size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise PreflightError(
                        f"package expands beyond {MAX_EXPANDED_BYTES} bytes"
                    )
            names = [member.name for member in members]
            canonical_names = [PurePosixPath(name).as_posix() for name in names]
            if (
                not members
                or len(names) != len(set(names))
                or len(canonical_names) != len(set(canonical_names))
            ):
                raise PreflightError(
                    "package archive is empty or contains duplicate/aliasing member names"
                )
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != root
                    or member.name != path.as_posix()
                ):
                    raise PreflightError(f"unsafe or unexpected package member {member.name!r}")
                if not (member.isfile() or member.isdir()):
                    raise PreflightError(
                        f"package member {member.name!r} is not a regular file or directory"
                    )

            manifest_name = f"{root}/Cargo.toml"
            lock_name = f"{root}/Cargo.lock"
            changelog_name = f"{root}/CHANGELOG.md"
            vcs_name = f"{root}/.cargo_vcs_info.json"
            required = {
                f"{root}/{path}" for path in REQUIRED_PACKAGE_PATHS
            } | {manifest_name, vcs_name}
            missing = sorted(required.difference(names))
            if missing:
                raise PreflightError(f"package is missing required members: {', '.join(missing)}")

            packaged_manifest = manifest_version(
                _archive_text(archive, manifest_name), manifest_name
            )
            packaged_lock = lock_version(_archive_text(archive, lock_name), lock_name)
            changelog_notes(_archive_text(archive, changelog_name), version, changelog_name)
            try:
                vcs = json.loads(_archive_text(archive, vcs_name))
            except json.JSONDecodeError as exc:
                raise PreflightError(f"invalid JSON in {vcs_name}: {exc}") from exc

            for member in members:
                if not member.isfile():
                    continue
                relative = PurePosixPath(member.name).relative_to(root).as_posix()
                if relative in {"Cargo.toml", ".cargo_vcs_info.json"}:
                    continue
                checkout_relative = "Cargo.toml" if relative == "Cargo.toml.orig" else relative
                packaged = _archive_bytes(archive, member.name)
                checkout = _held_checkout_bytes(repository_root, checkout_relative)
                if packaged != checkout:
                    raise PreflightError(
                        f"package member {relative!r} differs byte-for-byte from checkout {checkout_relative!r}"
                    )
                if require_git_source:
                    committed = _git_blob(repository_root, source_sha, checkout_relative)
                    if packaged != committed:
                        raise PreflightError(
                            f"package member {relative!r} differs byte-for-byte from git blob "
                            f"{source_sha}:{checkout_relative}"
                        )
    except (OSError, tarfile.TarError, KeyError) as exc:
        raise PreflightError(f"cannot validate package {crate_path}: {exc}") from exc

    if packaged_manifest != version or packaged_lock != version:
        raise PreflightError(
            "packaged Cargo.toml/Cargo.lock version disagreement: "
            f"{packaged_manifest!r}, {packaged_lock!r}, expected {version!r}"
        )
    git = vcs.get("git") if isinstance(vcs, dict) else None
    if not isinstance(git, dict):
        raise PreflightError(f"{vcs_name} has no git object")
    # Cargo omits `dirty` for a clean package and writes it only as true for an
    # --allow-dirty package; tolerate an explicit false for older/newer Cargo.
    dirty = git.get("dirty", False)
    if git.get("sha1") != source_sha or dirty is not False:
        raise PreflightError(
            f"package source is sha1={git.get('sha1')!r}, dirty={dirty!r}; "
            f"expected sha1={source_sha!r}, dirty=false"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="exact MAJOR.MINOR.PATCH release version")
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument("--notes", action="store_true", help="print only the validated notes")
    parser.add_argument("--crate", type=Path, help="also validate this packaged .crate")
    parser.add_argument("--sha", help="expected 40-character source SHA for --crate")
    parser.add_argument(
        "--git-source",
        action="store_true",
        help="bind every packaged source byte to --sha git blobs and reject symlink modes",
    )
    parser.add_argument("--checksums", type=Path, help="also validate an exact SHA256SUMS file")
    args = parser.parse_args(argv)
    if bool(args.crate) != bool(args.sha):
        parser.error("--crate and --sha must be supplied together")
    if args.git_source and not args.crate:
        parser.error("--git-source requires --crate and --sha")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        notes = validate_repository(args.root, args.version)
        if args.crate:
            validate_crate(
                args.crate,
                args.version,
                args.sha,
                args.root,
                require_git_source=args.git_source,
            )
        if args.checksums:
            validate_checksum_manifest(
                read_text(args.checksums), args.version, str(args.checksums)
            )
    except PreflightError as exc:
        print(f"release preflight failed: {exc}", file=sys.stderr)
        return 1
    if args.notes:
        sys.stdout.write(notes)
    else:
        suffix = " and requested artifacts" if args.crate or args.checksums else ""
        print(f"release preflight OK: keyrx {args.version}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
