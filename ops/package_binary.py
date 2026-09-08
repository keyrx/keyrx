#!/usr/bin/env python3
"""Build or validate the deterministic KeyRX Linux/WSL binary archive.

This helper performs no compilation.  The release workflow gives it one binary
that was built twice and compared byte-for-byte, plus source files from the
checked-out release commit.  The archive format and metadata are deliberately
fixed so the same inputs and SOURCE_DATE_EPOCH produce the same bytes.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile


CRATE_NAME = "keyrx"
LINUX_TARGET = "x86_64-unknown-linux-musl"
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_EPOCH = (1 << 32) - 1


class PackageError(RuntimeError):
    """The requested binary archive is unsafe, malformed, or inconsistent."""


def archive_name(version: str, target: str = LINUX_TARGET) -> str:
    return f"{CRATE_NAME}-{version}-{target}.tar.gz"


def _validate_identity(version: str, source_sha: str, target: str, epoch: int) -> None:
    if not VERSION_RE.fullmatch(version):
        raise PackageError("version is not canonical MAJOR.MINOR.PATCH")
    if not SHA_RE.fullmatch(source_sha):
        raise PackageError("source SHA is not 40 lowercase hexadecimal characters")
    if target != LINUX_TARGET:
        raise PackageError(f"unsupported binary target {target!r}")
    if not 0 <= epoch <= MAX_EPOCH:
        raise PackageError(f"SOURCE_DATE_EPOCH must be in 0..{MAX_EPOCH}")


def _state(value: os.stat_result) -> tuple[int, ...]:
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


def _read_regular(path: Path, *, executable: bool = False) -> bytes:
    """Read one stable regular file without following a symbolic link."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise PackageError("platform lacks O_NOFOLLOW required for release inputs")
    flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise PackageError(f"release input is not a regular file: {path}")
        descriptor = os.open(path, flags)
        held = os.fstat(descriptor)
        if _state(before) != _state(held) or not stat.S_ISREG(held.st_mode):
            raise PackageError(f"release input changed before it was held: {path}")
        if executable and not (held.st_mode & stat.S_IXUSR):
            raise PackageError(f"binary is not owner-executable: {path}")
        if held.st_size <= 0 or held.st_size > MAX_INPUT_BYTES:
            raise PackageError(
                f"release input size is outside 1..{MAX_INPUT_BYTES}: {path}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise PackageError(f"release input exceeds its read bound: {path}")
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if len(data) != held.st_size or _state(after) != _state(held):
            raise PackageError(f"release input changed while it was read: {path}")
        if _state(current) != _state(held):
            raise PackageError(f"release input path changed while it was read: {path}")
        return data
    except OSError as exc:
        raise PackageError(f"cannot safely read release input {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise PackageError(f"cannot close release input {path}: {exc}") from exc


def _require_linux_elf(binary: bytes) -> None:
    # ELF64, little-endian, version 1; e_machine 62 is x86-64.
    if (
        len(binary) < 64
        or binary[:4] != b"\x7fELF"
        or binary[4:7] != b"\x02\x01\x01"
        or int.from_bytes(binary[18:20], "little") != 62
    ):
        raise PackageError("binary is not an ELF64 little-endian x86-64 executable")


def _source_record(version: str, source_sha: str, target: str) -> bytes:
    return (
        json.dumps(
            {"sourceSha": source_sha, "target": target, "version": version},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _tar_info(name: str, mode: int, epoch: int, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    info.size = size
    return info


def build_archive_bytes(
    *,
    version: str,
    source_sha: str,
    target: str,
    epoch: int,
    binary: bytes,
    license_text: bytes,
    readme: bytes,
) -> bytes:
    _validate_identity(version, source_sha, target, epoch)
    _require_linux_elf(binary)
    root = f"{CRATE_NAME}-{version}-{target}"
    entries = (
        (f"{root}/keyrx", 0o755, binary),
        (f"{root}/LICENSE", 0o644, license_text),
        (f"{root}/README.md", 0o644, readme),
        (f"{root}/SOURCE.json", 0o644, _source_record(version, source_sha, target)),
    )
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directory = _tar_info(root, 0o755, epoch)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, mode, data in entries:
            archive.addfile(_tar_info(name, mode, epoch, len(data)), io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=epoch
    ) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def write_archive(
    *,
    version: str,
    source_sha: str,
    target: str,
    epoch: int,
    binary_path: Path,
    license_path: Path,
    readme_path: Path,
    output: Path,
) -> None:
    expected = archive_name(version, target)
    if output.name != expected:
        raise PackageError(f"output name is {output.name!r}, expected {expected!r}")
    data = build_archive_bytes(
        version=version,
        source_sha=source_sha,
        target=target,
        epoch=epoch,
        binary=_read_regular(binary_path, executable=True),
        license_text=_read_regular(license_path),
        readme=_read_regular(readme_path),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(output, flags, 0o600)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise PackageError(f"short write while creating {output}")
            written += count
        os.fsync(descriptor)
    except OSError as exc:
        raise PackageError(f"cannot create binary archive {output}: {exc}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise PackageError(f"cannot close binary archive {output}: {exc}") from exc


def validate_archive(
    archive_path: Path,
    *,
    version: str,
    source_sha: str,
    target: str,
    epoch: int,
    license_path: Path,
    readme_path: Path,
) -> None:
    _validate_identity(version, source_sha, target, epoch)
    if archive_path.name != archive_name(version, target):
        raise PackageError("binary archive filename does not bind version and target")
    archive_bytes = _read_regular(archive_path)
    expected_root = f"{CRATE_NAME}-{version}-{target}"
    expected = (
        (expected_root, tarfile.DIRTYPE, 0o755, None),
        (f"{expected_root}/keyrx", tarfile.REGTYPE, 0o755, None),
        (f"{expected_root}/LICENSE", tarfile.REGTYPE, 0o644, _read_regular(license_path)),
        (f"{expected_root}/README.md", tarfile.REGTYPE, 0o644, _read_regular(readme_path)),
        (
            f"{expected_root}/SOURCE.json",
            tarfile.REGTYPE,
            0o644,
            _source_record(version, source_sha, target),
        ),
    )
    binary_payload: bytes | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) != len(expected):
                raise PackageError("binary archive member set differs")
            for member, (name, kind, mode, wanted) in zip(members, expected):
                pure = PurePosixPath(member.name)
                if (
                    member.name != name
                    or pure.is_absolute()
                    or ".." in pure.parts
                    or member.type != kind
                    or member.mode != mode
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != epoch
                ):
                    raise PackageError(f"binary archive metadata differs for {member.name!r}")
                if wanted is not None:
                    stream = archive.extractfile(member)
                    if stream is None or stream.read(MAX_INPUT_BYTES + 1) != wanted:
                        raise PackageError(f"binary archive content differs for {member.name!r}")
                if name.endswith("/keyrx"):
                    stream = archive.extractfile(member)
                    binary = b"" if stream is None else stream.read(MAX_INPUT_BYTES + 1)
                    if len(binary) != member.size:
                        raise PackageError("binary archive executable is truncated")
                    _require_linux_elf(binary)
                    binary_payload = binary
    except (OSError, tarfile.TarError) as exc:
        raise PackageError(f"cannot validate binary archive {archive_path}: {exc}") from exc
    if binary_payload is None:
        raise PackageError("binary archive contains no executable payload")
    canonical = build_archive_bytes(
        version=version,
        source_sha=source_sha,
        target=target,
        epoch=epoch,
        binary=binary_payload,
        license_text=_read_regular(license_path),
        readme=_read_regular(readme_path),
    )
    if archive_bytes != canonical:
        raise PackageError("binary archive bytes are not the canonical deterministic encoding")


def validate_sidecar(sidecar: Path, archive_path: Path) -> None:
    expected = (
        hashlib.sha256(_read_regular(archive_path)).hexdigest()
        + "  "
        + archive_path.name
        + "\n"
    ).encode("ascii")
    if _read_regular(sidecar) != expected:
        raise PackageError("binary archive checksum sidecar differs")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--target", default=LINUX_TARGET)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--license", type=Path, required=True)
    parser.add_argument("--readme", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--binary", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--archive", type=Path, required=True)
    check.add_argument("--sidecar", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "create":
            write_archive(
                version=args.version,
                source_sha=args.source_sha,
                target=args.target,
                epoch=args.epoch,
                binary_path=args.binary,
                license_path=args.license,
                readme_path=args.readme,
                output=args.output,
            )
        else:
            validate_archive(
                args.archive,
                version=args.version,
                source_sha=args.source_sha,
                target=args.target,
                epoch=args.epoch,
                license_path=args.license,
                readme_path=args.readme,
            )
            validate_sidecar(args.sidecar, args.archive)
    except PackageError as exc:
        print(f"binary package failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
