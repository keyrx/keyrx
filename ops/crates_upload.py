#!/usr/bin/env python3
"""Build crates.io's documented upload body around one prevalidated .crate.

This program has no network access. It converts bounded `cargo metadata`
output into the registry Web API metadata and embeds the exact archive bytes;
the release workflow may then upload that body without asking `cargo publish`
to create a second, potentially different archive.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tarfile


CRATE_NAME = "keyrx"
MAX_CRATE_BYTES = 10 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_README_BYTES = 1024 * 1024
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class UploadError(RuntimeError):
    pass


def _read_json(path: Path) -> dict:
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_METADATA_BYTES:
            raise UploadError(
                f"cargo metadata is {size} bytes; expected 1..{MAX_METADATA_BYTES}"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UploadError(f"cannot read cargo metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise UploadError("cargo metadata top level is not an object")
    return value


def _string(value: object, field: str, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise UploadError(f"cargo metadata field {field} is not a string")
    return value


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise UploadError(f"cargo metadata field {field} is not an array of strings")
    return value


def _manifest_relative(value: str | None, package: dict, field: str) -> str | None:
    if value is None:
        return None
    manifest = _string(package.get("manifest_path"), "manifest_path", optional=False)
    assert manifest is not None
    path = Path(value)
    if path.is_absolute():
        try:
            path = path.relative_to(Path(manifest).parent)
        except ValueError as exc:
            raise UploadError(f"{field} is outside the package manifest directory") from exc
    posix = PurePosixPath(path.as_posix())
    if posix.is_absolute() or not posix.parts or ".." in posix.parts:
        raise UploadError(f"unsafe {field} path {value!r}")
    return posix.as_posix()


def _read_archive_file(crate_path: Path, member_name: str) -> str:
    try:
        with tarfile.open(crate_path, "r:gz") as archive:
            member = archive.getmember(member_name)
            if not member.isfile() or member.size < 0 or member.size > MAX_README_BYTES:
                raise UploadError(f"archive readme {member_name!r} is missing or too large")
            source = archive.extractfile(member)
            if source is None:
                raise UploadError(f"archive readme {member_name!r} is not readable")
            data = source.read(MAX_README_BYTES + 1)
            if len(data) != member.size or len(data) > MAX_README_BYTES:
                raise UploadError(f"archive readme {member_name!r} exceeds its safe bound")
            return data.decode("utf-8")
    except (OSError, KeyError, tarfile.TarError, UnicodeError) as exc:
        if isinstance(exc, UploadError):
            raise
        raise UploadError(f"cannot read packaged readme {member_name}: {exc}") from exc


def _dependency(item: object) -> dict:
    if not isinstance(item, dict):
        raise UploadError("cargo metadata dependency is not an object")
    name = _string(item.get("name"), "dependencies[].name", optional=False)
    requirement = _string(item.get("req"), "dependencies[].req", optional=False)
    source = _string(item.get("source"), "dependencies[].source")
    registry = _string(item.get("registry"), "dependencies[].registry")
    rename = _string(item.get("rename"), "dependencies[].rename")
    target = _string(item.get("target"), "dependencies[].target")
    kind = item.get("kind") or "normal"
    if kind not in {"normal", "dev", "build"}:
        raise UploadError(f"unsupported dependency kind {kind!r}")
    if source is not None and not source.startswith("registry+"):
        raise UploadError(f"dependency {name!r} is not from a registry")
    if registry is not None:
        raise UploadError(f"dependency {name!r} names a non-default registry")
    optional = item.get("optional")
    default_features = item.get("uses_default_features")
    if not isinstance(optional, bool) or not isinstance(default_features, bool):
        raise UploadError(f"dependency {name!r} lacks boolean feature flags")
    return {
        "name": name,
        "version_req": requirement,
        "features": _strings(item.get("features"), "dependencies[].features"),
        "optional": optional,
        "default_features": default_features,
        "target": target,
        "kind": kind,
        "registry": None,
        "explicit_name_in_toml": rename,
    }


def build_metadata(crate_path: Path, cargo_metadata: dict, version: str) -> dict:
    if not VERSION_RE.fullmatch(version):
        raise UploadError(f"non-canonical release version {version!r}")
    packages = cargo_metadata.get("packages")
    if not isinstance(packages, list):
        raise UploadError("cargo metadata has no packages array")
    matches = [
        item
        for item in packages
        if isinstance(item, dict)
        and item.get("name") == CRATE_NAME
        and item.get("version") == version
        and item.get("source") is None
    ]
    if len(matches) != 1:
        raise UploadError(
            f"cargo metadata must contain exactly one local {CRATE_NAME} {version} package"
        )
    package = matches[0]
    if crate_path.name != f"{CRATE_NAME}-{version}.crate":
        raise UploadError(f"unexpected crate filename {crate_path.name!r}")
    publish = package.get("publish")
    if publish is not None and (
        not isinstance(publish, list) or "crates-io" not in publish
    ):
        raise UploadError("package metadata does not permit publishing to crates.io")

    readme_file = _manifest_relative(
        _string(package.get("readme"), "readme"), package, "readme"
    )
    readme = None
    if readme_file is not None:
        readme = _read_archive_file(
            crate_path, f"{CRATE_NAME}-{version}/{readme_file}"
        )

    features = package.get("features")
    if not isinstance(features, dict):
        raise UploadError("cargo metadata features is not an object")
    for name, enabled in features.items():
        if not isinstance(name, str):
            raise UploadError("cargo feature name is not a string")
        _strings(enabled, f"features.{name}")

    dependencies = package.get("dependencies")
    if not isinstance(dependencies, list):
        raise UploadError("cargo metadata dependencies is not an array")
    deps = [_dependency(item) for item in dependencies]
    deps.sort(key=lambda item: (item["name"], item["kind"], item["target"] or ""))

    return {
        "name": CRATE_NAME,
        "vers": version,
        "deps": deps,
        "features": features,
        "authors": _strings(package.get("authors"), "authors"),
        "description": _string(package.get("description"), "description"),
        "documentation": _string(package.get("documentation"), "documentation"),
        "homepage": _string(package.get("homepage"), "homepage"),
        "readme": readme,
        "readme_file": readme_file,
        "keywords": _strings(package.get("keywords"), "keywords"),
        "categories": _strings(package.get("categories"), "categories"),
        "license": _string(package.get("license"), "license"),
        "license_file": _manifest_relative(
            _string(package.get("license_file"), "license_file"),
            package,
            "license_file",
        ),
        "repository": _string(package.get("repository"), "repository"),
        "badges": {},
        "links": _string(package.get("links"), "links"),
        "rust_version": _string(package.get("rust_version"), "rust_version"),
    }


def build_body(crate_path: Path, cargo_metadata: dict, version: str) -> bytes:
    try:
        crate_size = crate_path.stat().st_size
        if crate_size <= 0 or crate_size > MAX_CRATE_BYTES:
            raise UploadError(
                f"crate is {crate_size} bytes; expected 1..{MAX_CRATE_BYTES}"
            )
        crate_bytes = crate_path.read_bytes()
    except OSError as exc:
        raise UploadError(f"cannot read crate {crate_path}: {exc}") from exc
    metadata = json.dumps(
        build_metadata(crate_path, cargo_metadata, version),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(metadata) > 0xFFFFFFFF or len(crate_bytes) > 0xFFFFFFFF:
        raise UploadError("registry upload component exceeds its u32 protocol length")
    return (
        struct.pack("<I", len(metadata))
        + metadata
        + struct.pack("<I", len(crate_bytes))
        + crate_bytes
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("crate", type=Path)
    parser.add_argument("cargo_metadata", type=Path)
    parser.add_argument("output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        body = build_body(args.crate, _read_json(args.cargo_metadata), args.version)
        args.output.write_bytes(body)
    except (OSError, UploadError) as exc:
        print(f"crates.io upload body failed: {exc}", file=sys.stderr)
        return 1
    print(f"built exact crates.io upload body: {len(body)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
