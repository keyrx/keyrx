#!/usr/bin/env python3
"""Generate keyrx's deterministic CycloneDX SBOM from Cargo.toml and Cargo.lock."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import uuid


class SbomError(RuntimeError):
    pass


def read_toml(path: Path) -> dict:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SbomError(f"cannot read TOML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SbomError(f"{path} has no TOML document")
    return value


def build_sbom(manifest: dict, lock: dict, version: str, source_sha: str) -> dict:
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("name") != "keyrx":
        raise SbomError("Cargo.toml must describe package keyrx")
    if package.get("version") != version:
        raise SbomError("Cargo.toml version differs from the release version")
    if not isinstance(source_sha, str) or len(source_sha) != 40 or any(
        char not in "0123456789abcdef" for char in source_sha
    ):
        raise SbomError("source SHA must be 40 lowercase hexadecimal characters")

    raw_packages = lock.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise SbomError("Cargo.lock has no package entries")
    packages: dict[tuple[str, str], dict] = {}
    for item in raw_packages:
        if not isinstance(item, dict):
            raise SbomError("Cargo.lock contains a non-table package entry")
        name, item_version = item.get("name"), item.get("version")
        if not isinstance(name, str) or not isinstance(item_version, str):
            raise SbomError("Cargo.lock package identity is incomplete")
        identity = (name, item_version)
        if identity in packages:
            raise SbomError(f"Cargo.lock repeats {name} {item_version}")
        packages[identity] = item

    root = ("keyrx", version)
    if root not in packages:
        raise SbomError("Cargo.lock does not contain the released keyrx package")
    refs = {
        identity: f"pkg:cargo/{identity[0]}@{identity[1]}" for identity in packages
    }
    by_name: dict[str, list[tuple[str, str]]] = {}
    for identity in packages:
        by_name.setdefault(identity[0], []).append(identity)

    dependency_rows = []
    for identity, item in sorted(packages.items()):
        targets = []
        raw_dependencies = item.get("dependencies", [])
        if not isinstance(raw_dependencies, list):
            raise SbomError(f"Cargo.lock dependencies for {identity[0]} are not a list")
        for raw in raw_dependencies:
            if not isinstance(raw, str):
                raise SbomError("Cargo.lock contains a non-string dependency")
            parts = raw.split()
            candidates = [
                candidate
                for candidate in by_name.get(parts[0], [])
                if len(parts) == 1 or candidate[1] == parts[1]
            ]
            if len(candidates) != 1:
                raise SbomError(f"Cargo.lock dependency is ambiguous: {raw!r}")
            targets.append(refs[candidates[0]])
        dependency_rows.append({"ref": refs[identity], "dependsOn": sorted(targets)})

    license_name = package.get("license")
    if not isinstance(license_name, str) or not license_name:
        raise SbomError("Cargo.toml package.license is missing")
    root_component = {
        "type": "application",
        "bom-ref": refs[root],
        "name": "keyrx",
        "version": version,
        "purl": refs[root],
        "licenses": [{"license": {"id": license_name}}],
    }
    components = []
    for identity in sorted(packages):
        if identity == root:
            continue
        item = packages[identity]
        if item.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
            raise SbomError(f"dependency {identity[0]} {identity[1]} is not from crates.io")
        checksum = item.get("checksum")
        if (
            not isinstance(checksum, str)
            or len(checksum) != 64
            or any(char not in "0123456789abcdef" for char in checksum)
        ):
            raise SbomError(f"dependency {identity[0]} {identity[1]} has no canonical checksum")
        components.append(
            {
                "type": "library",
                "bom-ref": refs[identity],
                "name": identity[0],
                "version": identity[1],
                "purl": refs[identity],
                "hashes": [{"alg": "SHA-256", "content": checksum}],
            }
        )
    serial_hex = hashlib.sha256(
        (source_sha + "\0keyrx-cdx-1.5").encode("ascii")
    ).hexdigest()[:32]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.UUID(serial_hex)}",
        "version": 1,
        "metadata": {"component": root_component},
        "components": components,
        "dependencies": dependency_rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("source_sha")
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--lock", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args(argv)
    try:
        sbom = build_sbom(
            read_toml(args.manifest),
            read_toml(args.lock),
            args.version,
            args.source_sha,
        )
        encoded = json.dumps(
            sbom, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        args.output.write_bytes(encoded)
    except (OSError, SbomError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
