#!/usr/bin/env python3
"""Classify a crates.io response before or after a keyrx release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID_RE = re.compile(r"[1-9][0-9]*\Z")


class RegistryError(RuntimeError):
    pass


def version_key(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    if not match:
        raise RegistryError(f"non-canonical crates.io version {value!r}")
    return tuple(int(part) for part in match.groups())


def classify(payload: dict, version: str, checksum: str) -> dict[str, str]:
    current_key = version_key(version)
    if not SHA256_RE.fullmatch(checksum):
        raise RegistryError("expected crate checksum is not canonical SHA-256")
    rows = payload.get("versions")
    if not isinstance(rows, list):
        raise RegistryError("crates.io response has no versions array")

    seen = set()
    current = []
    older_live = []
    for row in rows:
        if not isinstance(row, dict):
            raise RegistryError("crates.io versions contains a non-object")
        number = row.get("num")
        if not isinstance(number, str):
            raise RegistryError("crates.io version has no string num")
        key = version_key(number)
        if number in seen:
            raise RegistryError(f"crates.io repeats version {number}")
        seen.add(number)
        yanked = row.get("yanked")
        if not isinstance(yanked, bool):
            raise RegistryError(f"crates.io version {number} has no boolean yanked")
        if key > current_key:
            raise RegistryError(f"newer version already exists: {number}")
        if key == current_key:
            current.append(row)
        elif key < current_key and not yanked:
            older_live.append(number)

    if len(current) > 1:
        raise RegistryError(f"crates.io repeats the release version {version}")
    if len(older_live) > 1:
        raise RegistryError(
            "expected at most one older unyanked release; found "
            + ", ".join(sorted(older_live, key=version_key))
        )
    predecessor = older_live[0] if older_live else ""
    if not current:
        return {"state": "absent", "predecessor": predecessor}

    row = current[0]
    if row.get("yanked") is not False:
        raise RegistryError(f"keyrx {version} exists but is yanked")
    actual_checksum = row.get("checksum")
    if actual_checksum != checksum:
        raise RegistryError(
            f"keyrx {version} checksum differs: expected {checksum}, got {actual_checksum!r}"
        )
    return {"state": "exact", "predecessor": predecessor}


def validate_trusted_version(
    payload: dict,
    version: str,
    checksum: str,
    crate_name: str,
    repository: str,
    source_sha: str,
) -> dict[str, str]:
    """Bind a served crate to this GitHub trusted-publisher execution."""
    version_key(version)
    if not SHA256_RE.fullmatch(checksum):
        raise RegistryError("expected crate checksum is not canonical SHA-256")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", crate_name):
        raise RegistryError("crate name is not canonical")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RegistryError("GitHub repository identity is not canonical owner/name")
    if not SHA_RE.fullmatch(source_sha):
        raise RegistryError("trusted-publisher source SHA is not canonical")
    row = payload.get("version")
    if not isinstance(row, dict):
        raise RegistryError("crates.io version response has no version object")
    expected = {
        "crate": crate_name,
        "num": version,
        "yanked": False,
        "checksum": checksum,
    }
    for field, value in expected.items():
        if row.get(field) != value:
            raise RegistryError(
                f"crates.io version {field} differs: expected {value!r}, "
                f"got {row.get(field)!r}"
            )
    trust = row.get("trustpub_data")
    if not isinstance(trust, dict):
        raise RegistryError("crates.io version has no trusted-publisher identity")
    expected_trust = {
        "provider": "github",
        "repository": repository,
        "sha": source_sha,
    }
    for field, value in expected_trust.items():
        if trust.get(field) != value:
            raise RegistryError(
                f"trusted-publisher {field} differs: expected {value!r}, "
                f"got {trust.get(field)!r}"
            )
    run_id = trust.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise RegistryError("trusted-publisher run_id is not a positive decimal string")
    return {"state": "trusted", "run_id": run_id}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("version")
    parser.add_argument("checksum")
    parser.add_argument("--trusted-crate")
    parser.add_argument("--trusted-repository")
    parser.add_argument("--trusted-sha")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.payload.read_text(encoding="utf-8"))
        trusted_values = (
            args.trusted_crate,
            args.trusted_repository,
            args.trusted_sha,
        )
        if any(value is not None for value in trusted_values):
            if not all(value is not None for value in trusted_values):
                raise RegistryError(
                    "trusted-publisher validation requires crate, repository, and SHA"
                )
            result = validate_trusted_version(
                payload,
                args.version,
                args.checksum,
                args.trusted_crate,
                args.trusted_repository,
                args.trusted_sha,
            )
        else:
            result = classify(payload, args.version, args.checksum)
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                for key, value in result.items():
                    output.write(f"{key}={value}\n")
        else:
            print(json.dumps(result, sort_keys=True))
    except (OSError, UnicodeError, json.JSONDecodeError, RegistryError) as exc:
        print(f"registry state failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
