#!/usr/bin/env python3
"""Validate the committed, inert release-policy document.

The privileged GitHub Actions job deliberately does not execute this
candidate-owned file. This module neither models nor authorizes provider effects;
shipping-boundary controls exercise the effect job's extracted inline validators.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
MAX_POLICY_BYTES = 64 * 1024
EXPECTED_ASSET_SUFFIXES = (
    ".crate",
    ".crate.sha256",
    ".cdx.json",
    ".crate.sigstore.json",
    ".crate.intoto.jsonl",
    ".SHA256SUMS",
)
LEGACY_MIGRATION = {
    "mode": "legacy-crate-tag",
    "version": "0.4.12",
    "checksum": "dcf2ff724aa2d0ec43173a2d1a7f225ea39efa8c5d61e43b02c82b26a4f7854d",
    "sourceSha": "9b4725a0e8b160ccacad0d7b858793ba8dee4a89",
    "archiveMembers": [
        "keyrx-0.4.12/.cargo_vcs_info.json",
        "keyrx-0.4.12/CHANGELOG.md",
        "keyrx-0.4.12/Cargo.lock",
        "keyrx-0.4.12/Cargo.toml",
        "keyrx-0.4.12/Cargo.toml.orig",
        "keyrx-0.4.12/LICENSE",
        "keyrx-0.4.12/README.md",
        "keyrx-0.4.12/TRADEMARK.md",
        "keyrx-0.4.12/src/evm.rs",
        "keyrx-0.4.12/src/main.rs",
        "keyrx-0.4.12/src/ui.rs",
    ],
}


class ContractError(RuntimeError):
    pass


def _exact_keys(value: dict, expected: set[str], source: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ContractError(
            f"{source} fields disagree: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _versions(values: object, source: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ContractError(f"{source} must be a non-empty array")
    if any(not isinstance(value, str) or not VERSION_RE.fullmatch(value) for value in values):
        raise ContractError(f"{source} contains a non-canonical version")
    if len(values) != len(set(values)):
        raise ContractError(f"{source} contains duplicate versions")
    return values


def validate_policy(policy: object) -> dict:
    if not isinstance(policy, dict):
        raise ContractError("release policy must be an object")
    _exact_keys(
        policy,
        {
            "schema",
            "crate",
            "version",
            "tag",
            "sourceBranch",
            "predecessorEvidence",
            "expectedLiveBefore",
            "yankTargets",
            "assets",
        },
        "release policy",
    )
    if policy["schema"] != 1 or policy["crate"] != "keyrx":
        raise ContractError("unsupported release policy identity")
    version = policy["version"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ContractError("release policy version is not canonical")
    if policy["tag"] != f"v{version}" or policy["sourceBranch"] != "main":
        raise ContractError("release policy tag or source branch disagrees")
    evidence = policy["predecessorEvidence"]
    if not isinstance(evidence, dict):
        raise ContractError("predecessorEvidence must be an object")
    _exact_keys(
        evidence,
        {"mode", "version", "checksum", "sourceSha", "archiveMembers"},
        "predecessorEvidence",
    )
    if evidence["mode"] not in {"legacy-crate-tag", "immutable-six-asset"}:
        raise ContractError("unsupported predecessor evidence mode")
    if not isinstance(evidence["version"], str) or not VERSION_RE.fullmatch(evidence["version"]):
        raise ContractError("predecessor evidence version is not canonical")
    if not isinstance(evidence["checksum"], str) or not DIGEST_RE.fullmatch(evidence["checksum"]):
        raise ContractError("predecessor evidence checksum is not a lowercase SHA-256")
    if not isinstance(evidence["sourceSha"], str) or not SHA_RE.fullmatch(evidence["sourceSha"]):
        raise ContractError("predecessor evidence sourceSha is not a full lowercase commit SHA")
    if evidence["mode"] == "legacy-crate-tag" and (
        version != "0.4.13" or evidence != LEGACY_MIGRATION
    ):
        raise ContractError(
            "legacy predecessor evidence is authorized only for the exact 0.4.12 to 0.4.13 migration"
        )
    members = evidence["archiveMembers"]
    root = f"keyrx-{evidence['version']}/"
    if (
        not isinstance(members, list)
        or not members
        or len(members) > 4096
        or len(members) != len(set(members))
        or any(
            not isinstance(member, str)
            or len(member.encode("utf-8")) > 4096
            or not member.startswith(root)
            or member.startswith("/")
            or "/../" in f"/{member}/"
            for member in members
        )
    ):
        raise ContractError("predecessor archiveMembers is not a bounded unique safe member set")
    live = _versions(policy["expectedLiveBefore"], "expectedLiveBefore")
    yanks = _versions(policy["yankTargets"], "yankTargets")
    if live != yanks:
        raise ContractError("yankTargets must equal the exact reviewed live predecessor set")
    if evidence["version"] not in live:
        raise ContractError("governed predecessor is absent from the reviewed live set")
    current_key = tuple(map(int, version.split(".")))
    if any(tuple(map(int, item.split("."))) >= current_key for item in live):
        raise ContractError("reviewed live/yank set contains a non-predecessor version")
    expected_assets = [f"keyrx-{version}{suffix}" for suffix in EXPECTED_ASSET_SUFFIXES]
    if policy["assets"] != expected_assets:
        raise ContractError("release asset list is not the canonical ordered six-file set")
    return policy


def load_policy(path: Path) -> dict:
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_POLICY_BYTES:
            raise ContractError(f"release policy size {size} is outside its safe bound")
        raw = path.read_bytes()
        if b"\x00" in raw:
            raise ContractError("release policy contains NUL")
        value = json.loads(raw.decode("utf-8"))
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot load release policy {path}: {exc}") from exc
    return validate_policy(value)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        policy = load_policy(args.policy)
    except ContractError as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 2
    if args.print_json:
        print(json.dumps(policy, sort_keys=True, separators=(",", ":")))
    else:
        print(f"release contract OK: {policy['tag']} -> {policy['sourceBranch']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
