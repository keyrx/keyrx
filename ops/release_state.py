#!/usr/bin/env python3
"""Probe or validate a KeyRX GitHub Release against local assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


class ReleaseError(RuntimeError):
    pass


def required_assets(version: str) -> tuple[str, ...]:
    return (
        f"keyrx-{version}.crate",
        f"keyrx-{version}.crate.sha256",
        f"keyrx-{version}.cdx.json",
        f"keyrx-{version}.crate.sigstore.json",
        f"keyrx-{version}.crate.intoto.jsonl",
        f"keyrx-{version}.SHA256SUMS",
    )


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def probe_release(
    payload: dict,
    version: str,
    source_sha: str,
    notes: str,
    assets_root: Path,
) -> dict[str, int | str]:
    """Classify an authenticated release lookup before run-specific provenance.

    Stable assets must already equal this run's prepared bytes when present.
    Complete prior provenance is downloaded and verified by the workflow before
    it is reused; a partial prior upload is deliberately not guessed around.
    """
    if not VERSION_RE.fullmatch(version):
        raise ReleaseError("version is not canonical MAJOR.MINOR.PATCH")
    if not SHA_RE.fullmatch(source_sha):
        raise ReleaseError("source SHA is not 40 lowercase hexadecimal characters")
    release_id = payload.get("id")
    if not isinstance(release_id, int) or release_id <= 0:
        raise ReleaseError("release has no positive integer id")
    expected = {
        "tag_name": f"v{version}",
        "target_commitish": source_sha,
        "name": f"keyrx {version}",
        "body": notes,
        "prerelease": False,
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            raise ReleaseError(
                f"release {field} differs: expected {value!r}, got {payload.get(field)!r}"
            )
    draft = payload.get("draft")
    if not isinstance(draft, bool):
        raise ReleaseError("release draft state is not boolean")
    if draft:
        if payload.get("published_at") is not None:
            raise ReleaseError("draft release unexpectedly has published_at")
    else:
        if payload.get("immutable") is not True:
            raise ReleaseError("published release is not immutable")
        if not isinstance(payload.get("published_at"), str):
            raise ReleaseError("published release has no published_at timestamp")

    rows = payload.get("assets")
    if not isinstance(rows, list):
        raise ReleaseError("release has no assets array")
    allowed = set(required_assets(version))
    stable = {
        f"keyrx-{version}.crate",
        f"keyrx-{version}.crate.sha256",
        f"keyrx-{version}.cdx.json",
    }
    names = set()
    asset_ids = set()
    asset_urls = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ReleaseError("release contains an asset without a name")
        name = row["name"]
        if name in names:
            raise ReleaseError(f"release repeats asset {name!r}")
        names.add(name)
        if name not in allowed:
            raise ReleaseError(f"release contains unexpected asset {name!r}")
        asset_id = row.get("id")
        asset_url = row.get("url")
        if (
            not isinstance(asset_id, int)
            or asset_id <= 0
            or not isinstance(asset_url, str)
            or not asset_url
            or row.get("state") != "uploaded"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", row.get("digest", ""))
            or not isinstance(row.get("size"), int)
            or row["size"] <= 0
        ):
            raise ReleaseError(f"release asset {name!r} has invalid API identity")
        if asset_id in asset_ids or asset_url in asset_urls:
            raise ReleaseError(f"release asset {name!r} repeats an API identity")
        asset_ids.add(asset_id)
        asset_urls.add(asset_url)
        if name in stable:
            path = assets_root / name
            if not path.is_file():
                raise ReleaseError(f"local stable release asset is missing: {name}")
            if row["size"] != path.stat().st_size or row["digest"] != "sha256:" + digest(path):
                raise ReleaseError(f"release stable asset {name!r} differs")
    if not draft and names != allowed:
        raise ReleaseError("published release does not contain the exact six assets")
    if not names:
        state = "draft-empty"
    elif names == allowed:
        state = "draft-exact" if draft else "published"
    else:
        state = "draft-partial"
    return {"release_id": release_id, "state": state}


def validate_release(
    payload: dict,
    version: str,
    source_sha: str,
    notes: str,
    assets_root: Path,
    expected_state: str,
) -> int:
    if not VERSION_RE.fullmatch(version):
        raise ReleaseError("version is not canonical MAJOR.MINOR.PATCH")
    if not SHA_RE.fullmatch(source_sha):
        raise ReleaseError("source SHA is not 40 lowercase hexadecimal characters")
    if expected_state not in {"draft", "published"}:
        raise ReleaseError(f"unsupported expected state {expected_state!r}")
    release_id = payload.get("id")
    if not isinstance(release_id, int) or release_id <= 0:
        raise ReleaseError("release has no positive integer id")
    expected = {
        "tag_name": f"v{version}",
        "target_commitish": source_sha,
        "name": f"keyrx {version}",
        "body": notes,
        "draft": expected_state == "draft",
        "prerelease": False,
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            raise ReleaseError(
                f"release {field} differs: expected {value!r}, got {payload.get(field)!r}"
            )
    if expected_state == "published" and payload.get("immutable") is not True:
        raise ReleaseError("published release is not immutable")
    if expected_state == "draft" and payload.get("published_at") is not None:
        raise ReleaseError("draft release unexpectedly has published_at")
    if expected_state == "published" and not isinstance(payload.get("published_at"), str):
        raise ReleaseError("published release has no published_at timestamp")

    rows = payload.get("assets")
    if not isinstance(rows, list):
        raise ReleaseError("release has no assets array")
    expected_names = required_assets(version)
    by_name = {}
    asset_ids = set()
    asset_urls = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ReleaseError("release contains an asset without a name")
        name = row["name"]
        if name in by_name:
            raise ReleaseError(f"release repeats asset {name!r}")
        asset_id = row.get("id")
        asset_url = row.get("url")
        if (
            not isinstance(asset_id, int)
            or asset_id <= 0
            or not isinstance(asset_url, str)
            or not asset_url
            or asset_id in asset_ids
            or asset_url in asset_urls
        ):
            raise ReleaseError(f"release asset {name!r} has invalid or repeated API identity")
        asset_ids.add(asset_id)
        asset_urls.add(asset_url)
        by_name[name] = row
    if set(by_name) != set(expected_names):
        raise ReleaseError(
            f"release asset set differs: expected={sorted(expected_names)}, got={sorted(by_name)}"
        )
    for name in expected_names:
        path = assets_root / name
        if not path.is_file():
            raise ReleaseError(f"local release asset is missing: {name}")
        row = by_name[name]
        size = path.stat().st_size
        if size <= 0 or row.get("size") != size:
            raise ReleaseError(
                f"release asset {name} size differs: expected {size}, got {row.get('size')!r}"
            )
        expected_digest = "sha256:" + digest(path)
        if row.get("digest") != expected_digest:
            raise ReleaseError(
                f"release asset {name} digest differs: expected {expected_digest}, "
                f"got {row.get('digest')!r}"
            )
        if row.get("state") != "uploaded":
            raise ReleaseError(f"release asset {name} is not uploaded")
    return release_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("version")
    parser.add_argument("source_sha")
    parser.add_argument("notes", type=Path)
    parser.add_argument("assets_root", type=Path)
    parser.add_argument("state", choices=("probe", "draft", "published"))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.payload.read_text(encoding="utf-8"))
        notes = args.notes.read_text(encoding="utf-8")
        if args.state == "probe":
            result = probe_release(
                payload,
                args.version,
                args.source_sha,
                notes,
                args.assets_root,
            )
        else:
            release_id = validate_release(
                payload,
                args.version,
                args.source_sha,
                notes,
                args.assets_root,
                args.state,
            )
            result = {"release_id": release_id}
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                for key, value in result.items():
                    output.write(f"{key}={value}\n")
        else:
            print(json.dumps(result, sort_keys=True) if args.state == "probe" else result["release_id"])
    except (OSError, UnicodeError, json.JSONDecodeError, ReleaseError) as exc:
        print(f"release state failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
