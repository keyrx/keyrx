#!/usr/bin/env python3
"""Select one exact GitHub Release from paginated API output.

``gh api --paginate`` writes one JSON array per response page.  GitHub's
release-by-tag endpoint intentionally omits drafts, so the release workflow
enumerates the authenticated releases collection and uses this helper to bind
an exact tag to zero or one positive release ID.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


TAG_RE = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class ReleaseLookupError(RuntimeError):
    pass


def parse_pages(text: str) -> list[list[object]]:
    """Decode every concatenated JSON page and reject incomplete output."""
    decoder = json.JSONDecoder()
    pages: list[list[object]] = []
    cursor = 0
    while True:
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor == len(text):
            break
        try:
            value, cursor = decoder.raw_decode(text, cursor)
        except json.JSONDecodeError as exc:
            raise ReleaseLookupError(f"invalid paginated release response: {exc}") from exc
        if not isinstance(value, list):
            raise ReleaseLookupError("a paginated release response is not an array")
        pages.append(value)
    if not pages:
        raise ReleaseLookupError("paginated release response is empty")
    return pages


def select_release_id(pages: list[list[object]], tag: str) -> int | None:
    if not TAG_RE.fullmatch(tag):
        raise ReleaseLookupError("release tag is not canonical vMAJOR.MINOR.PATCH")
    matches: list[int] = []
    for page in pages:
        if not isinstance(page, list):
            raise ReleaseLookupError("a paginated release response is not an array")
        for row in page:
            if not isinstance(row, dict):
                raise ReleaseLookupError("release collection contains a non-object")
            row_tag = row.get("tag_name")
            if not isinstance(row_tag, str):
                raise ReleaseLookupError("release collection row has no string tag_name")
            if row_tag != tag:
                continue
            release_id = row.get("id")
            if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
                raise ReleaseLookupError("matching release has no positive integer id")
            matches.append(release_id)
    if len(matches) > 1:
        raise ReleaseLookupError(f"release collection repeats exact tag {tag!r}")
    return matches[0] if matches else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pages", type=Path)
    parser.add_argument("tag")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        text = args.pages.read_text(encoding="utf-8")
        release_id = select_release_id(parse_pages(text), args.tag)
        result = {"state": "found" if release_id is not None else "absent"}
        if release_id is not None:
            result["release_id"] = str(release_id)
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                for key, value in result.items():
                    output.write(f"{key}={value}\n")
        else:
            print(json.dumps(result, sort_keys=True))
    except (OSError, UnicodeError, ReleaseLookupError) as exc:
        print(f"release lookup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
