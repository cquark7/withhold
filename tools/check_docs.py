#!/usr/bin/env python3
"""Check local inline Markdown links and heading anchors in public docs."""

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")


def prose(text):
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
        elif fence is None:
            yield number, line


def anchors(text):
    result = set()
    for _, line in prose(text):
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*$", line)
        if match:
            base = re.sub(r"[^\w -]", "", match[1].lower()).replace(" ", "-")
            slug, count = base, 0
            while slug in result:
                count += 1
                slug = f"{base}-{count}"
            result.add(slug)
    return result


def check_links(path, root):
    path, root = path.resolve(), root.resolve()
    errors = []
    for number, line in prose(path.read_text(encoding="utf-8")):
        for destination in LINK.findall(line):
            url = urlsplit(destination)
            if url.scheme or url.netloc:
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not target.is_relative_to(root) or not target.exists():
                problem = "missing local destination"
            elif url.fragment and target.suffix == ".md":
                if unquote(url.fragment) in anchors(target.read_text(encoding="utf-8")):
                    continue
                problem = "missing heading"
            else:
                continue
            errors.append(
                f"{path.relative_to(root)}:{number}: {problem}: {destination}"
            )
    return errors


def public_documents():
    return sorted(
        [*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md")]
        + list(ROOT.glob(".github/ISSUE_TEMPLATE/*.md"))
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    errors = [error for path in public_documents() for error in check_links(path, ROOT)]
    for error in errors:
        print(error)
    if not errors:
        print("Public documentation links and anchors are valid.")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
