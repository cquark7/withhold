"""Collect dependency notices for the modules recorded in a built Go executable."""

import json
import re
import subprocess
from pathlib import Path

_DOCUMENT = re.compile(
    r"^(?:licen[sc]e|copying|notice|copyright|patents)(?:$|[._-])", re.I
)
_LICENSE = re.compile(r"^(?:licen[sc]e|copying)(?:$|[._-])", re.I)


def json_objects(text: str):
    """Decode the successive JSON objects emitted by go list."""
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        value, index = decoder.raw_decode(text, index)
        yield value


def documents(root: Path) -> list[Path]:
    paths = sorted(
        (p for p in root.rglob("*") if _DOCUMENT.match(p.name)),
        key=lambda p: p.relative_to(root).as_posix(),
    )
    files = []
    for path in paths:
        if path.is_symlink():
            raise ValueError("dependency notice must not be a symlink")
        if path.is_file():
            files.append(path)
    if not any(p.parent == root and _LICENSE.match(p.name) for p in files):
        raise ValueError("dependency has no root license document")
    return files


def module_source(path: str, version: str) -> str:
    # Go's module proxy protocol escapes each uppercase letter with !lowercase.
    def escape(value):
        return "".join("!" + c.lower() if c.isupper() else c for c in value)

    return f"https://proxy.golang.org/{escape(path)}/@v/{escape(version)}.zip"


def render_notices(build: dict, modules: dict, goroot: Path) -> bytes:
    version = build["GoVersion"]
    parts = [
        "Third-party notices for withhold\n\n"
        "This executable includes Go and the modules listed below. Module versions\n"
        "come from the executable's build information. License, notice, copyright,\n"
        "and patent documents are reproduced from their source distributions,\n"
        "including nested documents that may cover additional components.\n"
        "Module source links provide the corresponding unmodified source, including\n"
        "files covered by source-availability terms. Retain this file when\n"
        "redistributing the executable. The project's MIT license does not replace\n"
        "these dependency terms.\n"
    ]

    def append(label, source, root, paths):
        parts.append(f"\n{'=' * 72}\n{label}\nSource: {source}\n")
        for path in paths:
            data = path.read_text(encoding="utf-8")
            if not data.strip():
                raise ValueError("empty dependency notice")
            parts.append(f"\n--- {path.relative_to(root).as_posix()} ---\n{data}\n")

    # Include Go's own terms and the licenses of its vendored libraries.
    go_docs = [p for p in goroot.iterdir() if _DOCUMENT.match(p.name) and p.is_file()]
    if not any(_LICENSE.match(p.name) for p in go_docs):
        raise ValueError("Go toolchain license is missing")
    go_docs += [
        p
        for p in (goroot / "src" / "vendor").rglob("*")
        if _DOCUMENT.match(p.name) and p.is_file()
    ]
    append(
        "Go " + version,
        f"https://go.dev/dl/{version}.src.tar.gz",
        goroot,
        sorted(go_docs, key=lambda p: p.relative_to(goroot).as_posix()),
    )
    for dep in sorted(build.get("Deps", []), key=lambda item: item["Path"]):
        path, version = dep["Path"], dep["Version"]
        module = modules.get(path)
        if (
            dep.get("Replace")
            or not module
            or module.get("Replace")
            or module.get("Version") != version
            or not module.get("Dir")
        ):
            raise ValueError(f"cannot establish dependency source for {path}")
        root = Path(module["Dir"])
        append(f"{path} {version}", module_source(path, version), root, documents(root))
    result = "".join(parts).encode("utf-8")
    if len(result) > 1024 * 1024:
        raise ValueError("dependency notices exceed archive verification limit")
    return result


def build_notices(binary: Path, *, cwd: Path, env: dict) -> bytes:
    def go(*args):
        return subprocess.check_output(
            ["go", *args], cwd=cwd, env=env, encoding="utf-8"
        )

    build = json.loads(go("version", "-m", "-json", str(binary)))
    modules = {}
    for package in json_objects(go("list", "-deps", "-json", "./cmd/withhold")):
        module = package.get("Module")
        if module:
            modules[module["Path"]] = module
    goroot = Path(go("env", "GOROOT").strip())
    if build["GoVersion"] != go("env", "GOVERSION").strip():
        raise ValueError("executable and notice toolchain versions differ")
    return render_notices(build, modules, goroot)
