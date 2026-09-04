#!/usr/bin/env python3
"""Check metadata and guidance in a materialised public candidate.

The input must be the projected tree, not the private upstream checkout.  This
keeps legitimate private files and maintainer guidance out of the public
release contract while proving that every check below describes what a fresh
public clone will actually contain.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit


PUBLIC_REPOSITORY = "https://github.com/withnative/native"
RUST_VERSION = "1.98"
RUST_TOOLCHAIN = "1.98.0"
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
MARKDOWN_REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)")
REPOSITORY_PATH = re.compile(r"(?<![\w./-])(?:\./)?(held|scripts)/[A-Za-z0-9_./-]+")


class CandidateError(RuntimeError):
    """The materialised public candidate is not self-consistent."""


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CandidateError(f"cannot read valid TOML from {path}: {exc}") from exc


def check_toolchain(repo: Path) -> None:
    toolchain = _read_toml(repo / "rust-toolchain.toml")
    if toolchain != {
        "toolchain": {"channel": RUST_TOOLCHAIN, "profile": "minimal"}
    }:
        raise CandidateError(
            "rust-toolchain.toml must select exactly Rust 1.98.0 with the minimal profile"
        )


def _link_destination(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<") and ">" in value:
        return value[1 : value.index(">")]
    # Markdown permits an optional title after a whitespace-separated URL.
    return value.split(maxsplit=1)[0]


def check_markdown_links(repo: Path) -> None:
    failures: list[str] = []
    repo = repo.resolve()
    for document in sorted(repo.rglob("*.md")):
        relative_document = document.relative_to(repo)
        fenced = False
        fence = ""
        for line_number, line in enumerate(
            document.read_text(encoding="utf-8").splitlines(), 1
        ):
            marker_match = re.match(r"\s*(`{3,}|~{3,})", line)
            if marker_match:
                marker = marker_match.group(1)
                if not fenced:
                    fenced = True
                    fence = marker[0]
                elif marker[0] == fence:
                    fenced = False
                    fence = ""
                continue
            if fenced:
                continue
            links = [(match.group(1), match.start()) for match in MARKDOWN_LINK.finditer(line)]
            reference = MARKDOWN_REFERENCE.match(line)
            if reference:
                # Validating the definition destination covers full, collapsed,
                # and shortcut reference links without reimplementing Markdown's
                # label-resolution rules.
                links.append((reference.group(1), reference.start(1)))
            for raw_destination, start in links:
                # A Markdown-looking example inside an inline code span is not
                # navigation. Link labels may themselves contain code (for
                # example [`Cargo.toml`](Cargo.toml)), so only count backticks
                # before the opening bracket rather than stripping code spans.
                if line[:start].count("`") % 2:
                    continue
                destination = _link_destination(raw_destination)
                parsed = urlsplit(destination)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                decoded = unquote(parsed.path)
                target = (
                    repo / decoded.lstrip("/")
                    if decoded.startswith("/")
                    else document.parent / decoded
                )
                target = target.resolve()
                try:
                    target.relative_to(repo)
                except ValueError:
                    failures.append(
                        f"{relative_document}:{line_number}: internal link escapes candidate {destination!r}"
                    )
                    continue
                if not target.exists():
                    failures.append(
                        f"{relative_document}:{line_number}: missing internal link {destination!r}"
                    )
    if failures:
        raise CandidateError("broken candidate Markdown links:\n" + "\n".join(failures))


def check_runnable_guidance(repo: Path) -> None:
    failures: list[str] = []
    for document in sorted(repo.rglob("*.md")):
        relative_document = document.relative_to(repo)
        fenced = False
        fence = ""
        for line_number, line in enumerate(
            document.read_text(encoding="utf-8").splitlines(), 1
        ):
            stripped = line.lstrip()
            marker_match = re.match(r"(`{3,}|~{3,})", stripped)
            if marker_match:
                marker = marker_match.group(1)
                if not fenced:
                    fenced = True
                    fence = marker[0]
                elif marker[0] == fence:
                    fenced = False
                    fence = ""
                continue
            if not fenced:
                continue
            for match in REPOSITORY_PATH.finditer(line):
                family = match.group(1)
                value = match.group(0).rstrip(".,:;)")
                normalized = value.removeprefix("./")
                if family == "held":
                    failures.append(
                        f"{relative_document}:{line_number}: public command names held path {value!r}"
                    )
                elif not (repo / normalized).exists():
                    failures.append(
                        f"{relative_document}:{line_number}: public command names missing path {value!r}"
                    )
    if failures:
        raise CandidateError(
            "misleading runnable guidance in candidate:\n" + "\n".join(failures)
        )


def cargo_metadata(repo: Path, cargo: str) -> dict:
    result = subprocess.run(
        (cargo, "metadata", "--locked", "--no-deps", "--format-version", "1"),
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise CandidateError(
            f"cargo metadata failed with exit {result.returncode}:\n{result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CandidateError(f"cargo metadata returned invalid JSON: {exc}") from exc


def check_cargo_metadata(repo: Path, metadata: dict) -> None:
    workspace_members = metadata.get("workspace_members")
    packages = metadata.get("packages")
    if not isinstance(workspace_members, list) or not isinstance(packages, list):
        raise CandidateError("cargo metadata omitted workspace_members or packages")
    by_id = {package.get("id"): package for package in packages}
    failures: list[str] = []
    for package_id in workspace_members:
        package = by_id.get(package_id)
        if package is None:
            failures.append(f"workspace package {package_id!r} is absent from metadata")
            continue
        try:
            manifest = Path(package["manifest_path"]).resolve().relative_to(repo.resolve())
        except (KeyError, ValueError):
            failures.append(f"workspace package {package_id!r} has a manifest outside the candidate")
            continue
        if package.get("repository") != PUBLIC_REPOSITORY:
            failures.append(
                f"{manifest}: repository is {package.get('repository')!r}, expected {PUBLIC_REPOSITORY!r}"
            )
        if package.get("rust_version") != RUST_VERSION:
            failures.append(
                f"{manifest}: rust-version is {package.get('rust_version')!r}, expected {RUST_VERSION!r}"
            )
    if failures:
        raise CandidateError("public Cargo metadata is inconsistent:\n" + "\n".join(failures))


def check(repo: Path, cargo: str) -> None:
    check_toolchain(repo)
    check_markdown_links(repo)
    check_runnable_guidance(repo)
    check_cargo_metadata(repo, cargo_metadata(repo, cargo))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args(argv)
    try:
        check(args.repo.resolve(), args.cargo)
    except CandidateError as exc:
        print(f"public-candidate: refused: {exc}", file=sys.stderr)
        return 1
    print("public-candidate: metadata, toolchain, links, and guidance are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
