#!/usr/bin/env python3
"""Compile-proof the public source selection.

`validate_source_boundary.py` proves that the selected file set is closed under
`mod` declarations, `include!` macros and declared Cargo edges. It does not
prove that the selection *compiles*: it resolves paths, not symbols. This
script closes that gap.

It:

  1. asks `validate_source_boundary.py` for the deterministic selection,
  2. materialises exactly those files (relative paths and modes preserved)
     into a clean temporary tree,
  3. runs the materialised tree's own boundary validator in target mode,
  4. checks its public metadata, pinned toolchain, internal links and runnable
     guidance, using `cargo metadata --locked --no-deps`,
  5. replaces the private selection authority with its deterministic,
     target-native public manifest and runs `cargo check --locked --all-targets`, and
  6. reports machine-readably which public files fail, with which error codes
     and which unresolved symbols, deduplicated and grouped.

Nothing in the repository is ever modified. The harness derives the same
target-native manifest as publication and never creates placeholders for held files.

Usage
-----
    python3 scripts/release/compile_public_selection.py
    python3 scripts/release/compile_public_selection.py --keep --report out.json
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_source_boundary as boundary  # noqa: E402

VALIDATOR = Path("scripts/release/validate_source_boundary.py")
CANDIDATE_CHECKER = Path("scripts/release/check_public_candidate.py")

# Backticked paths/identifiers a rustc diagnostic names as unresolved.
_BACKTICKED = re.compile(r"`([^`]+)`")
_UNRESOLVED_MESSAGE = re.compile(
    r"^(?:"
    r"unresolved import"
    r"|failed to resolve"
    r"|cannot find"
    r"|use of unresolved module or unlinked crate"
    r"|cannot determine resolution"
    r"|no (?:method|function|variant|associated item)"
    r"|unresolved imports"
    r")"
)


# --------------------------------------------------------------------------
# selection
# --------------------------------------------------------------------------


def emit_selection(repo: Path, manifest: Path, mode: str, out: Path) -> list[dict]:
    cmd = [
        sys.executable,
        str(repo / VALIDATOR),
        "--manifest",
        str(manifest),
        "--repo",
        str(repo),
        "--mode",
        mode,
        "--emit-selection",
        str(out),
    ]
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            "compile-public-selection: the boundary validator refused:\n"
            + proc.stderr.strip()
        )
    payload = json.loads(out.read_text(encoding="utf-8"))
    return payload["files"]


def materialise(repo: Path, files: list[dict], dest: Path) -> list[str]:
    """Copy exactly the selected blobs into `dest`, preserving mode."""
    written: list[str] = []
    for item in sorted(files, key=lambda i: i["target_path"]):
        if item.get("type") != "blob":
            continue
        source_rel = item["source_path"]
        rel = item["target_path"]
        src = repo / source_rel
        if not src.is_file():
            raise SystemExit(f"compile-public-selection: selected file missing: {source_rel}")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
        mode = item.get("mode")
        if mode:
            os.chmod(target, int(str(mode)[-4:], 8) & 0o7777)
        written.append(rel)
    return written


def write_target_manifest(tree: Path, upstream_manifest: dict) -> None:
    path = tree / "native-boundary.json"
    if not path.is_file():
        raise SystemExit("compile-public-selection: materialised boundary manifest is missing")
    path.write_bytes(boundary.target_manifest_bytes(upstream_manifest))
    path.chmod(0o644)


# --------------------------------------------------------------------------
# cargo
# --------------------------------------------------------------------------


def run_cargo(tree: Path, target_dir: Path, extra: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env["CARGO_TERM_COLOR"] = "never"
    cmd = [
        "cargo",
        "check",
        "--locked",
        "--all-targets",
        "--message-format=json-diagnostic-rendered-ansi",
        *extra,
    ]
    # plain rendering, deterministic ordering of our own report
    cmd[4] = "--message-format=json"
    return subprocess.run(cmd, cwd=tree, env=env, capture_output=True, text=True)


def validate_materialised_target(tree: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(tree / VALIDATOR),
            "--repo",
            str(tree),
            "--manifest",
            str(tree / "native-boundary.json"),
            "--mode",
            "target",
        ],
        cwd=tree,
        capture_output=True,
        text=True,
    )


def validate_public_candidate(tree: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(tree / CANDIDATE_CHECKER),
            "--repo",
            str(tree),
        ],
        cwd=tree,
        capture_output=True,
        text=True,
    )


# "cannot find type `Catalog` in module `crate::hosting`"
_IN_MODULE = re.compile(r"^cannot find \w+ `([^`]+)` in (?:module|crate) `([^`]+)`")
# "failed to resolve: could not find `memberships` in `hosting`"
_COULD_NOT_FIND = re.compile(r"could not find `([^`]+)` in `([^`]+)`")
# "failed to resolve: use of unresolved module or unlinked crate `native_x`"
_UNLINKED_CRATE = re.compile(r"use of unresolved module or unlinked crate `([^`]+)`")
# "unresolved import(s) `a`, `b`"
_UNRESOLVED_IMPORT = re.compile(r"^unresolved imports? (.+)$")


def _extract_symbols(message: str) -> list[str]:
    """Normalise a rustc diagnostic to the fully-qualified path(s) it names.

    rustc spells the same missing item three different ways depending on the
    error code, and several of those messages carry two backticked fragments
    (the item and the module). Joining them keeps one symbol per real use site
    instead of counting the module once per mention.
    """
    if not _UNRESOLVED_MESSAGE.match(message):
        return []
    m = _IN_MODULE.match(message)
    if m:
        return [f"{m.group(2)}::{m.group(1)}"]
    m = _COULD_NOT_FIND.search(message)
    if m:
        return [f"{m.group(2)}::{m.group(1)}"]
    m = _UNLINKED_CRATE.search(message)
    if m:
        return [m.group(1)]
    m = _UNRESOLVED_IMPORT.match(message)
    if m:
        return _BACKTICKED.findall(m.group(1))
    return _BACKTICKED.findall(message)


def analyse(proc: subprocess.CompletedProcess) -> dict:
    """Turn cargo's JSON stream into a deduplicated, grouped report."""
    diagnostics: list[dict] = []
    manifest_error: str | None = None

    for raw in proc.stdout.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        d = msg["message"]
        if d.get("level") not in ("error", "error: internal compiler error"):
            continue
        code = (d.get("code") or {}).get("code")
        text = d.get("message", "")
        spans = [s for s in d.get("spans", []) if s.get("is_primary")]
        if not spans:
            spans = d.get("spans", [])
        file_name = spans[0]["file_name"] if spans else "<no-span>"
        line = spans[0]["line_start"] if spans else None
        diagnostics.append(
            {
                "code": code,
                "message": text,
                "file": file_name,
                "line": line,
                "symbols": _extract_symbols(text),
                "rendered": d.get("rendered", "").strip(),
            }
        )

    if not diagnostics and proc.returncode != 0:
        manifest_error = proc.stderr.strip()

    by_file: dict[str, dict] = collections.defaultdict(
        lambda: {"errors": [], "count": 0}
    )
    symbol_sites: dict[str, list[str]] = collections.defaultdict(list)
    codes = collections.Counter()

    for d in diagnostics:
        codes[d["code"] or "<no-code>"] += 1
        entry = by_file[d["file"]]
        entry["count"] += 1
        key = (d["code"], d["message"])
        if key not in {(e["code"], e["message"]) for e in entry["errors"]}:
            entry["errors"].append(
                {"code": d["code"], "message": d["message"], "lines": []}
            )
        for e in entry["errors"]:
            if (e["code"], e["message"]) == key and d["line"] is not None:
                e["lines"].append(d["line"])
        for sym in d["symbols"]:
            symbol_sites[sym].append(f"{d['file']}:{d['line']}")

    return {
        "compiled": proc.returncode == 0,
        "cargo_exit_code": proc.returncode,
        "manifest_resolution_error": manifest_error,
        "error_count": len(diagnostics),
        "error_codes": dict(sorted(codes.items(), key=lambda kv: (-kv[1], str(kv[0])))),
        "failing_files": {
            f: {
                "count": v["count"],
                "errors": sorted(
                    ({**e, "lines": sorted(set(e["lines"]))} for e in v["errors"]),
                    key=lambda e: (str(e["code"]), e["message"]),
                ),
            }
            for f, v in sorted(by_file.items())
        },
        "unresolved_symbols": {
            s: {"use_sites": len(sites), "sites": sorted(set(sites))}
            for s, sites in sorted(
                symbol_sites.items(), key=lambda kv: (-len(kv[1]), kv[0])
            )
        },
        "stderr_tail": "\n".join(proc.stderr.strip().splitlines()[-40:]),
    }


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", type=Path, default=Path("."))
    p.add_argument("--manifest", type=Path, default=Path("native-ce-boundary.json"))
    p.add_argument("--target-dir", type=Path, default=None,
                   help="shared CARGO_TARGET_DIR (default <repo>/target/public-selection-check)")
    p.add_argument("--keep", action="store_true", help="leave the temp tree in place")
    p.add_argument("--report", type=Path, help="write the JSON report here (default stdout)")
    p.add_argument("cargo_args", nargs="*", help="extra args passed to cargo check")
    args = p.parse_args(argv)

    repo = args.repo.resolve()
    manifest_path = (repo / args.manifest) if not args.manifest.is_absolute() else args.manifest

    tmp = Path(tempfile.mkdtemp(prefix="native-public-selection-"))
    tree = tmp / "tree"
    tree.mkdir()
    target_dir = (
        args.target_dir.resolve()
        if args.target_dir
        else repo / "target" / "public-selection-check"
    )
    target_dir.mkdir(parents=True, exist_ok=True)

    try:
        files = emit_selection(
            repo, manifest_path, "upstream", tmp / "selected-source.json"
        )
        written = materialise(repo, files, tree)
        upstream_manifest = boundary.load_manifest(manifest_path, mode="upstream")
        write_target_manifest(tree, upstream_manifest)
        selected = set(written)

        report: dict = {
            "harness": {
                "temp_tree": str(tree),
                "cargo_target_dir": str(target_dir),
                "selected_files": len(written),
                "cargo_lock_in_selection": "Cargo.lock" in selected,
                "root_cargo_toml_in_selection": "Cargo.toml" in selected,
                "build_rs_in_selection": "build.rs" in selected,
                "target_native_manifest": True,
                "stubbed_held_modules": False,
                "selection_source": "validate_source_boundary.py",
            }
        }

        if "Cargo.toml" not in selected:
            raise SystemExit("compile-public-selection: the selection has no root Cargo.toml")

        target_validation = validate_materialised_target(tree)
        report["harness"]["target_validation_passed"] = target_validation.returncode == 0
        report["harness"]["target_validation_stdout"] = target_validation.stdout.strip()
        report["harness"]["target_validation_stderr"] = target_validation.stderr.strip()
        if target_validation.returncode != 0:
            raise SystemExit(
                "compile-public-selection: materialised target validation failed:\n"
                + target_validation.stderr.strip()
            )

        candidate_validation = validate_public_candidate(tree)
        report["harness"]["candidate_validation_passed"] = (
            candidate_validation.returncode == 0
        )
        report["harness"]["candidate_validation_stdout"] = (
            candidate_validation.stdout.strip()
        )
        report["harness"]["candidate_validation_stderr"] = (
            candidate_validation.stderr.strip()
        )
        if candidate_validation.returncode != 0:
            raise SystemExit(
                "compile-public-selection: public candidate validation failed:\n"
                + candidate_validation.stderr.strip()
            )

        proc = run_cargo(tree, target_dir, args.cargo_args)
        report.update(analyse(proc))
        encoded = json.dumps(report, indent=2, sort_keys=False) + "\n"
        if args.report:
            args.report.write_text(encoded, encoding="utf-8")
        else:
            sys.stdout.write(encoded)

        print(
            f"compile-public-selection: {'COMPILED' if report['compiled'] else 'FAILED'}"
            f" ({report['error_count']} errors, exit {report['cargo_exit_code']});"
            f" tree={tree if args.keep else '(removed)'}",
            file=sys.stderr,
        )
        return 0 if report["compiled"] else 1
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
