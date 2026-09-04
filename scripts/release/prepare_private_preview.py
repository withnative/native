#!/usr/bin/env python3
"""Materialise and verify a history-free publication source candidate.

This command is deliberately local-only.  It reads one exact commit through
the authoritative private source-boundary projection, applies one explicit
private-preview or public-release projection, derives a target-native public
manifest, validates that tree in canonical target mode, and stores audit evidence
outside the candidate.  It has no
GitHub or push code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_source_boundary as boundary  # noqa: E402


FORMAT = "native-ce.private-preview-preparation/v2"
PUBLIC_FORMAT = "native-ce.public-release-preparation/v2"
PRIVATE_PREVIEW = "private-preview"
PUBLIC_RELEASE = "public-release"
SCANNER = "native-ce-private-preview-credential-scan/v1"
EXPECTED_LICENSE_SHA256 = "40e38d978117d3ea0b1925acb7fa8b1dbd0955671050ee1051fdaec277486f8a"
EXPECTED_PUBLIC_FILE_SHA256 = {
    "CONTRIBUTING.md": "0f0d98d65dd8568943db51762b2452d5160e6e33d9135e6aa8c82856c47f9e68",
    "RELEASE_NOTES.md": "ba43c67347f6fdeac04dc714d73d73209e10fa25cebd6925f827e1b1c6e00686",
}
OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$"
)
SECRET_PATTERNS = (
    (
        "private-key",
        re.compile(
            rb"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY-----"
        ),
    ),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("github-fine-grained-token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "generic-bearer",
        re.compile(rb"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    ),
)
FORBIDDEN_GENERATED_PATHS = {"LICENSE"}
PUBLIC_RELEASE_REQUIRED_PATHS = {
    ".gitignore",
    "ARCHITECTURE.md",
    "BUILDING.md",
    "CONTRIBUTING.md",
    "README.md",
    "RELEASE_NOTES.md",
    "LICENSE.md",
    "docs/README.md",
    "native-boundary.json",
}
PUBLIC_CONTENT_MARKERS = {
    "CONTRIBUTING.md": (
        "Native is developed privately",
        "curated, read-only source release",
        "We do not accept external code",
        "Please do not open pull requests",
        "GitHub Issues and Discussions are not supported feedback or support routes",
        "https://www.withnative.ai/",
        "AGPL-3.0-only",
    ),
    "RELEASE_NOTES.md": (
        "curated public source snapshots",
        "Hosted control-plane composition",
        "outside this snapshot",
        "private upstream",
        "External contributions are not accepted",
        "Issues, Discussions, and pull requests are not supported feedback or support routes",
        "https://www.withnative.ai/",
        "AGPL-3.0-only",
        "meaningful self-hosting",
        "Verification and provenance",
        "Selected-Source-SHA256",
        "intentionally unsigned in v1",
        "Snapshot cadence",
        "about every two weeks",
    ),
}
PRIVATE_PREVIEW_ONLY_PHRASES = {
    "README.md": (
        "Private early preview",
        "incomplete, generated look",
        "Release tidy-up and audit are still in progress",
        "not the final public release",
        "preview-specific edit loop",
        "native-preview",
    ),
    "BUILDING.md": (
        "Building the private preview",
        "This generated preview",
    ),
    "docs/README.md": (
        "preview-specific build and test",
        "private preview and a later public release",
        "missing contribution guide",
    ),
}
class PreviewRefusal(RuntimeError):
    """The requested local preview cannot be proven to match policy."""


def valid_rfc3339_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or RFC3339_TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def run(args: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(args), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        diagnostic = result.stderr.decode("utf-8", "replace").strip()
        raise PreviewRefusal(
            f"command failed ({args[0]}): {diagnostic or 'no diagnostic'}"
        )
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def candidate_paths(candidate: Path) -> list[str]:
    return sorted(
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(candidate).parts
    )


def scan_credentials(candidate: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for relative in candidate_paths(candidate):
        data = (candidate / relative).read_bytes()
        for detector, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                findings.append({"path": relative, "detector": detector})
    return findings


def validation_implementation(source: Path, mode: str) -> dict[str, str]:
    tool_paths = {
        "preparer_sha256": (Path(__file__).resolve(), "scripts/release/prepare_private_preview.py"),
        "boundary_validator_sha256": (
            Path(boundary.__file__).resolve(),
            "scripts/release/validate_source_boundary.py",
        ),
    }
    if mode == PUBLIC_RELEASE:
        checker = source / "scripts/release/check_public_candidate.py"
        if not checker.is_file():
            raise PreviewRefusal(
                "public-release source is missing scripts/release/check_public_candidate.py"
            )
        tool_paths["public_candidate_checker_sha256"] = (
            checker,
            checker.relative_to(source).as_posix(),
        )
    identities: dict[str, str] = {"credential_scanner": SCANNER}
    for field, (running_path, selected_path) in tool_paths.items():
        running_bytes = running_path.read_bytes()
        if running_bytes != (source / selected_path).read_bytes():
            raise PreviewRefusal(
                f"running validation tool differs from exact source: {selected_path}"
            )
        identities[field] = sha256(running_bytes)
    return identities


def validate_public_candidate(candidate: Path) -> dict[str, Any]:
    checker = candidate / "scripts/release/check_public_candidate.py"
    if not checker.is_file():
        raise PreviewRefusal(
            "public-release candidate is missing scripts/release/check_public_candidate.py"
        )
    result = subprocess.run(
        (sys.executable, str(checker), "--repo", str(candidate)),
        cwd=candidate,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        diagnostic = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise PreviewRefusal(f"public-release candidate validation failed: {diagnostic}")
    return {
        "passed": True,
        "checker_sha256": sha256(checker.read_bytes()),
    }


def exact_source(repo: Path, source_ref: str) -> tuple[str, str, str]:
    if OBJECT_ID.fullmatch(source_ref) is None:
        raise PreviewRefusal("source ref must be an exact full Git commit ID")
    commit = run(("git", "rev-parse", f"{source_ref}^{{commit}}"), cwd=repo)
    resolved = commit.stdout.decode().strip()
    if resolved != source_ref:
        raise PreviewRefusal("source ref did not resolve to the exact supplied commit")
    tree = run(("git", "show", "-s", "--format=%T", resolved), cwd=repo)
    tree_id = tree.stdout.decode().strip()
    if OBJECT_ID.fullmatch(tree_id) is None:
        raise PreviewRefusal("source commit did not resolve to an exact tree ID")
    commit_date = run(("git", "show", "-s", "--format=%cI", resolved), cwd=repo)
    source_commit_date = commit_date.stdout.decode().strip()
    if not valid_rfc3339_timestamp(source_commit_date):
        raise PreviewRefusal("source commit has an invalid committer timestamp")
    return resolved, tree_id, source_commit_date


def assert_empty_destination(path: Path, label: str) -> None:
    if not path.exists():
        return
    if not path.is_dir():
        raise PreviewRefusal(f"{label} destination exists and is not a directory: {path}")
    if any(path.iterdir()):
        raise PreviewRefusal(f"{label} destination is not empty: {path}")


def paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_destinations(source_repo: Path, output: Path, evidence: Path) -> None:
    if paths_overlap(output, evidence):
        raise PreviewRefusal("candidate and evidence destinations must not overlap")
    for path, label in ((output, "candidate"), (evidence, "evidence")):
        if paths_overlap(source_repo, path):
            raise PreviewRefusal(f"{label} destination must not overlap the source repository")
        assert_empty_destination(path, label)


def clone_exact_source(source_repo: Path, commit: str, destination: Path) -> None:
    run(
        ("git", "clone", "--quiet", "--shared", "--no-checkout", "--", str(source_repo), str(destination)),
        cwd=source_repo.parent,
    )
    run(("git", "checkout", "--quiet", "--detach", commit), cwd=destination)


def selected_manifest(candidate: Path, projection: list[dict[str, str]]) -> tuple[bytes, list[dict[str, str]], str]:
    rows: list[dict[str, str]] = []
    encoded_rows: list[bytes] = []
    for item in sorted(projection, key=lambda value: value["target_path"].encode("utf-8")):
        source_path = item["source_path"]
        target_path = item["target_path"]
        mode = item["mode"]
        content = (candidate / target_path).read_bytes()
        digest = sha256(content)
        rows.append({
            "source_path": source_path,
            "target_path": target_path,
            "mode": mode,
            "sha256": digest,
        })
        encoded_rows.append(
            source_path.encode("utf-8") + b"\0" + target_path.encode("utf-8")
            + b"\0" + mode.encode("ascii") + b"\0"
            + digest.encode("ascii") + b"\n"
        )
    manifest = b"".join(encoded_rows)
    return manifest, rows, sha256(manifest)


def materialise(source: Path, projection: list[dict[str, str]], candidate: Path) -> None:
    for item in sorted(projection, key=lambda value: value["target_path"].encode("utf-8")):
        if item.get("type") != "blob" or item.get("mode") not in {"100644", "100755"}:
            raise PreviewRefusal(f"selection contains a non-ordinary file: {item.get('path')}")
        source_relative = item["source_path"]
        target_relative = item["target_path"]
        source_path = source / source_relative
        if not source_path.is_file() or source_path.is_symlink():
            raise PreviewRefusal(f"selected source is not a regular file: {source_relative}")
        destination = candidate / target_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination)
        destination.chmod(0o755 if item["mode"] == "100755" else 0o644)


def write_target_manifest(candidate: Path, manifest: dict[str, Any]) -> bytes:
    """Replace the selected upstream authority with its target-native public view."""
    content = boundary.target_manifest_bytes(manifest)
    path = candidate / "native-boundary.json"
    if not path.is_file() or path.is_symlink():
        raise PreviewRefusal("materialised candidate is missing native-boundary.json")
    path.write_bytes(content)
    path.chmod(0o644)
    return content


def publication_projection(
    projection: list[dict[str, str]], mode: str
) -> list[dict[str, str]]:
    if mode not in {PRIVATE_PREVIEW, PUBLIC_RELEASE}:
        raise PreviewRefusal(f"unsupported publication mode: {mode}")
    paths = {item.get("target_path") for item in projection}
    missing = sorted(PUBLIC_RELEASE_REQUIRED_PATHS - paths)
    if missing:
        raise PreviewRefusal(
            "publication projection is missing required files: " + ", ".join(missing)
        )
    return list(projection)


def manifest_exclusion_findings(
    candidate: Path, manifest: dict[str, Any]
) -> list[dict[str, str]]:
    selectors = [
        (excluded["id"], boundary.Selector(raw["kind"], raw["path"]))
        for excluded in manifest["exclusions"]
        for raw in excluded["paths"]
    ]
    findings: list[dict[str, str]] = []
    for path in candidate_paths(candidate):
        for exclusion, selector in selectors:
            if selector.matches(path):
                findings.append({"path": path, "exclusion": exclusion})
        if "held" in PurePosixPath(path).parts and not any(
            finding["path"] == path for finding in findings
        ):
            findings.append({"path": path, "exclusion": "held-path"})
    return findings


def validate_release_envelope(candidate: Path) -> None:
    paths = set(candidate_paths(candidate))
    generated = sorted(
        path for path in paths
        if (
            path in FORBIDDEN_GENERATED_PATHS
            or path.startswith(".release/")
        )
    )
    if generated:
        raise PreviewRefusal(
            "candidate contains files outside the approved publication envelope: "
            + ", ".join(generated)
        )


def validate_license_files(candidate: Path) -> dict[str, Any]:
    license_path = candidate / "LICENSE.md"
    if not license_path.is_file():
        raise PreviewRefusal("preview is missing LICENSE.md")
    if sha256(license_path.read_bytes()) != EXPECTED_LICENSE_SHA256:
        raise PreviewRefusal("LICENSE.md is not the expected AGPL-3.0-only licence")

    readme_path = candidate / "README.md"
    if not readme_path.is_file():
        raise PreviewRefusal("preview is missing README.md")
    readme = readme_path.read_text(encoding="utf-8")
    readme_markers = (
        "GNU Affero General Public License v3.0 only",
        "AGPL-3.0-only",
        "LICENSE.md",
    )
    if any(marker not in readme for marker in readme_markers):
        raise PreviewRefusal("README.md does not state the AGPL licence boundary")

    return {
        "passed": True,
        "license_path": "LICENSE.md",
        "license_sha256": sha256(license_path.read_bytes()),
        "readme_path": "README.md",
        "readme_sha256": sha256(readme_path.read_bytes()),
    }


def validate_preview_files(candidate: Path) -> dict[str, Any]:
    validate_release_envelope(candidate)
    return validate_license_files(candidate)


def validate_public_release_files(candidate: Path) -> dict[str, Any]:
    validate_release_envelope(candidate)
    paths = set(candidate_paths(candidate))
    missing = sorted(PUBLIC_RELEASE_REQUIRED_PATHS - paths)
    if missing:
        raise PreviewRefusal(
            "public-release candidate is missing required files: " + ", ".join(missing)
        )
    for relative, markers in PUBLIC_CONTENT_MARKERS.items():
        content = (candidate / relative).read_bytes()
        if sha256(content) != EXPECTED_PUBLIC_FILE_SHA256[relative]:
            raise PreviewRefusal(
                f"public-release content differs from the exact approved bytes: {relative}"
            )
        normalized = " ".join(content.decode("utf-8").split())
        absent = [marker for marker in markers if marker not in normalized]
        if absent:
            raise PreviewRefusal(
                f"public-release content policy is incomplete in {relative}: "
                + ", ".join(absent)
            )
    for relative, phrases in PRIVATE_PREVIEW_ONLY_PHRASES.items():
        content = (candidate / relative).read_text(encoding="utf-8")
        remaining = [phrase for phrase in phrases if phrase in content]
        if remaining:
            raise PreviewRefusal(
                f"public-release candidate retains private-preview-only framing in {relative}: "
                + ", ".join(remaining)
            )
    validation = validate_license_files(candidate)
    validation["contributing_sha256"] = sha256(
        (candidate / "CONTRIBUTING.md").read_bytes()
    )
    validation["release_notes_sha256"] = sha256(
        (candidate / "RELEASE_NOTES.md").read_bytes()
    )
    return validation


def replace_empty_destination(staging: Path, destination: Path, label: str) -> None:
    assert_empty_destination(destination, label)
    if destination.exists():
        destination.rmdir()
    os.replace(staging, destination)


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    for raw_path, label in (
        (args.output_dir, "candidate"),
        (args.evidence_dir, "evidence"),
    ):
        if raw_path.is_symlink():
            raise PreviewRefusal(f"{label} destination must not be a symlink")
    source_repo = args.source_repo.resolve()
    output = args.output_dir.resolve()
    evidence = args.evidence_dir.resolve()
    if not source_repo.is_dir():
        raise PreviewRefusal(f"source repository does not exist: {source_repo}")
    validate_destinations(source_repo, output, evidence)
    source_commit, source_tree, source_commit_date = exact_source(
        source_repo, args.source_ref
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    output_staging = Path(tempfile.mkdtemp(prefix=".native-preview-candidate-", dir=output.parent))
    evidence_staging = Path(tempfile.mkdtemp(prefix=".native-preview-evidence-", dir=evidence.parent))
    try:
        with tempfile.TemporaryDirectory(prefix="native-preview-source-") as source_name:
            source = Path(source_name) / "source"
            clone_exact_source(source_repo, source_commit, source)
            boundary_path = source / "native-ce-boundary.json"
            manifest_bytes = boundary_path.read_bytes()
            try:
                manifest = boundary.load_manifest(boundary_path, mode="upstream")
                upstream_projection = boundary.validate_repository(source, manifest, "upstream")
            except boundary.BoundaryError as exc:
                raise PreviewRefusal(f"upstream source-boundary validation failed: {exc}") from exc

            implementation = validation_implementation(source, args.mode)
            projection = publication_projection(upstream_projection, args.mode)
            materialise(source, projection, output_staging)
            public_manifest_bytes = write_target_manifest(output_staging, manifest)
            public_candidate_validation = (
                validate_public_candidate(output_staging)
                if args.mode == PUBLIC_RELEASE
                else None
            )
            if (
                public_candidate_validation is not None
                and public_candidate_validation["checker_sha256"]
                != implementation["public_candidate_checker_sha256"]
            ):
                raise PreviewRefusal(
                    "public candidate checker differs from the validated source identity"
                )
            held_findings = manifest_exclusion_findings(output_staging, manifest)
            if held_findings:
                paths = ", ".join(sorted(item["path"] for item in held_findings))
                raise PreviewRefusal(f"preview contains manifest-excluded or held paths: {paths}")
            credential_findings = scan_credentials(output_staging)
            if credential_findings:
                paths = ", ".join(sorted(item["path"] for item in credential_findings))
                raise PreviewRefusal(f"credential scan found redacted candidates in: {paths}")
            file_validation = (
                validate_public_release_files(output_staging)
                if args.mode == PUBLIC_RELEASE
                else validate_preview_files(output_staging)
            )

            try:
                target_manifest = boundary.load_manifest(
                    output_staging / "native-boundary.json", mode="target"
                )
                target_projection = boundary.validate_repository(
                    output_staging, target_manifest, "target"
                )
            except boundary.BoundaryError as exc:
                raise PreviewRefusal(f"candidate target-mode validation failed: {exc}") from exc

            selected_bytes, selected_rows, selected_digest = selected_manifest(
                output_staging, projection
            )
            projection_identity_fields = (
                "target_path", "mode", "type", "component", "sha256"
            )
            target_identities = sorted([
                tuple(item.get(field) for field in projection_identity_fields)
                for item in target_projection
            ], key=lambda item: str(item[0]).encode("utf-8"))
            expected_target_identities = sorted([
                (
                    item["target_path"],
                    item["mode"],
                    item["type"],
                    item["component"],
                    (
                        sha256(public_manifest_bytes)
                        if item["target_path"] == "native-boundary.json"
                        else item["sha256"]
                    ),
                )
                for item in projection
            ], key=lambda item: item[0].encode("utf-8"))
            if target_identities != expected_target_identities:
                raise PreviewRefusal("target-mode projection differs from the upstream selection")

            result_format = PUBLIC_FORMAT if args.mode == PUBLIC_RELEASE else FORMAT
            selection_record = {
                "format": result_format,
                "source_commit": source_commit,
                "source_commit_date": source_commit_date,
                "source_tree": source_tree,
                "boundary": {
                    "format": manifest["format"],
                    "manifest_version": manifest["manifest_version"],
                    "sha256": sha256(manifest_bytes),
                    "target_sha256": sha256(public_manifest_bytes),
                },
                "selected_source_sha256": selected_digest,
                "files": selected_rows,
            }
            if args.mode == PUBLIC_RELEASE:
                selection_record["mode"] = PUBLIC_RELEASE
            result = {
                "format": result_format,
                "passed": True,
                "source_commit": source_commit,
                "source_commit_date": source_commit_date,
                "source_tree": source_tree,
                "boundary": selection_record["boundary"],
                "validation_implementation": implementation,
                "selection": {
                    "file_count": len(selected_rows),
                    "selected_source_sha256": selected_digest,
                },
                "validation": {
                    "upstream_mode": {"passed": True},
                    "target_mode": {"passed": True},
                    "history_free_tree": {
                        "passed": not (output_staging / ".git").exists(),
                        "detail": "candidate is a plain tree with no Git metadata",
                    },
                },
                "scans": {
                    "credentials": {
                        "passed": True,
                        "finding_count": 0,
                        "scanner": SCANNER,
                    },
                    "manifest_exclusions_and_held_paths": {
                        "passed": True,
                        "finding_count": 0,
                    },
                    "preview_files": file_validation,
                },
            }
            if args.mode == PUBLIC_RELEASE:
                result["mode"] = PUBLIC_RELEASE
                result["validation"]["public_candidate"] = public_candidate_validation
            (evidence_staging / "selected-source.manifest").write_bytes(selected_bytes)
            (evidence_staging / "selected-source.json").write_bytes(json_bytes(selection_record))
            (evidence_staging / "preview-evidence.json").write_bytes(json_bytes(result))

        replace_empty_destination(evidence_staging, evidence, "evidence")
        try:
            replace_empty_destination(output_staging, output, "candidate")
        except (OSError, PreviewRefusal):
            shutil.rmtree(evidence, ignore_errors=True)
            raise
        return result
    finally:
        if output_staging.exists():
            shutil.rmtree(output_staging, ignore_errors=True)
        if evidence_staging.exists():
            shutil.rmtree(evidence_staging, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=(PRIVATE_PREVIEW, PUBLIC_RELEASE),
        default=PRIVATE_PREVIEW,
    )
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--source-ref", required=True, help="exact full source commit ID")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = prepare(build_parser().parse_args(argv))
    except (PreviewRefusal, OSError, UnicodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": "prepared",
        "source_commit": result["source_commit"],
        "selected_source_sha256": result["selection"]["selected_source_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
