#!/usr/bin/env python3
"""Focused fixtures for local publication preparation."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("prepare_private_preview.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("prepare_private_preview", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
preview = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preview
SPEC.loader.exec_module(preview)


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ("git", *args), cwd=repo, text=True, check=True,
        env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


REPOSITORY_ROOT = MODULE_PATH.parents[2]
PUBLICATION_ROOT = (
    REPOSITORY_ROOT / "publication/root"
    if (REPOSITORY_ROOT / "publication/root").is_dir()
    else REPOSITORY_ROOT
)
PUBLICATION_DOCS = (
    REPOSITORY_ROOT / "publication/docs"
    if (REPOSITORY_ROOT / "publication/docs").is_dir()
    else REPOSITORY_ROOT / "docs"
)
FSL = (PUBLICATION_ROOT / "LICENSE.md").read_text(encoding="utf-8")
README = """# Native

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).
See LICENSE.md.
"""
PRIVATE_README = """# Native

> **Private early preview.** This repository is an incomplete, generated look
> at Native's intended open-source release. Release tidy-up and audit are
> still in progress; interfaces and documentation may change. Feedback is
> welcome, but this snapshot is not the final public release.

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).
See LICENSE.md.

- **Building or running checks:** [`BUILDING.md`](BUILDING.md) gives the
  preview-specific edit loop, optional-feature boundaries, and runtime checks.

`"name":"native-preview","version"`

```sh
cargo run --bin mcp-stdio -- /tmp/native-preview.db
```

Remove `/tmp/native-preview.db` when you are finished.
"""
PRIVATE_BUILDING = """# Building the private preview

This generated preview contains the portable Native node and its selected test
and documentation surface. It does not contain upstream CI, release operations,
the commercial Workbench, or hosted-service composition.
"""
PRIVATE_DOCS_README = """# Native documentation

## Build and contribution guidance

- [`BUILDING.md`](../BUILDING.md) describes the preview-specific build and test
  loop and how to choose optional features.
- The root README gives the supported local entrypoints and license boundary.
- Contribution policy may differ between a private preview and a later public
  release. Do not infer that a missing contribution guide means contributions
  are accepted.
"""
CONTRIBUTING = (PUBLICATION_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
RELEASE_NOTES = (PUBLICATION_ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
PUBLIC_README = (PUBLICATION_ROOT / "README.md").read_text(encoding="utf-8")
PUBLIC_BUILDING = (PUBLICATION_ROOT / "BUILDING.md").read_text(encoding="utf-8")
PUBLIC_DOCS_README = (PUBLICATION_DOCS / "README.md").read_text(encoding="utf-8")


class PreviewPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="preview-preparer-test-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        git(self.repo, "init", "--initial-branch=main")
        git(self.repo, "config", "user.name", "test")
        git(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "README.md").write_text(README, encoding="utf-8")
        (self.repo / "LICENSE.md").write_text(FSL, encoding="utf-8")
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.repo / "ARCHITECTURE.md").write_text("# Architecture\n", encoding="utf-8")
        (self.repo / "BUILDING.md").write_text("# Building\n", encoding="utf-8")
        (self.repo / "CONTRIBUTING.md").write_text(CONTRIBUTING, encoding="utf-8")
        (self.repo / "RELEASE_NOTES.md").write_text(RELEASE_NOTES, encoding="utf-8")
        (self.repo / "docs").mkdir(exist_ok=True)
        (self.repo / "docs/README.md").write_text("# Documentation\n", encoding="utf-8")
        (self.repo / "native-ce-boundary.json").write_text("{}\n", encoding="utf-8")
        (self.repo / "tool.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (self.repo / "tool.sh").chmod(0o755)
        git(self.repo, "add", "-A")
        commit_env = os.environ.copy()
        commit_env.update({
            "GIT_AUTHOR_DATE": "2020-03-04T05:06:07-08:00",
            "GIT_COMMITTER_DATE": "2026-09-02T07:52:37+01:00",
        })
        git(self.repo, "commit", "-m", "fixture", env=commit_env)
        self.commit = git(self.repo, "rev-parse", "HEAD")
        self.output = self.root / "candidate"
        self.evidence = self.root / "evidence"
        self.manifest = {
            "format": preview.boundary.FORMAT,
            "manifest_version": 2,
            "exclusions": [{
                "id": "held-private",
                "paths": [{"kind": "tree", "path": "held"}],
            }],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def projection(self, extra: list[str] | None = None) -> list[dict[str, str]]:
        paths = [
            ".gitignore", "ARCHITECTURE.md", "BUILDING.md", "CONTRIBUTING.md",
            "LICENSE.md", "README.md", "RELEASE_NOTES.md", "docs/README.md",
            "native-ce-boundary.json", "tool.sh",
        ]
        paths.extend(extra or [])
        rows = []
        for path in sorted(paths):
            target = "native-boundary.json" if path == "native-ce-boundary.json" else path
            rows.append({
                "source_path": path,
                "target_path": target,
                "path": path,
                "component": "fixture",
                "mode": "100755" if path == "tool.sh" else "100644",
                "type": "blob",
            })
        return rows

    def args(self, mode: str = preview.PRIVATE_PREVIEW) -> object:
        arguments = [
            "--source-repo", str(self.repo),
            "--source-ref", self.commit,
            "--output-dir", str(self.output),
            "--evidence-dir", str(self.evidence),
        ]
        if mode != preview.PRIVATE_PREVIEW:
            arguments[0:0] = ["--mode", mode]
        return preview.build_parser().parse_args(arguments)

    def run_with_projection(
        self,
        projection: list[dict[str, str]],
        *,
        mode: str = preview.PRIVATE_PREVIEW,
        target_projection: list[dict[str, str]] | None = None,
        candidate_refusal: str | None = None,
        mutate_contributing: bool = False,
    ) -> dict:
        for item in projection:
            item.setdefault(
                "sha256",
                preview.sha256((self.repo / item["source_path"]).read_bytes()),
            )
        expected = preview.publication_projection(projection, mode)
        target_is_default = target_projection is None
        target = expected if target_projection is None else target_projection
        self.candidate_observations: list[dict[str, object]] = []
        validation_modes: list[str] = []

        def validate_repository(
            repository: Path, _manifest: dict[str, object], selected_mode: str
        ) -> list[dict[str, str]]:
            validation_modes.append(selected_mode)
            if selected_mode == "upstream":
                return projection
            rows = [dict(item) for item in target]
            for item in rows:
                item["source_path"] = item["target_path"]
                if target_is_default or "sha256" not in item:
                    item["sha256"] = preview.sha256(
                        (repository / item["target_path"]).read_bytes()
                    )
            return rows

        def validate_candidate(candidate: Path) -> dict[str, object]:
            readme = (candidate / "README.md").read_text(encoding="utf-8")
            self.candidate_observations.append({
                "public_banner": "**Public source snapshot.**" in readme,
                "contributing": (candidate / "CONTRIBUTING.md").is_file(),
                "release_notes": (candidate / "RELEASE_NOTES.md").is_file(),
            })
            if candidate_refusal is not None:
                raise preview.PreviewRefusal(candidate_refusal)
            if mutate_contributing:
                with (candidate / "CONTRIBUTING.md").open("a", encoding="utf-8") as policy:
                    policy.write("\nExternal changes are accepted.\n")
            return {"passed": True, "checker_sha256": "c" * 64}

        with mock.patch.object(preview.boundary, "load_manifest", return_value=self.manifest), \
             mock.patch.object(
                 preview.boundary, "validate_repository",
                 side_effect=validate_repository,
             ) as validate, mock.patch.object(
                 preview.boundary, "target_manifest_bytes",
                 return_value=b'{"fixture":"target-native"}\n',
             ), mock.patch.object(
                 preview,
                 "validation_implementation",
                 side_effect=lambda _source, selected_mode: {
                     "preparer_sha256": "a" * 64,
                     "boundary_validator_sha256": "b" * 64,
                     "credential_scanner": preview.SCANNER,
                     **(
                         {"public_candidate_checker_sha256": "c" * 64}
                         if selected_mode == preview.PUBLIC_RELEASE
                         else {}
                     ),
                 },
             ), mock.patch.object(
                 preview, "validate_public_candidate", side_effect=validate_candidate,
             ) as candidate_check:
            result = preview.prepare(self.args(mode))
        self.candidate_check_calls = candidate_check.call_count
        self.assertEqual(validation_modes, ["upstream", "target"])
        return result

    def add_public_files(self) -> list[str]:
        (self.repo / "README.md").write_text(PUBLIC_README, encoding="utf-8")
        (self.repo / "BUILDING.md").write_text(PUBLIC_BUILDING, encoding="utf-8")
        (self.repo / "CONTRIBUTING.md").write_text(CONTRIBUTING, encoding="utf-8")
        (self.repo / "RELEASE_NOTES.md").write_text(RELEASE_NOTES, encoding="utf-8")
        (self.repo / "docs").mkdir(exist_ok=True)
        (self.repo / "docs/README.md").write_text(
            PUBLIC_DOCS_README, encoding="utf-8"
        )
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "public fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        return []

    def test_persists_exact_candidate_modes_and_external_evidence(self) -> None:
        result = self.run_with_projection(self.projection())
        self.assertTrue(result["passed"])
        self.assertEqual((self.output / "README.md").read_text(), README)
        self.assertTrue(os.stat(self.output / "tool.sh").st_mode & 0o111)
        self.assertFalse((self.output / ".release").exists())
        self.assertFalse((self.output / "LICENSE").exists())
        evidence = json.loads((self.evidence / "preview-evidence.json").read_text())
        selection = json.loads((self.evidence / "selected-source.json").read_text())
        self.assertEqual(evidence["source_commit"], self.commit)
        source_commit_date = git(self.repo, "show", "-s", "--format=%cI", self.commit)
        self.assertNotEqual(
            source_commit_date,
            git(self.repo, "show", "-s", "--format=%aI", self.commit),
        )
        self.assertEqual(evidence["source_commit_date"], source_commit_date)
        self.assertEqual(selection["source_commit_date"], source_commit_date)
        self.assertEqual(evidence["source_tree"], git(self.repo, "show", "-s", "--format=%T", self.commit))
        self.assertTrue(evidence["validation"]["history_free_tree"]["passed"])
        self.assertEqual(selection["boundary"]["manifest_version"], 2)
        self.assertEqual(
            selection["boundary"]["target_sha256"],
            preview.sha256(b'{"fixture":"target-native"}\n'),
        )
        self.assertEqual(
            (self.output / "native-boundary.json").read_bytes(),
            b'{"fixture":"target-native"}\n',
        )
        self.assertEqual(selection["files"][0]["target_path"], ".gitignore")
        selected_manifest = (self.evidence / "selected-source.manifest").read_bytes()
        self.assertEqual(
            selection["selected_source_sha256"], preview.sha256(selected_manifest)
        )

    def test_timestamp_validation_rejects_noncanonical_or_impossible_values(self) -> None:
        self.assertTrue(preview.valid_rfc3339_timestamp("2026-09-02T07:52:37+01:00"))
        self.assertTrue(preview.valid_rfc3339_timestamp("2026-09-02T06:52:37Z"))
        for value in (
            "2026-09-02T07:52:37",
            "2026-09-02T07:52:37.1+01:00",
            "2026-02-31T07:52:37+01:00",
            "2026-09-02T07:52:37+99:99",
        ):
            with self.subTest(value=value):
                self.assertFalse(preview.valid_rfc3339_timestamp(value))

    def test_mapped_readme_is_copied_byte_for_byte(self) -> None:
        publication = self.repo / "publication/root/README.md"
        publication.parent.mkdir(parents=True)
        publication.write_bytes(PUBLIC_README.encode("utf-8"))
        git(self.repo, "add", "publication/root/README.md")
        git(self.repo, "commit", "-m", "mapped public readme")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        projection = self.projection()
        readme = next(item for item in projection if item["target_path"] == "README.md")
        readme["source_path"] = "publication/root/README.md"
        readme["path"] = "publication/root/README.md"
        self.run_with_projection(projection)
        self.assertEqual(self.output.joinpath("README.md").read_bytes(), publication.read_bytes())

    def test_private_mode_reflects_complete_wrapper_and_preserves_contract(self) -> None:
        extras = self.add_public_files()
        result = self.run_with_projection(self.projection(extras))
        self.assertEqual(result["format"], preview.FORMAT)
        self.assertNotIn("mode", result)
        self.assertNotIn("public_candidate", result["validation"])
        self.assertNotIn(
            "public_candidate_checker_sha256", result["validation_implementation"]
        )
        self.assertTrue((self.output / "CONTRIBUTING.md").exists())
        self.assertTrue((self.output / "RELEASE_NOTES.md").exists())
        selection = json.loads((self.evidence / "selected-source.json").read_text())
        self.assertEqual(selection["format"], preview.FORMAT)
        self.assertNotIn("mode", selection)
        self.assertEqual(self.candidate_check_calls, 0)
        self.assertIn(
            "CONTRIBUTING.md", {row["target_path"] for row in selection["files"]}
        )

    def test_public_mode_copies_complete_wrapper_verbatim(self) -> None:
        extras = self.add_public_files()
        result = self.run_with_projection(
            self.projection(extras), mode=preview.PUBLIC_RELEASE
        )
        self.assertEqual(result["format"], preview.PUBLIC_FORMAT)
        self.assertEqual(result["mode"], preview.PUBLIC_RELEASE)
        self.assertTrue(result["validation"]["public_candidate"]["passed"])
        self.assertEqual(
            result["validation"]["public_candidate"]["checker_sha256"],
            result["validation_implementation"]["public_candidate_checker_sha256"],
        )
        self.assertEqual(self.candidate_check_calls, 1)
        self.assertEqual(
            self.candidate_observations,
            [{"public_banner": True, "contributing": True, "release_notes": True}],
        )
        self.assertEqual((self.output / "CONTRIBUTING.md").read_text(), CONTRIBUTING)
        self.assertEqual((self.output / "RELEASE_NOTES.md").read_text(), RELEASE_NOTES)
        self.assertIn(
            "**Public source snapshot.**",
            (self.output / "README.md").read_text(),
        )
        public_readme = (self.output / "README.md").read_text()
        self.assertIn("[snapshot notes](RELEASE_NOTES.md)", public_readme)
        self.assertIn("[contribution policy](CONTRIBUTING.md)", public_readme)
        self.assertNotIn("Private early preview", public_readme)
        self.assertNotIn("native-preview", public_readme)
        self.assertIn('"name":"native-source","version"', public_readme)
        self.assertEqual(public_readme.count("/tmp/native-source.db"), 2)
        self.assertIn(
            "# Exploring the public source snapshot",
            (self.output / "BUILDING.md").read_text(),
        )
        docs = (self.output / "docs/README.md").read_text()
        self.assertIn("[`CONTRIBUTING.md`](../CONTRIBUTING.md)", docs)
        self.assertNotIn("private preview", docs)
        selection = json.loads((self.evidence / "selected-source.json").read_text())
        evidence = json.loads((self.evidence / "preview-evidence.json").read_text())
        self.assertEqual(selection["mode"], preview.PUBLIC_RELEASE)
        self.assertEqual(evidence["mode"], preview.PUBLIC_RELEASE)
        selected = {row["target_path"] for row in selection["files"]}
        self.assertTrue(preview.PUBLIC_RELEASE_REQUIRED_PATHS <= selected)

    def test_public_candidate_refusal_publishes_neither_tree_nor_evidence(self) -> None:
        extras = self.add_public_files()
        with self.assertRaisesRegex(preview.PreviewRefusal, "broken final candidate"):
            self.run_with_projection(
                self.projection(extras),
                mode=preview.PUBLIC_RELEASE,
                candidate_refusal="broken final candidate",
            )
        self.assertFalse(self.output.exists())
        self.assertFalse(self.evidence.exists())

    def test_public_candidate_side_effect_is_revalidated_before_publication(self) -> None:
        extras = self.add_public_files()
        with self.assertRaisesRegex(
            preview.PreviewRefusal,
            "differs from the exact approved bytes: CONTRIBUTING.md",
        ):
            self.run_with_projection(
                self.projection(extras),
                mode=preview.PUBLIC_RELEASE,
                mutate_contributing=True,
            )
        self.assertFalse(self.output.exists())
        self.assertFalse(self.evidence.exists())

    def test_public_mode_refuses_missing_or_private_framing(self) -> None:
        extras = self.add_public_files()
        (self.repo / "README.md").write_text(
            PUBLIC_README + "\nPrivate early preview.\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "drift framing")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(
            preview.PreviewRefusal, "retains private-preview-only framing in README.md"
        ):
            self.run_with_projection(
                self.projection(extras), mode=preview.PUBLIC_RELEASE
            )

        with self.assertRaisesRegex(
            preview.PreviewRefusal, "missing required files: RELEASE_NOTES.md"
        ):
            preview.publication_projection(
                [
                    item for item in self.projection(extras)
                    if item["target_path"] != "RELEASE_NOTES.md"
                ],
                preview.PUBLIC_RELEASE,
            )

    def test_public_mode_refuses_governance_and_release_note_policy_mutations(self) -> None:
        extras = self.add_public_files()
        (self.repo / "CONTRIBUTING.md").write_text(
            CONTRIBUTING + "\nExternal contributions are accepted after all.\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "CONTRIBUTING.md")
        git(self.repo, "commit", "-m", "drift contribution route")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(
            preview.PreviewRefusal, "differs from the exact approved bytes: CONTRIBUTING.md"
        ):
            self.run_with_projection(
                self.projection(extras), mode=preview.PUBLIC_RELEASE
            )

        (self.repo / "CONTRIBUTING.md").write_text(CONTRIBUTING, encoding="utf-8")
        (self.repo / "RELEASE_NOTES.md").write_text(
            RELEASE_NOTES + "\nPrivate hosted composition is included in this release.\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "CONTRIBUTING.md", "RELEASE_NOTES.md")
        git(self.repo, "commit", "-m", "drift release boundary")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(
            preview.PreviewRefusal, "differs from the exact approved bytes: RELEASE_NOTES.md"
        ):
            self.run_with_projection(
                self.projection(extras), mode=preview.PUBLIC_RELEASE
            )

    def test_public_mode_refuses_residual_private_preview_framing(self) -> None:
        extras = self.add_public_files()
        with (self.repo / "docs/README.md").open("a", encoding="utf-8") as document:
            document.write("\nThis still describes a missing contribution guide.\n")
        git(self.repo, "add", "docs/README.md")
        git(self.repo, "commit", "-m", "retain private framing")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(
            preview.PreviewRefusal,
            "retains private-preview-only framing in docs/README.md",
        ):
            self.run_with_projection(
                self.projection(extras), mode=preview.PUBLIC_RELEASE
            )

    def test_requires_an_exact_full_commit(self) -> None:
        args = self.args()
        args.source_ref = "HEAD"
        with self.assertRaisesRegex(preview.PreviewRefusal, "exact full Git commit"):
            preview.prepare(args)

    def test_refuses_nonempty_destination(self) -> None:
        self.output.mkdir()
        (self.output / "owned.txt").write_text("keep\n")
        with self.assertRaisesRegex(preview.PreviewRefusal, "candidate destination is not empty"):
            preview.prepare(self.args())
        self.assertEqual((self.output / "owned.txt").read_text(), "keep\n")

        (self.output / "owned.txt").unlink()
        self.output.rmdir()
        self.evidence.mkdir()
        (self.evidence / "owned.txt").write_text("keep\n")
        with self.assertRaisesRegex(preview.PreviewRefusal, "evidence destination is not empty"):
            preview.prepare(self.args())
        self.assertEqual((self.evidence / "owned.txt").read_text(), "keep\n")

    def test_accepts_preexisting_empty_destinations(self) -> None:
        self.output.mkdir()
        self.evidence.mkdir()
        self.run_with_projection(self.projection())
        self.assertTrue((self.output / "README.md").is_file())
        self.assertTrue((self.evidence / "preview-evidence.json").is_file())

    def test_refuses_manifest_exclusion_or_held_path(self) -> None:
        (self.repo / "held").mkdir()
        (self.repo / "held/private.rs").write_text("private\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "held")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(preview.PreviewRefusal, "manifest-excluded or held"):
            self.run_with_projection(self.projection(["held/private.rs"]))

    def test_refuses_redacted_credential_finding(self) -> None:
        # Construct the synthetic credential so this selected test file does not
        # itself contain token-shaped bytes that the preview scanner must reject.
        secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
        (self.repo / "secret.txt").write_text(secret)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "secret")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaises(preview.PreviewRefusal) as caught:
            self.run_with_projection(self.projection(["secret.txt"]))
        self.assertIn("secret.txt", str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))

    def test_detects_modern_github_token_and_encrypted_private_key(self) -> None:
        modern_token = "github" + "_pat_" + ("a" * 32)
        private_key = "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"
        (self.repo / "secret.txt").write_text(modern_token + "\n" + private_key)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "modern secrets")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaises(preview.PreviewRefusal) as caught:
            self.run_with_projection(self.projection(["secret.txt"]))
        self.assertIn("secret.txt", str(caught.exception))
        self.assertNotIn(modern_token, str(caught.exception))

    def test_refuses_release_generated_envelope(self) -> None:
        (self.repo / "LICENSE").write_text("AGPL fixture\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "wrong licence")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(preview.PreviewRefusal, "publication envelope"):
            self.run_with_projection(self.projection(["LICENSE"]))

    def test_refuses_modified_license_even_when_markers_remain(self) -> None:
        with (self.repo / "LICENSE.md").open("a", encoding="utf-8") as license_file:
            license_file.write("\nContradictory additional term.\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "alter licence")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(
            preview.PreviewRefusal, "not the expected AGPL-3.0-only"
        ):
            self.run_with_projection(self.projection())

    def test_refuses_target_projection_metadata_drift(self) -> None:
        upstream = self.projection()
        target = [dict(item) for item in upstream]
        target[-1]["mode"] = "100644"
        with self.assertRaisesRegex(
            preview.PreviewRefusal, "target-mode projection differs"
        ):
            self.run_with_projection(upstream, target_projection=target)

    def test_refuses_missing_target_and_digest_mismatch(self) -> None:
        upstream = self.projection()
        missing = [dict(item) for item in upstream[:-1]]
        with self.assertRaisesRegex(preview.PreviewRefusal, "target-mode projection differs"):
            self.run_with_projection(upstream, target_projection=missing)

        upstream = self.projection()
        target = [dict(item) for item in upstream]
        for item in upstream:
            item["sha256"] = "a" * 64
        for item in target:
            item["sha256"] = "a" * 64
        target[0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(preview.PreviewRefusal, "target-mode projection differs"):
            self.run_with_projection(upstream, target_projection=target)


if __name__ == "__main__":
    unittest.main()
