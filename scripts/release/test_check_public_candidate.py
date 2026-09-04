#!/usr/bin/env python3
"""Fixtures for the materialised public-candidate checks."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_public_candidate.py")
SPEC = importlib.util.spec_from_file_location("check_public_candidate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
candidate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = candidate
SPEC.loader.exec_module(candidate)


class PublicCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="public-candidate-fixture-")
        self.root = Path(self.temporary.name)
        (self.root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.98.0"\nprofile = "minimal"\n', encoding="utf-8"
        )
        (self.root / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.0.0"\n', encoding="utf-8"
        )
        (self.root / "README.md").write_text("[Cargo](Cargo.toml)\n", encoding="utf-8")
        self.metadata = {
            "workspace_members": ["fixture 0.0.0"],
            "packages": [
                {
                    "id": "fixture 0.0.0",
                    "manifest_path": str(self.root / "Cargo.toml"),
                    "repository": candidate.PUBLIC_REPOSITORY,
                    "rust_version": candidate.RUST_VERSION,
                }
            ],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_candidate_passes(self) -> None:
        candidate.check_toolchain(self.root)
        candidate.check_markdown_links(self.root)
        candidate.check_runnable_guidance(self.root)
        candidate.check_cargo_metadata(self.root, self.metadata)

    def test_missing_link_and_private_command_fail(self) -> None:
        (self.root / "README.md").write_text(
            "[missing](docs/missing.md)\n\n```sh\ncargo test --manifest-path held/Cargo.toml\n```\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(candidate.CandidateError, "missing internal link"):
            candidate.check_markdown_links(self.root)
        with self.assertRaisesRegex(candidate.CandidateError, "held path"):
            candidate.check_runnable_guidance(self.root)

    def test_external_fragment_and_code_example_links_are_not_local_files(self) -> None:
        (self.root / "README.md").write_text(
            "[external](https://example.com/path)\n"
            "[fragment](#heading)\n"
            "`[inline example](missing-inline.md)`\n"
            "```md\n[fenced example](missing-fenced.md)\n```\n",
            encoding="utf-8",
        )
        candidate.check_markdown_links(self.root)

    def test_internal_link_cannot_escape_candidate(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.md"
        outside.write_text("outside\n", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        (self.root / "README.md").write_text(
            f"[outside](../{outside.name})\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(candidate.CandidateError, "escapes candidate"):
            candidate.check_markdown_links(self.root)

    def test_reference_link_destination_must_exist(self) -> None:
        (self.root / "README.md").write_text(
            "Read the [guide][guide].\n\n[guide]: docs/missing.md\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(candidate.CandidateError, "missing internal link"):
            candidate.check_markdown_links(self.root)

    def test_toolchain_and_metadata_drift_fail(self) -> None:
        (self.root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "stable"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(candidate.CandidateError, "1.98.0"):
            candidate.check_toolchain(self.root)

        self.metadata["packages"][0]["repository"] = "https://github.com/withnative/native-ce"
        with self.assertRaisesRegex(candidate.CandidateError, "repository"):
            candidate.check_cargo_metadata(self.root, self.metadata)

    def test_metadata_command_is_locked_and_dependency_free(self) -> None:
        cargo = self.root / "fake-cargo"
        arguments = self.root / "arguments.json"
        cargo.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            f"pathlib.Path({str(arguments)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            f"print({json.dumps(self.metadata)!r})\n",
            encoding="utf-8",
        )
        cargo.chmod(0o755)
        metadata = candidate.cargo_metadata(self.root, str(cargo))
        self.assertEqual(metadata, self.metadata)
        self.assertEqual(
            json.loads(arguments.read_text(encoding="utf-8")),
            ["metadata", "--locked", "--no-deps", "--format-version", "1"],
        )

    def test_non_workspace_vendor_metadata_is_outside_public_package_policy(self) -> None:
        self.metadata["packages"].append(
            {
                "id": "vendored 12.0.1",
                "manifest_path": str(self.root / "vendor/swc/Cargo.toml"),
                "repository": "https://github.com/swc-project/swc",
                "rust_version": "1.82",
            }
        )
        candidate.check_cargo_metadata(self.root, self.metadata)


if __name__ == "__main__":
    unittest.main()
