#!/usr/bin/env python3
"""Fixtures for the target-native clean-root compiler proof."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("compile_public_selection.py")
SPEC = importlib.util.spec_from_file_location("compile_public_selection", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class CompilePublicSelectionTests(unittest.TestCase):
    def test_materialise_copies_source_to_mapped_target_verbatim(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            target = root / "target"
            (source / "publication/root").mkdir(parents=True)
            data = b"# Public Native\n"
            (source / "publication/root/README.md").write_bytes(data)
            written = proof.materialise(source, [{
                "source_path": "publication/root/README.md",
                "target_path": "README.md",
                "mode": "100644",
                "type": "blob",
            }], target)
            self.assertEqual(written, ["README.md"])
            self.assertEqual((target / "README.md").read_bytes(), data)
            self.assertFalse((target / "publication/root/README.md").exists())

    def test_materialised_boundary_is_replaced_with_target_native_manifest(self) -> None:
        upstream = proof.boundary.load_manifest(
            SCRIPT.parents[2] / "native-ce-boundary.json", mode="upstream"
        )
        with tempfile.TemporaryDirectory() as raw:
            tree = Path(raw)
            path = tree / "native-boundary.json"
            path.write_text("private upstream authority\n", encoding="utf-8")
            proof.write_target_manifest(tree, upstream)
            public = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(public["exclusions"], [])
            self.assertTrue(all("reason" not in row for row in public["components"]))
            self.assertNotIn("native-ce-boundary.json", path.read_text(encoding="utf-8"))

    def test_missing_path_dependency_is_not_healed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree = root / "tree"
            tree.mkdir()
            (tree / "src").mkdir()
            (tree / "src/lib.rs").write_text("pub fn selected() {}\n", encoding="utf-8")
            (tree / "Cargo.toml").write_text(
                """[package]
name = "selected-root"
version = "0.0.0"
edition = "2021"

[dependencies]
held-dependency = { path = "held/missing" }
""",
                encoding="utf-8",
            )
            result = proof.run_cargo(tree, root / "target", [])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("held/missing", result.stderr)
            self.assertFalse((tree / "held/missing").exists())

    def test_transitional_manifest_and_stub_flags_are_rejected(self) -> None:
        for flag in ("--synthesize-manifest", "--stub-held-modules", "--selection"):
            result = subprocess.run(
                [str(SCRIPT), flag], capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unrecognized arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
