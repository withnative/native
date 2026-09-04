#!/usr/bin/env python3
"""Mutation and repository fixtures for the v2 source boundary."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IS_UPSTREAM = (ROOT / "native-ce-boundary.json").is_file()
BOUNDARY_PATH = ROOT / ("native-ce-boundary.json" if IS_UPSTREAM else "native-boundary.json")
MODULE_PATH = Path(__file__).with_name("validate_source_boundary.py")
SPEC = importlib.util.spec_from_file_location("source_boundary", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
boundary = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = boundary
SPEC.loader.exec_module(boundary)


def debt_digest(manifest: dict[str, object]) -> str:
    return hashlib.sha256(boundary.canonical_debt_bytes(manifest["transition_debt"])).hexdigest()


def retired_debt_fixture() -> dict[str, str]:
    """A structurally valid historical edge used only for rejection fixtures."""
    return {
        "source_component": "tier-1-node",
        "target_component": "operated-evidence",
        "kind": "cargo-workspace-member",
        "source_path": "Cargo.toml",
        "target_path": "held/contracts/schema-admission-contract/Cargo.toml",
        "evidence": "retired workspace edge",
        "successor_task": "b27c449",
        "reason": "Mutation fixture proving that the frozen debt set remains empty.",
    }


def git(repo: Path, *args: str) -> None:
    subprocess.run(("git", *args), cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class SourceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = boundary.load_manifest(
            BOUNDARY_PATH, mode="upstream" if IS_UPSTREAM else "target"
        )

    def changed(self) -> dict[str, object]:
        return copy.deepcopy(self.manifest)

    @unittest.skipUnless(IS_UPSTREAM, "requires the private upstream Git checkout")
    def test_checked_manifest_validates_and_projects_deterministically(self) -> None:
        self.assertFalse((ROOT / "LICENSE.md").exists())
        first = boundary.validate_repository(ROOT, self.changed(), "upstream")
        inventory = boundary.upstream_inventory(ROOT)
        second = boundary.project_selection(self.changed(), reversed(inventory))
        self.assertEqual(
            [{key: row[key] for key in row if key != "sha256"} for row in first], second
        )
        self.assertEqual(first, sorted(first, key=lambda row: row["target_path"].encode("utf-8")))
        boundary_row = next(row for row in first if row["source_path"] == "native-ce-boundary.json")
        self.assertEqual(boundary_row["target_path"], "native-boundary.json")
        self.assertEqual(boundary_row["mode"], "100644")
        self.assertRegex(boundary_row["sha256"], r"^[0-9a-f]{64}$")
        readme = next(row for row in first if row["target_path"] == "README.md")
        self.assertEqual(readme["source_path"], "publication/root/README.md")
        self.assertFalse(any(row["path"].startswith("docs/evals/") for row in first))
        self.assertFalse(any(row["path"] in {"Dockerfile", "docker-entrypoint.sh"} for row in first))

    @unittest.skipUnless(IS_UPSTREAM, "compares private and publication wrapper inputs")
    def test_cold_roots_describe_distinct_repository_perspectives(self) -> None:
        upstream = (ROOT / "README.md").read_text(encoding="utf-8")
        public = (ROOT / "publication/root/README.md").read_text(encoding="utf-8")
        upstream_ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        public_ignore = (ROOT / "publication/root/.gitignore").read_text(encoding="utf-8")
        for marker in (
            "withnative/native-ce", "complete private development upstream", "public-core",
            "Held hosting", "Workbench", "web/workbench", "release/README.md",
            "AGENTS.md", "private-maintainer-operations.md", "native.source-boundary/v2",
        ):
            self.assertIn(marker, upstream)
        self.assertIn("withnative/native", public)
        self.assertIn("Public source snapshot", public)
        for upstream_only in ("complete private development upstream", "Held hosting", "AGENTS.md"):
            self.assertNotIn(upstream_only, public)
        for private_path in ("held/", "web/workbench", ".claude", "scripts/wordlist"):
            self.assertNotIn(private_path, public_ignore)
        self.assertIn("held/", upstream_ignore)
        self.assertIn("web/workbench", upstream_ignore)

    @unittest.skipUnless(IS_UPSTREAM, "requires the private upstream Git checkout")
    def test_catalog_break_glass_runbook_is_held_from_projection(self) -> None:
        path = "held/hosting/runbooks/catalog-break-glass.md"
        inventory = boundary.upstream_inventory(ROOT)
        self.assertIn(path, {entry.path for entry in inventory})
        self.assertEqual(boundary.owner_of(self.manifest, path), ("hosted-control-plane", False))

        projection = boundary.validate_repository(ROOT, self.changed(), "upstream")
        self.assertNotIn(path, {entry["path"] for entry in projection})

    def test_unknown_fields_are_rejected_at_every_level(self) -> None:
        root = self.changed()
        root["surprise"] = True
        with self.assertRaises(boundary.BoundaryError):
            boundary._object(root, "manifest", boundary.ROOT_KEYS)

        mutations = []
        for location in ("component", "selector", "service", "debt"):
            manifest = self.changed()
            if location == "component":
                manifest["components"][0]["surprise"] = True
            elif location == "selector":
                manifest["components"][0]["paths"][0]["glob"] = "**"
            elif location == "service":
                manifest["components"][0]["runtime_services"][0]["surprise"] = True
            else:
                manifest["transition_debt"].append(retired_debt_fixture())
                manifest["transition_debt"][0]["temporary"] = True
                manifest["transition_debt_sha256"] = debt_digest(manifest)
            mutations.append((location, manifest))
        for location, manifest in mutations:
            with self.subTest(location=location), self.assertRaises(boundary.BoundaryError):
                boundary.validate_shape(manifest, mode="upstream")

    def test_direction_matrix_rejects_held_dependency_bypass(self) -> None:
        manifest = self.changed()
        manifest["components"][0]["permitted_dependencies"].append("hosted-control-plane")
        with self.assertRaisesRegex(boundary.BoundaryError, "direction"):
            boundary.validate_shape(manifest, mode="upstream")

    def test_overlapping_selected_and_forbidden_selectors_are_rejected(self) -> None:
        selected = self.changed()
        selected["components"][1]["paths"].append(copy.deepcopy(selected["components"][0]["paths"][0]))
        with self.assertRaisesRegex(boundary.BoundaryError, "selected selectors overlap"):
            boundary.validate_shape(selected, mode="upstream")
        forbidden = self.changed()
        forbidden["exclusions"][0]["paths"].append({"kind": "file", "path": "src/lib.rs"})
        with self.assertRaisesRegex(boundary.BoundaryError, "selected/forbidden selectors overlap"):
            boundary.validate_shape(forbidden, mode="upstream")

    def test_forbidden_and_undeclared_selections_are_rejected(self) -> None:
        with self.assertRaisesRegex(boundary.BoundaryError, "forbidden path selected"):
            boundary.validate_selected_paths(self.changed(), ["web/workbench/src/App.tsx"])
        with self.assertRaisesRegex(boundary.BoundaryError, "undeclared path selected"):
            boundary.validate_selected_paths(self.changed(), ["private/new-service.rs"])

    def test_mcp_apps_exception_and_deferred_execution_are_exact(self) -> None:
        for mutation in ("third", "command", "execution"):
            manifest = self.changed()
            apps = next(item for item in manifest["components"] if item["id"] == "mcp-apps")
            if mutation == "third":
                apps["generated_artifacts"].append(
                    {
                        "path": "web/mcp-apps/dist/extra.html",
                        "producer": "npm run build",
                        "drift_check": "npm run build",
                        "execution": "deferred:b27c449",
                    }
                )
            elif mutation == "command":
                apps["generated_artifacts"][0]["drift_check"] = "vite build"
            else:
                apps["generated_artifacts"][0]["execution"] = "executed-here"
            with self.subTest(mutation=mutation), self.assertRaises(boundary.BoundaryError):
                boundary.validate_shape(manifest, mode="upstream")

    def test_transition_debt_is_fingerprinted_and_mode_aware(self) -> None:
        stale = self.changed()
        stale["transition_debt"].append(retired_debt_fixture())
        with self.assertRaisesRegex(boundary.BoundaryError, "exact frozen debt set"):
            boundary.validate_shape(stale, mode="upstream")

        recomputed = self.changed()
        recomputed["transition_debt"].append(retired_debt_fixture())
        recomputed["transition_debt_sha256"] = debt_digest(recomputed)
        with self.assertRaisesRegex(boundary.BoundaryError, "frozen v2 upstream"):
            boundary.validate_shape(recomputed, mode="upstream")
        target_with_debt = self.target_fixture_manifest()
        target_debt = retired_debt_fixture()
        target_debt["target_component"] = "public-documentation"
        target_debt["target_path"] = "docs/placeholder"
        target_with_debt["transition_debt"].append(target_debt)
        target_with_debt["transition_debt_sha256"] = debt_digest(target_with_debt)
        with self.assertRaisesRegex(boundary.BoundaryError, "frozen v2 target"):
            boundary.validate_shape(target_with_debt, mode="target")

        target = self.target_fixture_manifest()
        boundary.validate_shape(target, mode="target")
        with self.assertRaisesRegex(boundary.BoundaryError, "must not disclose"):
            boundary.validate_shape(self.changed(), mode="target")

    @unittest.skipUnless(IS_UPSTREAM, "requires the private upstream manifest")
    def test_target_manifest_is_deterministic_and_contains_only_public_topology(self) -> None:
        first = boundary.target_manifest_bytes(self.changed())
        second = boundary.target_manifest_bytes(self.changed())
        self.assertEqual(first, second)
        target = json.loads(first)
        boundary.validate_shape(copy.deepcopy(target), mode="target")
        self.assertEqual(target["exclusions"], [])
        self.assertEqual(target["transition_debt"], [])
        for component in target["components"]:
            self.assertNotIn("reason", component)
            for selector in component["paths"]:
                self.assertEqual(set(selector), {"kind", "source"})
            for artifact in component["generated_artifacts"]:
                self.assertNotIn("execution", artifact)
        def string_values(value: object) -> set[str]:
            if isinstance(value, str):
                return {value}
            if isinstance(value, dict):
                return set().union(*(string_values(item) for item in value.values()))
            if isinstance(value, list):
                return set().union(*(string_values(item) for item in value))
            return set()

        upstream_only_values = {
            mapping.source
            for component in self.manifest["components"]
            for raw in component["paths"]
            for mapping in [boundary.parse_mapping(raw, "upstream mapping")]
            if mapping.source != mapping.target
        }
        for component in self.manifest["components"]:
            upstream_only_values.add(component["reason"])
            upstream_only_values.update(
                artifact["execution"]
                for artifact in component["generated_artifacts"]
            )
        for exclusion in self.manifest["exclusions"]:
            upstream_only_values.update((exclusion["id"], exclusion["reason"]))
            upstream_only_values.update(selector["path"] for selector in exclusion["paths"])
        self.assertTrue(upstream_only_values)
        public_values = string_values(target)
        for upstream_only in upstream_only_values:
            self.assertNotIn(upstream_only, public_values)
        selected_targets = {
            component["id"]: {
                (mapping.kind, mapping.target)
                for raw in component["paths"]
                for mapping in [boundary.parse_mapping(raw, "test mapping")]
            }
            for component in self.manifest["components"]
        }
        public_targets = {
            component["id"]: {
                (mapping.kind, mapping.source)
                for raw in component["paths"]
                for mapping in [boundary.parse_mapping(raw, "test target")]
            }
            for component in target["components"]
        }
        self.assertEqual(public_targets, selected_targets)
        upstream_by_id = {row["id"]: row for row in self.manifest["components"]}
        for component in target["components"]:
            upstream = upstream_by_id[component["id"]]
            for field in (
                "classification", "binaries", "features", "runtime_services",
                "maturity", "permitted_dependencies",
            ):
                self.assertEqual(component[field], upstream[field])

    def test_target_shape_rejects_upstream_only_fields(self) -> None:
        for mutation, pattern in (
            ("exclusion", "must not disclose"),
            ("reason", "unknown fields"),
            ("mapping", "only target-native paths"),
            ("execution", "unknown fields"),
        ):
            manifest = self.target_fixture_manifest()
            if mutation == "exclusion":
                manifest["exclusions"] = [{
                    "id": "private-shape",
                    "classification": "held-private",
                    "reason": "should not be public",
                    "paths": [{"kind": "tree", "path": "private"}],
                }]
            elif mutation == "reason":
                manifest["components"][0]["reason"] = "upstream-only prose"
            elif mutation == "mapping":
                manifest["components"][0]["paths"][0]["target"] = "Cargo.toml"
            else:
                apps = next(
                    row for row in manifest["components"] if row["id"] == "mcp-apps"
                )
                apps["generated_artifacts"][0]["execution"] = "upstream-task"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                boundary.BoundaryError, pattern
            ):
                boundary.validate_shape(manifest, mode="target")

    def test_runtime_binaries_features_and_entrypoints_are_enforced(self) -> None:
        for mutation in ("binary", "feature", "entrypoint"):
            manifest = self.changed()
            tier = manifest["components"][0]
            if mutation == "binary":
                tier["binaries"][0] = "serve"
                tier["runtime_services"][0]["id"] = "serve"
            elif mutation == "feature":
                tier["features"].append("not-a-cargo-feature")
            else:
                tier["runtime_services"][0]["entrypoint"] = "src/bin/serve.rs"
            with self.subTest(mutation=mutation), self.assertRaises(boundary.BoundaryError):
                boundary.validate_shape(manifest, mode="upstream")
                boundary.validate_declared_runtime(ROOT, manifest)

    def test_runtime_binary_may_be_owned_by_a_selected_workspace_member(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        member = root / "member"
        (member / "src/bin").mkdir(parents=True)
        (member / "src/lib.rs").write_text("pub fn safe() {}\n", encoding="utf-8")
        (member / "src/bin/relay.rs").write_text("fn main() {}\n", encoding="utf-8")
        (member / "Cargo.toml").write_text(
            '[package]\nname="member"\nversion="0.0.0"\nedition="2021"\n'
            '[[bin]]\nname="relay"\npath="src/bin/relay.rs"\n',
            encoding="utf-8",
        )
        (root / "Cargo.toml").write_text(
            '[package]\nname="fixture"\nversion="0.0.0"\nedition="2021"\n'
            '[workspace]\nmembers=["member"]\n[features]\ndefault=[]\nfederation=[]\n',
            encoding="utf-8",
        )
        manifest = self.fixture_manifest()
        tier = next(item for item in manifest["components"] if item["id"] == "tier-2-wire")
        tier["paths"].append({"kind": "tree", "path": "member"})
        tier["binaries"] = ["relay"]
        tier["features"] = ["federation"]
        tier["runtime_services"] = [
            {
                "id": "relay",
                "kind": "binary",
                "entrypoint": "member/src/bin/relay.rs",
                "support": "reference",
            }
        ]
        git(root, "add", ".")
        try:
            boundary.validate_declared_runtime(root, manifest)
            (member / "Cargo.toml").write_text(
                '[package]\nname="member"\nversion="0.0.0"\nedition="2021"\n'
                '[[bin]]\nname="relay"\npath="src/lib.rs"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(boundary.BoundaryError, "selected Cargo"):
                boundary.validate_declared_runtime(root, manifest)
        finally:
            temporary.cleanup()

    def fixture_manifest(self) -> dict[str, object]:
        manifest = self.changed()
        paths = {
            "tier-1-node": [
                {"kind": "file", "source": "Cargo.toml"},
                {"kind": "file", "source": "src/foo.rs"},
            ],
            "tier-2-wire": [{"kind": "file", "source": "protocol/placeholder"}],
            "mcp-apps": [{"kind": "tree", "source": "web/mcp-apps"}],
            "public-documentation": [{"kind": "file", "source": "docs/placeholder"}],
            "source-boundary": [{"kind": "file", "source": "boundary.json"}],
        }
        for component in manifest["components"]:
            component["paths"] = paths[component["id"]]
            component["binaries"] = []
            component["features"] = []
            component["runtime_services"] = []
        manifest["exclusions"] = []
        manifest["transition_debt"] = []
        manifest["transition_debt_sha256"] = boundary.EMPTY_DEBT_SHA256
        return manifest

    def target_fixture_manifest(self) -> dict[str, object]:
        manifest = self.fixture_manifest()
        return boundary.target_manifest(manifest) if IS_UPSTREAM else manifest

    def write_fixture(
        self, rust: str, *, git_index: bool = True
    ) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="source-boundary-fixture-")
        root = Path(temporary.name)
        (root / "src").mkdir()
        (root / "src/foo.rs").write_text(rust, encoding="utf-8")
        (root / "protocol").mkdir()
        (root / "protocol/placeholder").write_text("protocol", encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs/placeholder").write_text("docs", encoding="utf-8")
        (root / "boundary.json").write_text("{}\n", encoding="utf-8")
        (root / "Cargo.toml").write_text(
            '[package]\nname="fixture"\nversion="0.0.0"\nedition="2021"\n[features]\ndefault=[]\n',
            encoding="utf-8",
        )
        dist = root / "web/mcp-apps/dist"
        dist.mkdir(parents=True)
        (dist / "record-version-diff.html").write_text("fixture", encoding="utf-8")
        (dist / "suggestion-review.html").write_text("fixture", encoding="utf-8")
        if git_index:
            git(root, "init", "-q")
            git(root, "add", ".")
        return temporary, root

    def test_comments_do_not_create_edges(self) -> None:
        temporary, root = self.write_fixture(
            '// include!("../web/workbench/secret.rs")\nconst OK: &str = "safe";\n'
        )
        try:
            boundary.validate_repository(root, self.fixture_manifest(), "upstream")
        finally:
            temporary.cleanup()

    def test_dynamic_include_macros_fail_closed(self) -> None:
        for macro in ("include", "include_str", "include_bytes"):
            temporary, root = self.write_fixture(
                f'const X: &str = {macro} ! (concat ! ("../", "secret"));\n'
            )
            try:
                with self.subTest(macro=macro), self.assertRaisesRegex(
                    boundary.BoundaryError, "unsupported dynamic include"
                ):
                    boundary.validate_repository(root, self.fixture_manifest(), "upstream")
            finally:
                temporary.cleanup()

        temporary, root = self.write_fixture(
            '# [ folder = concat ! ("web/", "workbench") ]\nstruct Assets;\n'
        )
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "unsupported dynamic RustEmbed"):
                boundary.validate_repository(root, self.fixture_manifest(), "upstream")
        finally:
            temporary.cleanup()

    def test_rust_legal_whitespace_edges_fail_closed(self) -> None:
        cases = (
            ('include ! ("../web/workbench/secret.rs");\n', False),
            ('const TEXT: &str = include_str ! ("../web/workbench/secret.rs");\n', False),
            ('const BYTES: &[u8] = include_bytes ! ("../web/workbench/secret.rs");\n', False),
            ('const TEXT: &str = include_str! { "../web/workbench/secret.rs" };\n', False),
            ('const TEXT: &str = include_str!["../web/workbench/secret.rs"];\n', False),
            ('# [ path = "../web/workbench/secret.rs" ] mod secret;\n', True),
            ('# [ path = "../web/workbench/secret.rs" ] pub mod secret;\n', True),
            (
                '# /*a*/ [ path /*b*/ = "../web/workbench/secret.rs" ] '
                'pub /*c*/ (crate) mod secret;\n',
                True,
            ),
            ('#[path="../web/workbench/secret.rs"] pub(crate)mod secret;\n', True),
            ('#[r#path="../web/workbench/secret.rs"] pub mod secret;\n', True),
            ('# [ folder = "web/workbench/assets" ]\nstruct Assets;\n', True),
        )
        for rust, tree_selected in cases:
            temporary, root = self.write_fixture(rust)
            (root / "web/workbench").mkdir(parents=True)
            (root / "web/workbench/secret.rs").write_text("pub fn held() {}\n", encoding="utf-8")
            (root / "web/workbench/assets").mkdir()
            (root / "web/workbench/assets/data.txt").write_text("held\n", encoding="utf-8")
            git(root, "add", ".")
            manifest = self.fixture_manifest()
            if tree_selected:
                manifest["components"][0]["paths"][1] = {"kind": "tree", "source": "src"}
            manifest["exclusions"] = [
                {
                    "id": "commercial-workbench",
                    "classification": "held-private",
                    "reason": "fixture held source",
                    "paths": [{"kind": "tree", "path": "web/workbench"}],
                }
            ]
            try:
                with self.subTest(rust=rust), self.assertRaisesRegex(
                    boundary.BoundaryError, "differs from frozen set"
                ):
                    boundary.validate_repository(root, manifest, "upstream")
            finally:
                temporary.cleanup()

        unsupported = (
            '#[cfg_attr(all(), path="../web/workbench/secret.rs")] '
            'pub(crate)mod secret;\n',
            '#[cfg_attr(all(), doc = stringify!([x]), '
            'path="../web/workbench/secret.rs")] pub mod secret;\n',
            '#[cfg_attr(all(), r#path="../web/workbench/secret.rs")] pub mod secret;\n',
            '#[path="../web/workbench/secret.rs"]\n#[doc="]"]\npub mod secret;\n',
        )
        for rust in unsupported:
            temporary, root = self.write_fixture(rust)
            try:
                with self.subTest(rust=rust), self.assertRaisesRegex(
                    boundary.BoundaryError, "unsupported .*Rust path attribute"
                ):
                    boundary.validate_repository(root, self.fixture_manifest(), "upstream")
            finally:
                temporary.cleanup()

        for declaration in ("mod secret;\n", "mod r#secret;\n"):
            temporary, root = self.write_fixture(declaration)
            (root / "src/foo").mkdir()
            (root / "src/foo/secret.rs").write_text("pub fn held() {}\n", encoding="utf-8")
            git(root, "add", ".")
            manifest = self.fixture_manifest()
            manifest["exclusions"] = [
                {
                    "id": "held-module",
                    "classification": "held-private",
                    "reason": "fixture held module",
                    "paths": [{"kind": "tree", "path": "src/foo"}],
                }
            ]
            try:
                with self.subTest(declaration=declaration), self.assertRaisesRegex(
                    boundary.BoundaryError, "differs from frozen set"
                ):
                    boundary.validate_repository(root, manifest, "upstream")
            finally:
                temporary.cleanup()

    def test_new_static_public_to_held_include_edge_is_rejected(self) -> None:
        temporary, root = self.write_fixture('include!("../web/workbench/secret.rs");\n')
        (root / "web/workbench").mkdir(parents=True)
        (root / "web/workbench/secret.rs").write_text("pub fn held() {}\n", encoding="utf-8")
        git(root, "add", ".")
        manifest = self.fixture_manifest()
        manifest["exclusions"] = [
            {
                "id": "commercial-workbench",
                "classification": "held-private",
                "reason": "fixture held source",
                "paths": [{"kind": "tree", "path": "web/workbench"}],
            }
        ]
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "differs from frozen set"):
                boundary.validate_repository(root, manifest, "upstream")
        finally:
            temporary.cleanup()

    def test_target_mode_reads_untracked_and_ignored_files_and_rejects_symlink(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n", git_index=False)
        manifest = self.target_fixture_manifest()
        try:
            (root / "boundary.json").write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            loaded = boundary.load_manifest(root / "boundary.json", mode="target")
            boundary.validate_repository(root, loaded, "target")
            (root / ".gitignore").write_text("secret.env\n", encoding="utf-8")
            (root / "secret.env").write_text("secret\n", encoding="utf-8")
            with self.assertRaisesRegex(boundary.BoundaryError, "undeclared/forbidden"):
                boundary.validate_repository(root, manifest, "target")
            (root / "secret.env").unlink()
            (root / ".gitignore").unlink()
            os.symlink("src/foo.rs", root / "linked.rs")
            with self.assertRaisesRegex(boundary.BoundaryError, "symlink"):
                boundary.validate_repository(root, manifest, "target")
            (root / "linked.rs").unlink()
            os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(boundary.BoundaryError, "non-regular"):
                boundary.validate_repository(root, manifest, "target")
        finally:
            temporary.cleanup()

    def test_projection_modes_and_non_blob_modes_fail_closed(self) -> None:
        manifest = self.fixture_manifest()
        regular = boundary.project_selection(
            manifest,
            [
                boundary.InventoryEntry("src/foo.rs", "100755"),
                boundary.InventoryEntry("Cargo.toml", "100644"),
            ],
        )
        self.assertEqual(regular[1]["mode"], "100755")
        for mode in ("120000", "160000"):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                boundary.BoundaryError, "not a regular/executable blob"
            ):
                boundary.project_selection(manifest, [boundary.InventoryEntry("src/foo.rs", mode)])

    def test_v2_mapping_shape_refusals_and_tree_projection(self) -> None:
        def upstream_fixture() -> dict[str, object]:
            value = self.fixture_manifest()
            value["exclusions"] = [{
                "id": "fixture-private",
                "classification": "held-private",
                "reason": "Synthetic held selector for mapping-shape validation.",
                "paths": [{"kind": "tree", "path": "private"}],
            }]
            return value

        manifest = upstream_fixture()
        manifest["components"][0]["paths"][0]["target"] = "../Cargo.toml"
        with self.assertRaisesRegex(boundary.BoundaryError, "canonical repository path"):
            boundary.validate_shape(manifest, mode="upstream")

        collision = upstream_fixture()
        collision["components"][0]["paths"][0]["target"] = "src/foo.rs"
        with self.assertRaisesRegex(boundary.BoundaryError, "target paths collide"):
            boundary.validate_shape(collision, mode="upstream")

        cross = upstream_fixture()
        cross["components"][0]["paths"][0]["target"] = "protocol/placeholder"
        cross["components"][1]["paths"][0]["target"] = "wire/placeholder"
        with self.assertRaisesRegex(boundary.BoundaryError, "source/target paths collide"):
            boundary.validate_shape(cross, mode="upstream")

        self_overlap = upstream_fixture()
        self_overlap["components"][2]["paths"][0] = {
            "kind": "tree", "source": "web/mcp-apps", "target": "web/mcp-apps/out"
        }
        with self.assertRaisesRegex(boundary.BoundaryError, "within mcp-apps"):
            boundary.validate_shape(self_overlap, mode="upstream")

        mapped = self.fixture_manifest()
        mapped["components"][2]["paths"][0]["target"] = "apps"
        rows = boundary.project_selection(
            mapped, [boundary.InventoryEntry("web/mcp-apps/dist/app.html", "100644")]
        )
        self.assertEqual(rows[0]["source_path"], "web/mcp-apps/dist/app.html")
        self.assertEqual(rows[0]["target_path"], "apps/dist/app.html")

    def test_v1_manifest_is_not_accepted_as_v2(self) -> None:
        manifest = self.fixture_manifest()
        manifest["format"] = "native-ce.source-boundary/v1"
        manifest["manifest_version"] = 1
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "boundary.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(boundary.BoundaryError, "only native.source-boundary/v2"):
                boundary.load_manifest(path)

    def test_target_refuses_mapped_source_path_leakage(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        manifest = self.fixture_manifest()
        manifest["components"][0]["paths"][1]["target"] = "mapped/foo.rs"
        (root / "mapped").mkdir()
        (root / "mapped/foo.rs").write_text("pub fn safe() {}\n", encoding="utf-8")
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "undeclared/forbidden"):
                boundary.validate_repository(root, manifest, "target")
        finally:
            temporary.cleanup()

    def test_target_refuses_missing_mapped_target(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        manifest = self.fixture_manifest()
        manifest["components"][0]["paths"][1]["target"] = "mapped/foo.rs"
        (root / "src/foo.rs").unlink()
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "matches no projected blob"):
                boundary.validate_repository(root, manifest, "target")
        finally:
            temporary.cleanup()

    def test_upstream_root_counterpart_cannot_replace_publication_input(self) -> None:
        manifest = self.changed()
        component = next(item for item in manifest["components"] if item["id"] == "tier-1-node")
        readme = next(item for item in component["paths"] if item.get("target") == "README.md")
        readme["source"] = "README.md"
        with self.assertRaisesRegex(boundary.BoundaryError, "exact v2 repository wrapper"):
            boundary.validate_shape(manifest)

        bypass = self.changed()
        for component in bypass["components"]:
            for mapping in component["paths"]:
                target = mapping.get("target", mapping["source"])
                if target in boundary.REQUIRED_PUBLICATION_MAPPINGS.values():
                    mapping["source"] = target
                    mapping.pop("target", None)
        with self.assertRaisesRegex(boundary.BoundaryError, "exact v2 repository wrapper"):
            boundary.validate_shape(bypass)

    def test_upstream_selected_selector_must_match_tracked_blob(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        manifest = self.fixture_manifest()
        manifest["components"][0]["paths"].append({"kind": "file", "source": "src/missing.rs"})
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "matches no tracked blob"):
                boundary.validate_repository(root, manifest, "upstream")
        finally:
            temporary.cleanup()

    def test_upstream_excluded_selector_must_match_tracked_entry(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        manifest = self.fixture_manifest()
        manifest["exclusions"] = [
            {
                "id": "missing-private",
                "classification": "held-private",
                "reason": "fixture missing exclusion",
                "paths": [{"kind": "tree", "path": "private/missing"}],
            }
        ]
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "matches no tracked entry"):
                boundary.validate_repository(root, manifest, "upstream")
        finally:
            temporary.cleanup()

    def test_upstream_refuses_index_worktree_content_mismatch(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        (root / "web/workbench").mkdir(parents=True)
        (root / "web/workbench/secret.rs").write_text("pub fn held() {}\n", encoding="utf-8")
        (root / "src/foo.rs").write_text(
            'include ! ("../web/workbench/secret.rs");\n', encoding="utf-8"
        )
        git(root, "add", ".")
        (root / "src/foo.rs").write_text("pub fn safe() {}\n", encoding="utf-8")
        manifest = self.fixture_manifest()
        manifest["exclusions"] = [
            {
                "id": "commercial-workbench",
                "classification": "held-private",
                "reason": "fixture held source",
                "paths": [{"kind": "tree", "path": "web/workbench"}],
            }
        ]
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "index and working tree"):
                boundary.validate_repository(root, manifest, "upstream")
        finally:
            temporary.cleanup()

    def test_cargo_build_scripts_are_dependency_edges(self) -> None:
        for explicit in (False, True):
            temporary, root = self.write_fixture("pub fn safe() {}\n")
            manifest = self.fixture_manifest()
            if explicit:
                build_path = root / "private/build.rs"
                build_path.parent.mkdir()
                package_build = 'build="private/build.rs"\n'
                held_selector = {"kind": "tree", "path": "private"}
            else:
                build_path = root / "build.rs"
                package_build = ""
                held_selector = {"kind": "file", "path": "build.rs"}
            build_path.write_text("fn main() {}\n", encoding="utf-8")
            (root / "Cargo.toml").write_text(
                "[package]\n"
                'name="fixture"\n'
                'version="0.0.0"\n'
                'edition="2021"\n'
                f"{package_build}"
                "[features]\n"
                "default=[]\n",
                encoding="utf-8",
            )
            git(root, "add", ".")
            manifest["exclusions"] = [
                {
                    "id": "held-build-script",
                    "classification": "held-private",
                    "reason": "fixture held build script",
                    "paths": [held_selector],
                }
            ]
            try:
                files = {entry.path for entry in boundary.upstream_inventory(root)}
                build_edges = [
                    edge
                    for edge in boundary.cargo_edges(root, manifest, files)
                    if edge.kind == "cargo-build-script"
                ]
                self.assertEqual(len(build_edges), 1)
                self.assertEqual(
                    build_edges[0].evidence,
                    "package.build" if explicit else "implicit build.rs",
                )
                with self.assertRaisesRegex(boundary.BoundaryError, "differs from frozen set"):
                    boundary.validate_repository(root, manifest, "upstream")
            finally:
                temporary.cleanup()

    def test_cargo_implicit_targets_are_dependency_edges(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        manifest = self.fixture_manifest()
        implicit = root / "src/bin/secret.rs"
        implicit.parent.mkdir()
        implicit.write_text("fn main() {}\n", encoding="utf-8")
        git(root, "add", ".")
        manifest["exclusions"] = [
            {
                "id": "held-implicit-target",
                "classification": "held-private",
                "reason": "fixture held implicit Cargo target",
                "paths": [{"kind": "tree", "path": "src/bin"}],
            }
        ]
        try:
            files = {entry.path for entry in boundary.upstream_inventory(root)}
            targets = [
                edge
                for edge in boundary.cargo_edges(root, manifest, files)
                if edge.kind == "cargo-target" and edge.target_path == "src/bin/secret.rs"
            ]
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].evidence, "implicit bin target")
            with self.assertRaisesRegex(boundary.BoundaryError, "differs from frozen set"):
                boundary.validate_repository(root, manifest, "upstream")
        finally:
            temporary.cleanup()

    def test_cargo_package_workspace_is_a_dependency_edge(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        manifest = self.fixture_manifest()
        private = root / "private"
        private.mkdir()
        (private / "Cargo.toml").write_text("[workspace]\nmembers=[]\n", encoding="utf-8")
        (root / "Cargo.toml").write_text(
            '[package]\nname="fixture"\nversion="0.0.0"\nedition="2021"\n'
            'workspace="private"\n[features]\ndefault=[]\n',
            encoding="utf-8",
        )
        git(root, "add", ".")
        manifest["exclusions"] = [
            {
                "id": "held-workspace",
                "classification": "held-private",
                "reason": "fixture held workspace root",
                "paths": [{"kind": "tree", "path": "private"}],
            }
        ]
        try:
            files = {entry.path for entry in boundary.upstream_inventory(root)}
            workspace_edges = [
                edge
                for edge in boundary.cargo_edges(root, manifest, files)
                if edge.evidence == "package.workspace"
            ]
            self.assertEqual(len(workspace_edges), 1)
            self.assertEqual(workspace_edges[0].target_path, "private/Cargo.toml")
            with self.assertRaisesRegex(boundary.BoundaryError, "differs from frozen set"):
                boundary.validate_repository(root, manifest, "upstream")
        finally:
            temporary.cleanup()

    def test_cargo_explicit_targets_require_paths(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n")
        (root / "Cargo.toml").write_text(
            '[package]\nname="fixture"\nversion="0.0.0"\nedition="2021"\n'
            'autotests=false\n[features]\ndefault=[]\n[[test]]\nname="secret"\n',
            encoding="utf-8",
        )
        git(root, "add", ".")
        try:
            with self.assertRaisesRegex(boundary.BoundaryError, "must declare path"):
                boundary.validate_repository(root, self.fixture_manifest(), "upstream")
        finally:
            temporary.cleanup()

    def test_cargo_parser_covers_workspace_patch_replace_and_target_dependencies(self) -> None:
        temporary, root = self.write_fixture("pub fn safe() {}\n", git_index=False)
        manifest = self.fixture_manifest()
        for name in ("member", "default", "patched", "replaced", "targetdep"):
            directory = root / name
            directory.mkdir()
            (directory / "Cargo.toml").write_text(
                f'[package]\nname="{name}"\nversion="0.0.0"\nedition="2021"\n',
                encoding="utf-8",
            )
            manifest["components"][0]["paths"].append({"kind": "tree", "source": name})
        (root / "Cargo.toml").write_text(
            """[package]
name="fixture"
version="0.0.0"
edition="2021"

[workspace]
members=["member", "default"]
default-members=["default"]
exclude=["excluded"]

[patch.crates-io]
patched={path="patched"}

[replace]
"old:1.0.0"={path="replaced"}

[target.'cfg(unix)'.dependencies]
targetdep={path="targetdep"}

[features]
default=[]
""",
            encoding="utf-8",
        )
        (root / "excluded").mkdir()
        files = {entry.path for entry in boundary.target_inventory(root)}
        edges = boundary.cargo_edges(root, manifest, files)
        kinds = {edge.kind for edge in edges}
        self.assertTrue(
            {
                "cargo-workspace-member",
                "cargo-workspace-default-member",
                "cargo-patch",
                "cargo-replace",
                "cargo-path-dependency",
            }
            <= kinds
        )
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
