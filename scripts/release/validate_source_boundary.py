#!/usr/bin/env python3
"""Validate and deterministically project the native-ce source boundary.

This is deliberately independent of the snapshot publisher.  It freezes the
component contract and its transition debt; the successor publisher task owns
using the projection to materialise a release candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


FORMAT = "native.source-boundary/v2"
EMPTY_DEBT_SHA256 = hashlib.sha256(b"[]").hexdigest()
FROZEN_UPSTREAM_DEBT_SHA256 = EMPTY_DEBT_SHA256
PUBLIC_DEPENDENCY_DIRECTIONS = {
    "tier-1-node": {"tier-2-wire", "mcp-apps", "public-documentation"},
    "tier-2-wire": set(),
    "mcp-apps": set(),
    "public-documentation": set(),
    "source-boundary": set(),
}
CLASSIFICATIONS = {
    "tier-1-node",
    "tier-2-protocol-reference",
    "public-optional-extension",
    "public-documentation",
    "boundary-governance",
}
MATURITIES = {"stable", "experimental", "research", "governance"}
EDGE_KINDS = {
    "cargo-build-script",
    "cargo-path-dependency",
    "cargo-patch",
    "cargo-replace",
    "cargo-target",
    "cargo-workspace-default-member",
    "cargo-workspace-member",
    "rust-include",
    "rust-module",
    "rust-embed-folder",
    "generated-output",
}
ROOT_KEYS = {
    "format",
    "manifest_version",
    "selection",
    "components",
    "exclusions",
    "transition_debt",
    "transition_debt_sha256",
}
COMPONENT_KEYS = {
    "id",
    "classification",
    "reason",
    "paths",
    "binaries",
    "features",
    "runtime_services",
    "maturity",
    "generated_artifacts",
    "permitted_dependencies",
}
TARGET_COMPONENT_KEYS = COMPONENT_KEYS - {"reason"}
EXCLUSION_KEYS = {"id", "classification", "reason", "paths"}
SELECTOR_KEYS = {"kind", "path"}
MAPPING_KEYS = {"kind", "source", "target"}
ARTIFACT_KEYS = {"path", "producer", "drift_check", "execution"}
TARGET_ARTIFACT_KEYS = ARTIFACT_KEYS - {"execution"}
RUNTIME_SERVICE_KEYS = {"id", "kind", "entrypoint", "support"}
DEBT_KEYS = {
    "source_component",
    "target_component",
    "kind",
    "source_path",
    "target_path",
    "evidence",
    "successor_task",
    "reason",
}
ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
TASK_RE = re.compile(r"^[0-9a-f]{7}$")
REQUIRED_PUBLICATION_MAPPINGS = {
    "publication/root/.gitignore": ".gitignore",
    "publication/root/ARCHITECTURE.md": "ARCHITECTURE.md",
    "publication/root/BUILDING.md": "BUILDING.md",
    "publication/root/CONTRIBUTING.md": "CONTRIBUTING.md",
    "publication/root/LICENSE.md": "LICENSE.md",
    "publication/root/README.md": "README.md",
    "publication/root/RELEASE_NOTES.md": "RELEASE_NOTES.md",
    "publication/docs/README.md": "docs/README.md",
    "native-ce-boundary.json": "native-boundary.json",
}


class BoundaryError(RuntimeError):
    """The boundary cannot be proven safe."""


@dataclass(frozen=True)
class Selector:
    kind: str
    path: str

    def matches(self, path: str) -> bool:
        if self.kind == "file":
            return path == self.path
        return path.startswith(self.path + "/")


@dataclass(frozen=True)
class MappingSelector:
    kind: str
    source: str
    target: str

    def selector(self, mode: str) -> Selector:
        return Selector(self.kind, self.source if mode == "upstream" else self.target)

    def map_path(self, path: str, mode: str) -> tuple[str, str]:
        selected = self.selector(mode)
        if not selected.matches(path):
            raise BoundaryError(f"path is outside mapping: {path}")
        base = self.source if mode == "upstream" else self.target
        suffix = path[len(base):]
        return self.source + suffix, self.target + suffix


@dataclass(frozen=True)
class Edge:
    source_component: str
    target_component: str
    kind: str
    source_path: str
    target_path: str
    evidence: str

    def debt_key(self) -> tuple[str, ...]:
        return (
            self.source_component,
            self.target_component,
            self.kind,
            self.source_path,
            self.target_path,
            self.evidence,
        )


@dataclass(frozen=True)
class InventoryEntry:
    path: str
    mode: str
    kind: str = "blob"
    oid: str | None = None


def _object(value: Any, context: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BoundaryError(f"{context} must be an object")
    unknown = set(value) - keys
    if unknown:
        raise BoundaryError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise BoundaryError(f"{context} must be a non-empty, trimmed string")
    return value


def canonical_path(value: Any, context: str, *, tree: bool = False) -> str:
    path = _string(value, context)
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or "." in pure.parts
        or "\\" in path
        or path != pure.as_posix()
        or path.endswith("/")
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        raise BoundaryError(f"{context} is not a canonical repository path: {path!r}")
    if not pure.parts or (tree and len(pure.parts) == 0):
        raise BoundaryError(f"{context} must not select the repository root")
    return path


def parse_selector(value: Any, context: str) -> Selector:
    item = _object(value, context, SELECTOR_KEYS)
    if set(item) != SELECTOR_KEYS:
        raise BoundaryError(f"{context} requires exactly kind and path")
    kind = item["kind"]
    if kind not in {"file", "tree"}:
        raise BoundaryError(f"{context}.kind must be file or tree")
    return Selector(kind, canonical_path(item["path"], f"{context}.path", tree=kind == "tree"))


def parse_mapping(value: Any, context: str) -> MappingSelector:
    item = _object(value, context, MAPPING_KEYS)
    required = {"kind", "source"}
    if not required <= set(item):
        raise BoundaryError(f"{context} requires kind and source")
    kind = item["kind"]
    if kind not in {"file", "tree"}:
        raise BoundaryError(f"{context}.kind must be file or tree")
    source = canonical_path(item["source"], f"{context}.source", tree=kind == "tree")
    target = canonical_path(item.get("target", source), f"{context}.target", tree=kind == "tree")
    return MappingSelector(kind, source, target)


def selectors_intersect(left: Selector, right: Selector) -> bool:
    if left.kind == right.kind == "file":
        return left.path == right.path
    if left.kind == "tree" and right.kind == "tree":
        return (
            left.path == right.path
            or left.path.startswith(right.path + "/")
            or right.path.startswith(left.path + "/")
        )
    tree, file = (left, right) if left.kind == "tree" else (right, left)
    return file.path.startswith(tree.path + "/")


def canonical_debt_bytes(debts: list[dict[str, Any]]) -> bytes:
    return json.dumps(debts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def target_manifest(upstream: dict[str, Any]) -> dict[str, Any]:
    """Derive the public target authority without carrying upstream topology."""
    components: list[dict[str, Any]] = []
    for component in upstream["components"]:
        mappings = [
            parse_mapping(raw, f"component {component['id']} paths[{index}]")
            for index, raw in enumerate(component["paths"])
        ]

        def target_path(path: str, context: str) -> str:
            matches = [
                mapping
                for mapping in mappings
                if mapping.selector("upstream").matches(path)
            ]
            if len(matches) != 1:
                raise BoundaryError(
                    f"{context} must resolve through exactly one selected component mapping"
                )
            return matches[0].map_path(path, "upstream")[1]

        projected = dict(component)
        projected.pop("reason")
        projected["paths"] = [
            {"kind": mapping.kind, "source": mapping.target}
            for mapping in mappings
        ]
        projected["runtime_services"] = [
            {
                **service,
                "entrypoint": target_path(
                    service["entrypoint"],
                    f"component {component['id']} runtime service {service['id']}",
                ),
            }
            for service in component["runtime_services"]
        ]
        projected["generated_artifacts"] = [
            {
                **{
                    key: value
                    for key, value in artifact.items()
                    if key not in {"path", "execution"}
                },
                "path": target_path(
                    artifact["path"],
                    f"component {component['id']} generated artifact",
                ),
            }
            for artifact in component["generated_artifacts"]
        ]
        components.append(projected)
    result = {
        "format": upstream["format"],
        "manifest_version": upstream["manifest_version"],
        "selection": upstream["selection"],
        "components": components,
        "exclusions": [],
        "transition_debt": [],
        "transition_debt_sha256": EMPTY_DEBT_SHA256,
    }
    validate_shape(result, mode="target")
    return result


def target_manifest_bytes(upstream: dict[str, Any]) -> bytes:
    return (
        json.dumps(target_manifest(upstream), indent=2, ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def load_manifest(path: Path, *, mode: str = "upstream") -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryError(f"cannot read valid boundary JSON from {path}: {exc}") from exc
    manifest = _object(value, "manifest", ROOT_KEYS)
    if set(manifest) != ROOT_KEYS:
        raise BoundaryError("manifest is missing one or more required fields")
    if manifest["format"] != FORMAT or manifest["manifest_version"] != 2:
        raise BoundaryError(f"only {FORMAT} with manifest_version 2 is supported")
    if manifest["selection"] != "public":
        raise BoundaryError("selection must be exactly public")
    validate_shape(manifest, mode=mode)
    return manifest


def _string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise BoundaryError(f"{context} must be an array of strings")
    if len(value) != len(set(value)):
        raise BoundaryError(f"{context} must not contain duplicates")
    return [_string(item, f"{context} entry") for item in value]


def validate_shape(manifest: dict[str, Any], *, mode: str = "upstream") -> None:
    if mode not in {"upstream", "target"}:
        raise BoundaryError(f"unsupported validation mode: {mode}")
    components = manifest["components"]
    exclusions = manifest["exclusions"]
    debts = manifest["transition_debt"]
    if not isinstance(components, list) or not components:
        raise BoundaryError("components must be a non-empty array")
    if not isinstance(exclusions, list) or (mode == "upstream" and not exclusions):
        raise BoundaryError("exclusions must be an array (non-empty in upstream mode)")
    if mode == "target" and exclusions:
        raise BoundaryError("target manifest must not disclose upstream exclusions")
    if not isinstance(debts, list):
        raise BoundaryError("transition_debt must be an array")

    identities: set[str] = set()
    selected: list[tuple[str, MappingSelector]] = []
    for index, raw in enumerate(components):
        context = f"components[{index}]"
        component_keys = COMPONENT_KEYS if mode == "upstream" else TARGET_COMPONENT_KEYS
        component = _object(raw, context, component_keys)
        if set(component) != component_keys:
            raise BoundaryError(f"{context} is missing required fields")
        identifier = _string(component["id"], f"{context}.id")
        if not ID_RE.fullmatch(identifier) or identifier in identities:
            raise BoundaryError(f"{context}.id is invalid or duplicated")
        identities.add(identifier)
        if component["classification"] not in CLASSIFICATIONS:
            raise BoundaryError(f"{context}.classification is not a v1 classification")
        if mode == "upstream":
            _string(component["reason"], f"{context}.reason")
        if component["maturity"] not in MATURITIES:
            raise BoundaryError(f"{context}.maturity is invalid")
        paths = component["paths"]
        if not isinstance(paths, list) or not paths:
            raise BoundaryError(f"{context}.paths must be a non-empty array")
        for path_index, item in enumerate(paths):
            if mode == "target" and set(item) != {"kind", "source"}:
                raise BoundaryError(
                    f"{context}.paths[{path_index}] must contain only target-native paths"
                )
            selected.append((identifier, parse_mapping(item, f"{context}.paths[{path_index}]")))
        _string_list(component["binaries"], f"{context}.binaries")
        _string_list(component["features"], f"{context}.features")
        services = component["runtime_services"]
        if not isinstance(services, list):
            raise BoundaryError(f"{context}.runtime_services must be an array")
        service_ids: list[str] = []
        for service_index, raw_service in enumerate(services):
            service_context = f"{context}.runtime_services[{service_index}]"
            service = _object(raw_service, service_context, RUNTIME_SERVICE_KEYS)
            if set(service) != RUNTIME_SERVICE_KEYS:
                raise BoundaryError(f"{service_context} is missing required fields")
            identifier_value = _string(service["id"], f"{service_context}.id")
            if not ID_RE.fullmatch(identifier_value):
                raise BoundaryError(f"{service_context}.id is invalid")
            if service["kind"] not in {"binary", "static-extension"}:
                raise BoundaryError(f"{service_context}.kind is invalid")
            canonical_path(service["entrypoint"], f"{service_context}.entrypoint")
            if service["support"] not in {"standalone", "reference", "optional"}:
                raise BoundaryError(f"{service_context}.support is invalid")
            service_ids.append(identifier_value)
        if len(service_ids) != len(set(service_ids)):
            raise BoundaryError(f"{context}.runtime_services has duplicate ids")
        binary_service_ids = [
            service["id"] for service in services if service["kind"] == "binary"
        ]
        if component["binaries"] != binary_service_ids:
            raise BoundaryError(
                f"{context}.binaries must exactly match binary runtime_services in order"
            )
        dependencies = _string_list(
            component["permitted_dependencies"], f"{context}.permitted_dependencies"
        )
        artifacts = component["generated_artifacts"]
        if not isinstance(artifacts, list):
            raise BoundaryError(f"{context}.generated_artifacts must be an array")
        for artifact_index, raw_artifact in enumerate(artifacts):
            artifact_context = f"{context}.generated_artifacts[{artifact_index}]"
            artifact_keys = ARTIFACT_KEYS if mode == "upstream" else TARGET_ARTIFACT_KEYS
            artifact = _object(raw_artifact, artifact_context, artifact_keys)
            if set(artifact) != artifact_keys:
                raise BoundaryError(f"{artifact_context} is missing required fields")
            canonical_path(artifact["path"], f"{artifact_context}.path")
            _string(artifact["producer"], f"{artifact_context}.producer")
            _string(artifact["drift_check"], f"{artifact_context}.drift_check")
            if mode == "upstream" and artifact["execution"] != "deferred:b27c449":
                raise BoundaryError(
                    f"{artifact_context}.execution must defer drift execution to b27c449"
                )
        component["_validated_dependencies"] = dependencies

    excluded_selectors: list[tuple[str, Selector]] = []
    for index, raw in enumerate(exclusions):
        context = f"exclusions[{index}]"
        exclusion = _object(raw, context, EXCLUSION_KEYS)
        if set(exclusion) != EXCLUSION_KEYS:
            raise BoundaryError(f"{context} is missing required fields")
        identifier = _string(exclusion["id"], f"{context}.id")
        if not ID_RE.fullmatch(identifier) or identifier in identities:
            raise BoundaryError(f"{context}.id is invalid or duplicated")
        identities.add(identifier)
        if exclusion["classification"] != "held-private":
            raise BoundaryError(f"{context}.classification must be held-private")
        _string(exclusion["reason"], f"{context}.reason")
        paths = exclusion["paths"]
        if not isinstance(paths, list) or not paths:
            raise BoundaryError(f"{context}.paths must be a non-empty array")
        for path_index, item in enumerate(paths):
            excluded_selectors.append(
                (identifier, parse_selector(item, f"{context}.paths[{path_index}]"))
            )

    for index, (owner, mapping) in enumerate(selected):
        source = mapping.selector("upstream")
        target = mapping.selector("target")
        if mapping.source != mapping.target and selectors_intersect(source, target):
            raise BoundaryError(
                f"selected source/target paths collide within {owner}: "
                f"{source.path} / {target.path}"
            )
        for other_owner, other_mapping in selected[index + 1 :]:
            other_source = other_mapping.selector("upstream")
            other_target = other_mapping.selector("target")
            if selectors_intersect(source, other_source):
                raise BoundaryError(
                    f"selected selectors overlap between {owner} and {other_owner}: "
                    f"{source.path} / {other_source.path}"
                )
            if selectors_intersect(target, other_target):
                raise BoundaryError(
                    f"selected target paths collide between {owner} and {other_owner}: "
                    f"{target.path} / {other_target.path}"
                )
            if selectors_intersect(target, other_source) or selectors_intersect(source, other_target):
                raise BoundaryError(
                    f"selected source/target paths collide between {owner} and {other_owner}"
                )
        for excluded_owner, excluded in excluded_selectors:
            if selectors_intersect(source, excluded):
                raise BoundaryError(
                    f"selected/forbidden selectors overlap between {owner} and "
                    f"{excluded_owner}: {source.path} / {excluded.path}"
                )
    for index, (owner, selector) in enumerate(excluded_selectors):
        for other_owner, other in excluded_selectors[index + 1 :]:
            if selectors_intersect(selector, other):
                raise BoundaryError(
                    f"forbidden selectors overlap between {owner} and {other_owner}: "
                    f"{selector.path} / {other.path}"
                )

    selected_mappings = {
        mapping.source: mapping.target for _owner, mapping in selected
    }
    wrapper_targets = set(REQUIRED_PUBLICATION_MAPPINGS.values())
    if mode == "upstream" and any(
        target in wrapper_targets for target in selected_mappings.values()
    ):
        actual = {
            source: selected_mappings.get(source)
            for source in REQUIRED_PUBLICATION_MAPPINGS
        }
        if actual != REQUIRED_PUBLICATION_MAPPINGS:
            raise BoundaryError(
                "publication wrapper mappings differ from the exact v2 repository wrapper"
            )

    public_ids = {component["id"] for component in components}
    if public_ids != set(PUBLIC_DEPENDENCY_DIRECTIONS):
        raise BoundaryError("public component identities differ from the frozen v2 direction matrix")
    for component in components:
        dependencies = set(component.pop("_validated_dependencies"))
        expected_directions = PUBLIC_DEPENDENCY_DIRECTIONS[component["id"]]
        if dependencies != expected_directions:
            raise BoundaryError(
                f"component {component['id']} dependency directions differ from frozen v2 matrix"
            )
        if not dependencies <= public_ids:
            raise BoundaryError(f"component {component['id']} permits held-private dependencies")

    validate_mcp_apps(components)
    validated_debts: list[dict[str, Any]] = []
    for index, raw in enumerate(debts):
        context = f"transition_debt[{index}]"
        debt = _object(raw, context, DEBT_KEYS)
        if set(debt) != DEBT_KEYS:
            raise BoundaryError(f"{context} is missing required fields")
        for field in DEBT_KEYS:
            _string(debt[field], f"{context}.{field}")
        if debt["source_component"] not in identities or debt["target_component"] not in identities:
            raise BoundaryError(f"{context} names an unknown component")
        if debt["kind"] not in EDGE_KINDS:
            raise BoundaryError(f"{context}.kind is unsupported")
        canonical_path(debt["source_path"], f"{context}.source_path")
        canonical_path(debt["target_path"], f"{context}.target_path")
        if not TASK_RE.fullmatch(debt["successor_task"]):
            raise BoundaryError(f"{context}.successor_task must be a seven-character task ID")
        validated_debts.append(debt)
    if len({tuple(sorted(item.items())) for item in validated_debts}) != len(validated_debts):
        raise BoundaryError("transition_debt must not contain duplicates")
    expected = hashlib.sha256(canonical_debt_bytes(validated_debts)).hexdigest()
    if manifest["transition_debt_sha256"] != expected:
        raise BoundaryError("transition_debt_sha256 does not match the exact frozen debt set")
    frozen = FROZEN_UPSTREAM_DEBT_SHA256 if mode == "upstream" else EMPTY_DEBT_SHA256
    if expected != frozen:
        raise BoundaryError(f"transition debt differs from the validator's frozen v2 {mode} set")


def validate_mcp_apps(components: list[dict[str, Any]]) -> None:
    apps = [item for item in components if item["id"] == "mcp-apps"]
    if len(apps) != 1:
        raise BoundaryError("v2 requires exactly one mcp-apps component")
    artifacts = apps[0]["generated_artifacts"]
    expected = {
        "web/mcp-apps/dist/record-version-diff.html",
        "web/mcp-apps/dist/suggestion-review.html",
    }
    if {item["path"] for item in artifacts} != expected or len(artifacts) != 2:
        raise BoundaryError("mcp-apps must declare exactly the two approved HTML bundles")
    for artifact in artifacts:
        if artifact["producer"] != "npm run build" or artifact["drift_check"] != "npm run build":
            raise BoundaryError("MCP App bundles require the exact npm run build producer/drift check")


def manifest_for_mode(manifest: dict[str, Any], mode: str) -> dict[str, Any]:
    """Return the ownership view for the repository paths visible in ``mode``."""
    effective = dict(manifest)
    effective["components"] = []
    for component in manifest["components"]:
        projected = dict(component)
        projected["paths"] = [
            {
                "kind": mapping.kind,
                "path": mapping.source if mode == "upstream" else mapping.target,
            }
            for index, raw in enumerate(component["paths"])
            for mapping in [parse_mapping(raw, f"component {component['id']} paths[{index}]")]
        ]
        effective["components"].append(projected)
    return effective


def owner_of(manifest: dict[str, Any], path: str) -> tuple[str, bool] | None:
    matches: list[tuple[str, bool]] = []
    for component in manifest["components"]:
        if any(
            Selector(item["kind"], item.get("path", item.get("source", ""))).matches(path)
            for item in component["paths"]
        ):
            matches.append((component["id"], True))
    for exclusion in manifest["exclusions"]:
        if any(Selector(item["kind"], item["path"]).matches(path) for item in exclusion["paths"]):
            matches.append((exclusion["id"], False))
    if len(matches) > 1:
        raise BoundaryError(f"{path} has multiple owners")
    return matches[0] if matches else None


def upstream_inventory(repo: Path) -> list[InventoryEntry]:
    result = subprocess.run(
        ("git", "ls-files", "--stage", "-z"),
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise BoundaryError(
            "upstream mode requires a Git index: "
            + result.stderr.decode("utf-8", "replace").strip()
        )
    entries: list[InventoryEntry] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            mode, oid, stage = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise BoundaryError("Git index returned an unparseable entry") from exc
        canonical_path(path, "Git index path")
        if stage != "0":
            raise BoundaryError(f"Git index has an unresolved stage for {path}")
        entries.append(InventoryEntry(path, mode, oid=oid))
    parity = subprocess.run(
        ("git", "-c", "core.filemode=true", "diff-files", "--quiet", "--"),
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if parity.returncode == 1:
        raise BoundaryError(
            "upstream mode requires the Git index and working tree to match exactly"
        )
    if parity.returncode != 0:
        raise BoundaryError(
            "cannot compare the Git index and working tree: "
            + parity.stderr.decode("utf-8", "replace").strip()
        )
    return sorted(entries, key=lambda item: item.path.encode("utf-8"))


def require_index_worktree_parity(
    repo: Path, entries: Iterable[InventoryEntry], paths: set[str]
) -> None:
    """Prove analyzed working-tree bytes and modes exactly match their index blobs."""
    by_path = {entry.path: entry for entry in entries}
    for path in sorted(paths, key=lambda item: item.encode("utf-8")):
        entry = by_path.get(path)
        if entry is None or entry.oid is None:
            raise BoundaryError(f"cannot prove index/working-tree parity for {path}")
        try:
            info = (repo / path).lstat()
            data = (repo / path).read_bytes()
        except OSError as exc:
            raise BoundaryError(f"cannot read indexed working-tree path {path}: {exc}") from exc
        if not stat.S_ISREG(info.st_mode) or entry.mode not in {"100644", "100755"}:
            raise BoundaryError(f"analyzed index path is not a regular blob: {path}")
        worktree_mode = "100755" if info.st_mode & 0o111 else "100644"
        if worktree_mode != entry.mode:
            raise BoundaryError(f"index/working-tree mode mismatch for {path}")
        algorithm = {40: "sha1", 64: "sha256"}.get(len(entry.oid))
        if algorithm is None:
            raise BoundaryError(f"unsupported Git object ID for {path}")
        digest = hashlib.new(algorithm, f"blob {len(data)}\0".encode() + data).hexdigest()
        if digest != entry.oid:
            raise BoundaryError(f"index/working-tree content mismatch for {path}")


def target_inventory(repo: Path) -> list[InventoryEntry]:
    entries: list[InventoryEntry] = []
    for root, directories, filenames in os.walk(repo, topdown=True, followlinks=False):
        root_path = Path(root)
        directories[:] = sorted(name for name in directories if name != ".git")
        for name in list(directories):
            path = root_path / name
            info = path.lstat()
            relative = path.relative_to(repo).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise BoundaryError(f"target contains a symlink: {relative}")
            if not stat.S_ISDIR(info.st_mode):
                raise BoundaryError(f"target contains a non-directory tree entry: {relative}")
        for name in sorted(filenames):
            path = root_path / name
            relative = path.relative_to(repo).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise BoundaryError(f"target contains a symlink: {relative}")
            if not stat.S_ISREG(info.st_mode):
                raise BoundaryError(f"target contains a non-regular file: {relative}")
            mode = "100755" if info.st_mode & 0o111 else "100644"
            canonical_path(relative, "target path")
            entries.append(InventoryEntry(relative, mode))
    return sorted(entries, key=lambda item: item.path.encode("utf-8"))


def project_selection(
    manifest: dict[str, Any], entries: Iterable[InventoryEntry], mode: str = "upstream"
) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    unique = {entry.path: entry for entry in entries}
    mappings = [
        (component["id"], parse_mapping(raw, f"component {component['id']} mapping"))
        for component in manifest["components"]
        for raw in component["paths"]
    ]
    for path in sorted(unique, key=lambda item: item.encode("utf-8")):
        entry = unique[path]
        canonical_path(entry.path, "repository path")
        matches = [
            (component, mapping)
            for component, mapping in mappings
            if mapping.selector(mode).matches(entry.path)
        ]
        if len(matches) > 1:
            raise BoundaryError(f"{entry.path} has multiple selected mappings")
        if matches:
            if entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
                raise BoundaryError(
                    f"selected path is not a regular/executable blob: {entry.path} ({entry.mode})"
                )
            component, mapping = matches[0]
            source_path, target_path = mapping.map_path(entry.path, mode)
            selected.append(
                {
                    "source_path": source_path,
                    "target_path": target_path,
                    "path": entry.path,
                    "component": component,
                    "mode": entry.mode,
                    "type": entry.kind,
                }
            )
    return sorted(selected, key=lambda item: item["target_path"].encode("utf-8"))


def validate_selected_paths(manifest: dict[str, Any], paths: Iterable[str]) -> None:
    for path in paths:
        canonical_path(path, "selected path")
        owner = owner_of(manifest, path)
        if owner is None:
            raise BoundaryError(f"undeclared path selected: {path}")
        if not owner[1]:
            raise BoundaryError(f"forbidden path selected from {owner[0]}: {path}")


def strip_rust_comments(source: str, path: str, *, retain_literals: bool = True) -> str:
    """Remove comments, optionally mask literals, and reject unterminated lexical forms."""
    output: list[str] = []
    index = 0
    block_depth = 0
    state = "code"
    raw_end = ""
    while index < len(source):
        pair = source[index : index + 2]
        char = source[index]
        if state == "code":
            if pair == "//":
                state = "line"
                output.extend("  ")
                index += 2
            elif pair == "/*":
                state = "block"
                block_depth = 1
                output.extend("  ")
                index += 2
            elif (raw := re.match(r'(?:br|rb|r)(#*)"', source[index:])) is not None:
                token = raw.group(0)
                raw_end = '"' + raw.group(1)
                state = "raw"
                output.extend(token if retain_literals else " " * len(token))
                index += len(token)
            elif char == '"':
                state = "string"
                output.append(char if retain_literals else " ")
                index += 1
            elif char == "'" and (
                (index + 2 < len(source) and source[index + 2] == "'")
                or (index + 3 < len(source) and source[index + 1] == "\\" and source[index + 3] == "'")
            ):
                state = "char"
                output.append(char if retain_literals else " ")
                index += 1
            else:
                output.append(char)
                index += 1
        elif state == "line":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
            index += 1
        elif state == "block":
            if pair == "/*":
                block_depth += 1
                output.extend("  ")
                index += 2
            elif pair == "*/":
                block_depth -= 1
                output.extend("  ")
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
        elif state in {"string", "char"}:
            output.append(char if retain_literals else ("\n" if char == "\n" else " "))
            index += 1
            if char == "\\" and index < len(source):
                escaped = source[index]
                output.append(escaped if retain_literals else ("\n" if escaped == "\n" else " "))
                index += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        else:
            if source.startswith(raw_end, index):
                output.extend(raw_end if retain_literals else " " * len(raw_end))
                index += len(raw_end)
                state = "code"
            else:
                output.append(char if retain_literals else ("\n" if char == "\n" else " "))
                index += 1
    if state in {"block", "string", "char", "raw"}:
        raise BoundaryError(f"cannot lex Rust source safely: {path}")
    return "".join(output)


def resolve_repo_path(repo: Path, source_path: str, literal: str, *, folder: bool = False) -> str:
    source_dir = PurePosixPath(source_path).parent
    joined = source_dir.joinpath(literal)
    parts: list[str] = []
    for part in joined.parts:
        if part == ".":
            continue
        if part == "..":
            if not parts:
                raise BoundaryError(f"dependency escapes repository: {source_path} -> {literal}")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        if folder:
            return ""
        raise BoundaryError(f"dependency resolves to repository root: {source_path} -> {literal}")
    resolved = PurePosixPath(*parts).as_posix()
    canonical_path(resolved, "dependency target", tree=folder)
    return resolved


def has_conditional_rust_path_attribute(code: str, source: str) -> bool:
    """Find path inside cfg_attr using balanced delimiters in literal/comment-masked code."""
    start = re.compile(r'#\s*\[\s*(?:r#)?cfg_attr\b')
    pairs = {"(": ")", "[": "]", "{": "}"}
    for match in start.finditer(code):
        opening = code.find("[", match.start(), match.end())
        stack: list[str] = []
        for index in range(opening, len(code)):
            char = code[index]
            if char in pairs:
                stack.append(pairs[char])
            elif char in ")]}":
                if not stack or char != stack.pop():
                    raise BoundaryError(f"cannot parse Rust cfg_attr safely in {source}")
                if not stack:
                    attribute = code[opening : index + 1]
                    if re.search(r"\b(?:r#)?path\s*=", attribute):
                        return True
                    break
        else:
            raise BoundaryError(f"cannot parse Rust cfg_attr safely in {source}")
    return False


def make_edge(
    manifest: dict[str, Any], source: str, target: str, kind: str, evidence: str
) -> Edge | None:
    source_owner = owner_of(manifest, source)
    target_owner = owner_of(manifest, target)
    if source_owner is None:
        return None
    if target_owner is None:
        raise BoundaryError(f"dependency target is undeclared: {source} -> {target}")
    return Edge(source_owner[0], target_owner[0], kind, source, target, evidence)


def cargo_edges(repo: Path, manifest: dict[str, Any], files: set[str]) -> list[Edge]:
    edges: list[Edge] = []
    dependency_tables = {"dependencies", "dev-dependencies", "build-dependencies"}
    for source in sorted(path for path in files if path.endswith("Cargo.toml")):
        if owner_of(manifest, source) is None or not owner_of(manifest, source)[1]:
            continue
        try:
            document = tomllib.loads((repo / source).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise BoundaryError(f"cannot parse selected Cargo manifest {source}: {exc}") from exc

        package = document.get("package")
        if package is not None:
            if not isinstance(package, dict):
                raise BoundaryError(f"unsupported Cargo package shape in {source}")
            package_workspace = package.get("workspace")
            if package_workspace is not None:
                if not isinstance(package_workspace, str):
                    raise BoundaryError(f"unsupported Cargo package.workspace in {source}")
                workspace_dir = resolve_repo_path(
                    repo, source, package_workspace, folder=True
                )
                workspace_manifest = (
                    f"{workspace_dir}/Cargo.toml" if workspace_dir else "Cargo.toml"
                )
                edge = make_edge(
                    manifest,
                    source,
                    workspace_manifest,
                    "cargo-workspace-member",
                    "package.workspace",
                )
                if edge:
                    edges.append(edge)
            build = package.get("build")
            if build is False:
                pass
            elif build is not None:
                if not isinstance(build, str):
                    raise BoundaryError(f"unsupported Cargo package.build in {source}")
                target = resolve_repo_path(repo, source, build)
                edge = make_edge(
                    manifest, source, target, "cargo-build-script", "package.build"
                )
                if edge:
                    edges.append(edge)
            else:
                source_dir = PurePosixPath(source).parent
                implicit = (source_dir / "build.rs").as_posix()
                if implicit in files:
                    edge = make_edge(
                        manifest,
                        source,
                        implicit,
                        "cargo-build-script",
                        "implicit build.rs",
                    )
                    if edge:
                        edges.append(edge)

        tables: list[tuple[str, dict[str, Any]]] = []

        def dependency_sections(value: Any, prefix: str = "") -> None:
            if not isinstance(value, dict):
                return
            for name, child in value.items():
                dotted = f"{prefix}.{name}" if prefix else name
                if name in dependency_tables:
                    if not isinstance(child, dict):
                        raise BoundaryError(f"unsupported Cargo dependency table {dotted} in {source}")
                    tables.append((dotted, child))
                else:
                    dependency_sections(child, dotted)

        dependency_sections(document)
        for table_name, table in tables:
            for dependency_name, value in table.items():
                if isinstance(value, dict) and "path" in value:
                    if not isinstance(value["path"], str):
                        raise BoundaryError(f"non-string Cargo path dependency in {source}")
                    target_dir = resolve_repo_path(repo, source, value["path"], folder=True)
                    target = f"{target_dir}/Cargo.toml" if target_dir else "Cargo.toml"
                    edge = make_edge(
                        manifest,
                        source,
                        target,
                        "cargo-path-dependency",
                        f"{table_name}.{dependency_name}.path",
                    )
                    if edge:
                        edges.append(edge)
        patch = document.get("patch", {})
        if patch is not None:
            if not isinstance(patch, dict):
                raise BoundaryError(f"unsupported Cargo patch shape in {source}")
            for registry, packages in patch.items():
                if not isinstance(packages, dict):
                    raise BoundaryError(f"unsupported Cargo patch registry in {source}")
                for package_name, value in packages.items():
                    if isinstance(value, dict) and "path" in value:
                        if not isinstance(value["path"], str):
                            raise BoundaryError(f"non-string Cargo patch path in {source}")
                        target_dir = resolve_repo_path(repo, source, value["path"], folder=True)
                        target = f"{target_dir}/Cargo.toml" if target_dir else "Cargo.toml"
                        edge = make_edge(
                            manifest,
                            source,
                            target,
                            "cargo-patch",
                                f"patch.{registry}.{package_name}.path",
                        )
                        if edge:
                            edges.append(edge)
        replace = document.get("replace", {})
        if replace is not None:
            if not isinstance(replace, dict):
                raise BoundaryError(f"unsupported Cargo replace shape in {source}")
            for package_name, value in replace.items():
                if isinstance(value, dict) and "path" in value:
                    if not isinstance(value["path"], str):
                        raise BoundaryError(f"non-string Cargo replace path in {source}")
                    target_dir = resolve_repo_path(repo, source, value["path"], folder=True)
                    target = f"{target_dir}/Cargo.toml" if target_dir else "Cargo.toml"
                    edge = make_edge(
                        manifest,
                        source,
                        target,
                        "cargo-replace",
                        f"replace.{package_name}.path",
                    )
                    if edge:
                        edges.append(edge)
        workspace = document.get("workspace")
        if workspace is not None:
            if not isinstance(workspace, dict):
                raise BoundaryError(f"unsupported Cargo workspace shape in {source}")
            for field, kind in (
                ("members", "cargo-workspace-member"),
                ("default-members", "cargo-workspace-default-member"),
            ):
                values = workspace.get(field, [])
                if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                    raise BoundaryError(f"workspace.{field} must be a string array in {source}")
                for index, value in enumerate(values):
                    if any(character in value for character in "*?["):
                        raise BoundaryError(
                            f"workspace.{field} globs are unsupported fail-closed in {source}"
                        )
                    target_dir = resolve_repo_path(repo, source, value, folder=True)
                    target = f"{target_dir}/Cargo.toml" if target_dir else "Cargo.toml"
                    edge = make_edge(
                        manifest, source, target, kind, f"workspace.{field}[{index}]"
                    )
                    if edge:
                        edges.append(edge)
            excludes = workspace.get("exclude", [])
            if not isinstance(excludes, list) or any(not isinstance(item, str) for item in excludes):
                raise BoundaryError(f"workspace.exclude must be a string array in {source}")
            for value in excludes:
                if any(character in value for character in "*?["):
                    raise BoundaryError("workspace.exclude globs are unsupported fail-closed")
                resolve_repo_path(repo, source, value, folder=True)
        explicit_target_paths: set[str] = set()
        for target_kind in ("lib", "bin", "example", "test", "bench"):
            raw_targets = document.get(target_kind, [])
            targets = [raw_targets] if isinstance(raw_targets, dict) else raw_targets
            if not isinstance(targets, list):
                raise BoundaryError(f"unsupported Cargo {target_kind} target shape in {source}")
            for index, target_spec in enumerate(targets):
                if not isinstance(target_spec, dict) or "path" not in target_spec:
                    raise BoundaryError(
                        f"explicit Cargo {target_kind}[{index}] must declare path in {source}"
                    )
                if not isinstance(target_spec["path"], str):
                    raise BoundaryError(f"non-string Cargo target path in {source}")
                target = resolve_repo_path(repo, source, target_spec["path"])
                explicit_target_paths.add(target)
                edge = make_edge(
                    manifest, source, target, "cargo-target", f"{target_kind}[{index}].path"
                )
                if edge:
                    edges.append(edge)
        if package is not None:
            source_dir = PurePosixPath(source).parent

            def implicit_enabled(field: str) -> bool:
                value = package.get(field, True)
                if not isinstance(value, bool):
                    raise BoundaryError(f"package.{field} must be boolean in {source}")
                return value

            implicit_targets: list[tuple[str, str]] = []
            if implicit_enabled("autolib"):
                implicit_targets.append(("lib", (source_dir / "src/lib.rs").as_posix()))
            if implicit_enabled("autobins"):
                implicit_targets.append(("bin", (source_dir / "src/main.rs").as_posix()))
            for target_kind, folder, flag in (
                ("bin", "src/bin", "autobins"),
                ("example", "examples", "autoexamples"),
                ("test", "tests", "autotests"),
                ("bench", "benches", "autobenches"),
            ):
                if not implicit_enabled(flag):
                    continue
                prefix = (source_dir / folder).as_posix().rstrip("/") + "/"
                for candidate in sorted(path for path in files if path.startswith(prefix)):
                    relative = candidate[len(prefix) :]
                    if ("/" not in relative and relative.endswith(".rs")) or (
                        relative.count("/") == 1 and relative.endswith("/main.rs")
                    ):
                        implicit_targets.append((target_kind, candidate))
            for target_kind, target in implicit_targets:
                if target not in files or target in explicit_target_paths:
                    continue
                edge = make_edge(
                    manifest,
                    source,
                    target,
                    "cargo-target",
                    f"implicit {target_kind} target",
                )
                if edge:
                    edges.append(edge)
    return edges


def validate_declared_runtime(repo: Path, manifest: dict[str, Any]) -> None:
    cargo_path = repo / "Cargo.toml"
    try:
        cargo = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BoundaryError(f"cannot parse root Cargo.toml for runtime declarations: {exc}") from exc
    cargo_bins: dict[str, str] = {}
    cargo_manifests = [("Cargo.toml", cargo)]
    workspace = cargo.get("workspace", {})
    if not isinstance(workspace, dict):
        raise BoundaryError("root Cargo workspace has unsupported shape")
    members = workspace.get("members", [])
    if not isinstance(members, list) or any(not isinstance(member, str) for member in members):
        raise BoundaryError("root Cargo workspace members must be a string array")
    for member in members:
        member_manifest = resolve_repo_path(repo, "Cargo.toml", member, folder=True)
        member_manifest = f"{member_manifest}/Cargo.toml"
        owner = owner_of(manifest, member_manifest)
        if owner is None or not owner[1]:
            continue
        try:
            member_cargo = tomllib.loads((repo / member_manifest).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise BoundaryError(
                f"cannot parse selected Cargo manifest {member_manifest}: {exc}"
            ) from exc
        cargo_manifests.append((member_manifest, member_cargo))
    for cargo_source, cargo_document in cargo_manifests:
        raw_bins = cargo_document.get("bin", [])
        if not isinstance(raw_bins, list):
            raise BoundaryError(f"{cargo_source} [[bin]] declarations have unsupported shape")
        for index, value in enumerate(raw_bins):
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("name"), str)
                or not isinstance(value.get("path"), str)
            ):
                raise BoundaryError(
                    f"{cargo_source} bin[{index}] must declare string name and path"
                )
            binary = value["name"]
            path = resolve_repo_path(repo, cargo_source, value["path"])
            if binary in cargo_bins:
                raise BoundaryError(f"runtime binary has duplicate Cargo declarations: {binary}")
            cargo_bins[binary] = path
    features = cargo.get("features")
    if not isinstance(features, dict):
        raise BoundaryError("root Cargo.toml must declare a feature table")

    declared_bins: set[str] = set()
    for component in manifest["components"]:
        for feature in component["features"]:
            if feature not in features:
                raise BoundaryError(
                    f"component {component['id']} declares unknown Cargo feature {feature}"
                )
        for service in component["runtime_services"]:
            owner = owner_of(manifest, service["entrypoint"])
            if owner is None or not owner[1] or owner[0] != component["id"]:
                raise BoundaryError(
                    f"runtime service {service['id']} entrypoint is not selected by its component"
                )
            if service["kind"] == "binary":
                binary = service["id"]
                if cargo_bins.get(binary) != service["entrypoint"]:
                    raise BoundaryError(
                        f"runtime service {binary} does not match selected Cargo [[bin]] path"
                    )
                if binary in declared_bins:
                    raise BoundaryError(f"runtime binary declared more than once: {binary}")
                declared_bins.add(binary)
    for binary, path in cargo_bins.items():
        owner = owner_of(manifest, path)
        if owner is not None and not owner[1] and binary in declared_bins:
            raise BoundaryError(f"held Cargo binary is declared public: {binary}")


def rust_edges(repo: Path, manifest: dict[str, Any], files: set[str]) -> list[Edge]:
    edges: list[Edge] = []
    macro_start = re.compile(r'(?<!["\'])\b(include_str|include_bytes|include)\s*!\s*[({\[]')
    static_macro = re.compile(
        r'(?<!["\'])\b(include_str|include_bytes|include)\s*!\s*'
        r'(?:\(\s*"([^"\\]+)"\s*\)|\{\s*"([^"\\]+)"\s*\}|\[\s*"([^"\\]+)"\s*\])'
    )
    manifest_concat = re.compile(
        r'(?<!["\'])\b(include_str|include_bytes|include)\s*!\s*\(\s*concat\s*!\s*\(\s*env\s*!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"/([^"\\]+)"\s*\)\s*\)'
    )
    embed_start = re.compile(r"#\s*\[\s*folder\s*=")
    static_embed = re.compile(r'#\s*\[\s*folder\s*=\s*"([^"\\]+)"\s*\]')
    path_attribute = re.compile(
        r'#\s*\[\s*(?:r#)?path\s*=\s*"([^"\\]+)"\s*\]\s*'
        r'(?:#\s*\[[^\]]+\]\s*)*'
        r'(?:pub(?:\s*\([^)]*\)\s*|\s+))?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;'
    )
    path_attribute_start = re.compile(r'#\s*\[\s*(?:r#)?path\s*=')
    module = re.compile(
        r"(?m)^\s*(?:pub(?:\s*\([^)]*\)\s*|\s+))?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;"
    )
    generated = re.compile(
        r'\bconst\s+(GENERATED_PATH|TS_PATH)\s*:\s*&str\s*=\s*"([^"\\]+)"\s*;'
    )
    debt_sources = {debt["source_path"] for debt in manifest["transition_debt"]}
    for source in sorted(path for path in files if path.endswith(".rs")):
        owner = owner_of(manifest, source)
        if owner is None or (not owner[1] and source not in debt_sources):
            continue
        file_owned = any(
            raw_selector["kind"] == "file" and raw_selector["path"] == source
            for component in manifest["components"]
            for raw_selector in component["paths"]
        ) or source in debt_sources
        raw = (repo / source).read_text(encoding="utf-8")
        # Legal forms may put arbitrary Rust whitespace/comments around punctuation,
        # but cannot split these identifiers. False positives only cause full lexing.
        identifiers = r"\b(?:include|include_str|include_bytes|folder|path|GENERATED_PATH|TS_PATH)\b"
        if file_owned:
            identifiers = rf"(?:{identifiers}|\bmod\b)"
        if re.search(identifiers, raw) is None:
            continue
        text = strip_rust_comments(raw, source)
        code = strip_rust_comments(raw, source, retain_literals=False)
        if len(macro_start.findall(text)) != len(static_macro.findall(text)) + len(
            manifest_concat.findall(text)
        ):
            raise BoundaryError(f"unsupported dynamic include macro in {source}")
        if len(embed_start.findall(text)) != len(static_embed.findall(text)):
            raise BoundaryError(f"unsupported dynamic RustEmbed folder in {source}")
        for match in static_macro.finditer(text):
            literal = next(group for group in match.groups()[1:] if group is not None)
            target = resolve_repo_path(repo, source, literal)
            evidence = f'{match.group(1)}!("{literal}")'
            edge = make_edge(manifest, source, target, "rust-include", evidence)
            if edge:
                edges.append(edge)
        for match in manifest_concat.finditer(text):
            target = canonical_path(match.group(2), "CARGO_MANIFEST_DIR include target")
            edge = make_edge(manifest, source, target, "rust-include", match.group(0))
            if edge:
                edges.append(edge)
        for match in static_embed.finditer(text):
            # RustEmbed resolves folders from CARGO_MANIFEST_DIR, not the source file.
            target = canonical_path(match.group(1), "RustEmbed folder", tree=True)
            edge = make_edge(manifest, source, target, "rust-embed-folder", match.group(0))
            if edge:
                edges.append(edge)
        attributed_modules: set[str] = set()
        if has_conditional_rust_path_attribute(code, source):
            raise BoundaryError(f"unsupported conditional Rust path attribute in {source}")
        path_matches = [
            match for match in path_attribute.finditer(text) if code[match.start()] == "#"
        ]
        if len(path_attribute_start.findall(code)) != len(path_matches):
            raise BoundaryError(f"unsupported Rust path attribute in {source}")
        for match in path_matches:
            attributed_modules.add(match.group(2))
            target = resolve_repo_path(repo, source, match.group(1))
            edge = make_edge(manifest, source, target, "rust-module", match.group(0))
            if edge:
                edges.append(edge)
        source_posix = PurePosixPath(source)
        is_crate_root = (
            source_posix.name in {"lib.rs", "main.rs"}
            or source_posix.parent.name == "bin"
            or (source_posix.parent.as_posix() == "tests")
        )
        module_base = (
            source_posix.parent
            if source_posix.name == "mod.rs" or is_crate_root
            else source_posix.parent / source_posix.stem
        )
        for match in module.finditer(text) if file_owned else ():
            if match.group(1) in attributed_modules:
                continue
            name = match.group(1)
            candidates = [module_base / f"{name}.rs", module_base / name / "mod.rs"]
            existing = [item.as_posix() for item in candidates if item.as_posix() in files]
            if len(existing) != 1:
                raise BoundaryError(f"cannot resolve Rust module {name} from {source} fail-closed")
            edge = make_edge(manifest, source, existing[0], "rust-module", match.group(0).strip())
            if edge:
                edges.append(edge)
        for match in generated.finditer(text):
            target = canonical_path(match.group(2), "generated output")
            edge = make_edge(
                manifest, source, target, "generated-output", f"const {match.group(1)}"
            )
            if edge:
                edges.append(edge)
    return edges


def validate_dependencies(repo: Path, manifest: dict[str, Any], files: set[str], mode: str) -> None:
    edges = cargo_edges(repo, manifest, files) + rust_edges(repo, manifest, files)
    component_by_id = {item["id"]: item for item in manifest["components"]}
    for item in manifest["exclusions"]:
        component_by_id[item["id"]] = {"permitted_dependencies": []}
    violations: list[Edge] = []
    for edge in edges:
        if edge.source_component == edge.target_component:
            continue
        permitted = component_by_id[edge.source_component]["permitted_dependencies"]
        if edge.target_component not in permitted:
            violations.append(edge)
    actual = {edge.debt_key() for edge in violations}
    expected = {
        (
            debt["source_component"],
            debt["target_component"],
            debt["kind"],
            debt["source_path"],
            debt["target_path"],
            debt["evidence"],
        )
        for debt in manifest["transition_debt"]
    }
    if mode == "target" and manifest["transition_debt"]:
        raise BoundaryError("target mode requires an empty transition debt set")
    if actual != expected:
        missing = sorted(expected - actual)
        added = sorted(actual - expected)
        raise BoundaryError(f"transition debt differs from frozen set; stale={missing}, new={added}")


def validate_repository(repo: Path, manifest: dict[str, Any], mode: str) -> list[dict[str, str]]:
    if mode == "target" and manifest["transition_debt"]:
        raise BoundaryError("target mode requires an empty transition debt set")
    effective_manifest = manifest_for_mode(manifest, mode)
    inventory = upstream_inventory(repo) if mode == "upstream" else target_inventory(repo)
    files = {entry.path for entry in inventory}
    regular_paths = {
        entry.path for entry in inventory if entry.mode in {"100644", "100755"}
    }
    for component in effective_manifest["components"]:
        for raw_selector in component["paths"]:
            selector = Selector(raw_selector["kind"], raw_selector["path"])
            if not any(selector.matches(path) for path in regular_paths):
                perspective = "tracked" if mode == "upstream" else "projected"
                raise BoundaryError(
                    f"selected selector matches no {perspective} blob: "
                    f"{selector.kind}:{selector.path}"
                )
    if mode == "upstream":
        for exclusion in manifest["exclusions"]:
            for raw_selector in exclusion["paths"]:
                selector = Selector(raw_selector["kind"], raw_selector["path"])
                if not any(selector.matches(path) for path in files):
                    raise BoundaryError(
                        "excluded selector matches no tracked entry: "
                        f"{selector.kind}:{selector.path}"
                    )
    projection = project_selection(manifest, inventory, mode)
    for item in projection:
        item["sha256"] = hashlib.sha256((repo / item["path"]).read_bytes()).hexdigest()
    if mode == "upstream":
        analyzed_paths = {item["path"] for item in projection}
        analyzed_paths.update(
            debt["source_path"]
            for debt in manifest["transition_debt"]
            if debt["source_path"] in files
        )
        require_index_worktree_parity(repo, inventory, analyzed_paths)
    validate_selected_paths(effective_manifest, (item["path"] for item in projection))
    if mode == "target":
        selected = {item["path"] for item in projection}
        undeclared = sorted(files - selected)
        if undeclared:
            raise BoundaryError(f"target contains undeclared/forbidden files: {undeclared}")
    selected_dist = {
        item["path"] for item in projection if item["path"].startswith("web/mcp-apps/dist/")
    }
    expected_dist = {
        artifact["path"]
        for component in manifest["components"]
        if component["id"] == "mcp-apps"
        for artifact in component["generated_artifacts"]
    }
    if selected_dist != expected_dist:
        raise BoundaryError("selected MCP App dist files differ from the exact generated artifact set")
    validate_declared_runtime(repo, effective_manifest)
    validate_dependencies(repo, effective_manifest, files, mode)
    return projection


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("native-ce-boundary.json"))
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--mode", choices=("upstream", "target"), default="upstream")
    parser.add_argument("--emit-selection", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest, mode=args.mode)
        projection = validate_repository(args.repo.resolve(), manifest, args.mode)
        encoded = json.dumps(
            {"format": FORMAT, "files": projection}, indent=2, sort_keys=True
        ) + "\n"
        if args.emit_selection:
            args.emit_selection.write_text(encoded, encoding="utf-8")
        else:
            sys.stdout.write(encoded)
    except BoundaryError as exc:
        print(f"source-boundary: refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
