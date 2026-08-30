from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.interfaces import GovernanceValidationResult

GOVERNANCE_DOMAIN_MODULES: dict[str, str] = {
    "interfaces": "governance.interfaces",
    "evidence": "governance.evidence",
    "chronology": "governance.chronology",
    "timestamping": "governance.timestamping",
    "trust_policy": "governance.trust_policy",
}

ALLOWED_GOVERNANCE_IMPORTS: dict[str, tuple[str, ...]] = {
    "interfaces": (),
    "evidence": ("governance.interfaces",),
    "chronology": ("governance.interfaces",),
    "timestamping": ("governance.interfaces",),
    "trust_policy": ("governance.interfaces",),
}

FORBIDDEN_RUNTIME_IMPORT_PREFIXES = (
    "audit",
    "gateway",
    "scripts",
    "security",
    "simulation_governance",
)


@dataclass(frozen=True)
class GovernanceDependencyMap:
    """Deterministic dependency graph for governance boundary modules."""

    nodes: tuple[str, ...]
    edges: tuple[tuple[str, str], ...]
    graph_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "edges": [{"source": source, "target": target} for source, target in self.edges],
            "graph_hash": self.graph_hash,
        }


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _source_for_module(root: Path, module_name: str, module_sources: dict[str, str] | None) -> str:
    if module_sources is not None and module_name in module_sources:
        return module_sources[module_name]
    relative = Path(*module_name.split(".")).with_suffix(".py")
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(str(path))
    return path.read_text(encoding="utf-8")


def _imported_modules(source: str) -> tuple[str, ...]:
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return tuple(sorted(imports))


def _governance_target(import_name: str) -> str | None:
    if import_name == "governance":
        return import_name
    if import_name.startswith("governance."):
        parts = import_name.split(".")
        if len(parts) >= 2:
            return ".".join(parts[:2])
    return None


def _has_cycle(edges: tuple[tuple[str, str], ...]) -> bool:
    adjacency: dict[str, list[str]] = {}
    for source, target in edges:
        adjacency.setdefault(source, []).append(target)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for next_node in adjacency.get(node, []):
            if visit(next_node):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in adjacency)


def build_governance_dependency_map(
    root: Path,
    *,
    module_sources: dict[str, str] | None = None,
) -> GovernanceDependencyMap:
    """Build a deterministic graph for the isolated governance domains.

    Governance scope: reads source text and records imports between explicit
    governance domains only. It never imports analyzed modules dynamically.
    Fail-closed expectation: callers must deny validation if graph validation
    returns any failure.
    Sensitive-data handling: source import analysis only; no evidence payloads
    or signing material are read.
    """

    nodes = tuple(sorted(GOVERNANCE_DOMAIN_MODULES.values()))
    edges: set[tuple[str, str]] = set()
    for module_name in nodes:
        source = _source_for_module(root, module_name, module_sources)
        for imported in _imported_modules(source):
            target = _governance_target(imported)
            if target in nodes:
                edges.add((module_name, target))
    ordered_edges = tuple(sorted(edges))
    graph_payload = {"nodes": list(nodes), "edges": [{"source": source, "target": target} for source, target in ordered_edges]}
    graph_hash = hashlib.sha256(_canonical_json(graph_payload).encode("utf-8")).hexdigest()
    return GovernanceDependencyMap(nodes=nodes, edges=ordered_edges, graph_hash=graph_hash)


def validate_governance_dependency_map(
    root: Path,
    *,
    module_sources: dict[str, str] | None = None,
    expected_graph_hash: str | None = None,
) -> GovernanceValidationResult:
    failures: list[str] = []
    try:
        graph = build_governance_dependency_map(root, module_sources=module_sources)
    except Exception:
        return GovernanceValidationResult(False, ("GOVERNANCE_DEPENDENCY_MAP_UNAVAILABLE",))

    allowed_by_module = {
        GOVERNANCE_DOMAIN_MODULES[domain]: set(allowed)
        for domain, allowed in ALLOWED_GOVERNANCE_IMPORTS.items()
    }
    source_imports: dict[str, tuple[str, ...]] = {}
    for module_name in graph.nodes:
        try:
            source_imports[module_name] = _imported_modules(_source_for_module(root, module_name, module_sources))
        except Exception:
            failures.append(f"GOVERNANCE_DEPENDENCY_SOURCE_UNAVAILABLE:{module_name}")
            continue
        for imported in source_imports[module_name]:
            if imported.split(".")[0] in FORBIDDEN_RUNTIME_IMPORT_PREFIXES:
                failures.append(f"GOVERNANCE_RUNTIME_COUPLING_FORBIDDEN:{module_name}:{imported}")

    for source, target in graph.edges:
        if target not in allowed_by_module.get(source, set()):
            failures.append(f"GOVERNANCE_FORBIDDEN_DOMAIN_IMPORT:{source}:{target}")
    if _has_cycle(graph.edges):
        failures.append("GOVERNANCE_CIRCULAR_IMPORT_DETECTED")
    if expected_graph_hash is not None and graph.graph_hash != expected_graph_hash:
        failures.append("GOVERNANCE_DEPENDENCY_GRAPH_DRIFT")

    return GovernanceValidationResult(
        valid=not failures,
        failures=tuple(sorted(set(failures))),
        metadata={
            "dependency_graph": graph.to_dict(),
            "artifact_counts": {
                "modules": len(graph.nodes),
                "edges": len(graph.edges),
                "source_imports": sum(len(imports) for imports in source_imports.values()),
            },
        },
    )
