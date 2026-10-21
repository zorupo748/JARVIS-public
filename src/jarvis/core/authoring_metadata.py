"""Build proposal metadata from literal code without importing that code."""

from __future__ import annotations

import ast
import hashlib
import re
import sys
import unicodedata

from jarvis.core.dependency_resolver import DEFAULT_IMPORT_NAMES


def build_initial_metadata(
    source: str, supplied: dict[str, object] | None, user_request: str,
    *, existing_skill_name: str | None = None,
) -> dict[str, object]:
    """Preserve valid declarations and add statically identifiable imports.

    Unknown import roots remain declarations for the existing resolver to check;
    this function does not install or import packages. Syntax errors belong to
    CodeValidation, so they do not prevent construction of the proposal.
    """
    supplied = supplied or {}
    proposed_name = supplied.get("skill_name")
    seed = proposed_name if isinstance(proposed_name, str) and proposed_name.strip() else existing_skill_name or user_request
    name = unicodedata.normalize("NFKD", seed).encode("ascii", "ignore").decode().lower()
    name = re.sub(r"[^a-z0-9]+", "_", name).strip("_") or "generated_skill"
    if not name[0].isalpha():
        name = "skill_" + name
    if len(name) > 64:
        name = name[:55].rstrip("_") + "_" + hashlib.sha256(seed.encode()).hexdigest()[:8]
    summary = supplied.get("implementation_summary")
    if not isinstance(summary, str) or not summary.strip():
        summary = user_request.strip() or "Generated dynamic skill implementation."

    declared = supplied.get("dependencies", [])
    # Malformed declarations are deliberately retained for the strict proposal
    # parser rather than silently dropping an explicit dependency requirement.
    if not isinstance(declared, list) or any(not isinstance(d, str) or not d.strip() for d in declared):
        return {"skill_name": name, "implementation_summary": summary, "dependencies": declared}
    dependencies = list(declared)
    known_names = {_distribution_key(d) for d in dependencies}
    import_to_distribution = {v: k for k, v in DEFAULT_IMPORT_NAMES.items()}
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        tree = None
    roots: set[str] = set()
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    for root in sorted(roots - sys.stdlib_module_names - {"jarvis", "__future__"}):
        distribution = import_to_distribution.get(root, root)
        key = _distribution_key(distribution)
        if key not in known_names:
            dependencies.append(distribution)
            known_names.add(key)
    return {"skill_name": name, "implementation_summary": summary, "dependencies": dependencies}


def _distribution_key(declaration: str) -> str:
    name = re.split(r"[<>=!~\[ ]", declaration, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()
