"""Read-only resolution of declarative skill dependencies in this interpreter.

This is not an installer. It never imports the declared package or invokes pip.
Only simple numeric version comparisons are supported; unsupported declarations
fail closed instead of being passed to a package manager.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping


_NAME = r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*"
_CLAIM = re.compile(rf"^(?P<name>{_NAME})(?P<spec>(?:(?:==|!=|>=|<=|>|<)[0-9]+(?:\.[0-9]+)*(?:,(?:==|!=|>=|<=|>|<)[0-9]+(?:\.[0-9]+)*)*)?)$")
_COMPARISON = re.compile(r"(==|!=|>=|<=|>|<)([0-9]+(?:\.[0-9]+)*)")
_INSTALLED_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")

# Overrides are extensible by the caller. For other distributions the installed
# metadata is consulted before trying the conventional distribution name.
DEFAULT_IMPORT_NAMES: Mapping[str, str] = {
    "beautifulsoup4": "bs4",
    "pyyaml": "yaml",
    "pillow": "PIL",
    "python-dateutil": "dateutil",
}


class DependencyStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    INCOMPATIBLE = "incompatible"
    INVALID_UNSUPPORTED = "invalid/unsupported"


@dataclass(frozen=True)
class DependencyDeclaration:
    distribution_name: str
    import_name: str
    version_spec: str | None = None


@dataclass(frozen=True)
class DependencyResolution:
    dependency: str
    status: DependencyStatus
    reason: str
    declaration: DependencyDeclaration | None = None
    installed_version: str | None = None
    required_version: str | None = None


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not _INSTALLED_VERSION.fullmatch(value):
        return None
    return tuple(int(part) for part in value.split("."))


def _version_satisfies(installed: str, specification: str) -> bool | None:
    actual = _numeric_version(installed)
    if actual is None:
        return None
    for item in specification.split(","):
        match = _COMPARISON.fullmatch(item)
        if match is None:
            return None
        operator, required_text = match.groups()
        required = _numeric_version(required_text)
        if required is None:
            return None
        length = max(len(actual), len(required))
        left = actual + (0,) * (length - len(actual))
        right = required + (0,) * (length - len(required))
        matches = {
            "==": left == right,
            "!=": left != right,
            ">=": left >= right,
            "<=": left <= right,
            ">": left > right,
            "<": left < right,
        }
        if not matches[operator]:
            return False
    return True


class DependencyResolver:
    """Resolve packages using installed metadata and top-level module specs."""

    def __init__(
        self,
        *,
        import_names: Mapping[str, str] | None = None,
        distribution_version: Callable[[str], str] | None = None,
        find_spec: Callable[[str], object | None] | None = None,
        packages_distributions: Callable[[], Mapping[str, list[str]]] | None = None,
    ) -> None:
        names = dict(DEFAULT_IMPORT_NAMES)
        if import_names:
            names.update({_canonical_name(key): value for key, value in import_names.items()})
        if any(not name.isidentifier() or "." in name for name in names.values()):
            raise ValueError("Import-name overrides must be top-level module identifiers.")
        self._import_names = names
        self._distribution_version = distribution_version or importlib.metadata.version
        self._find_spec = find_spec or importlib.util.find_spec
        self._packages_distributions = packages_distributions or importlib.metadata.packages_distributions

    def _import_name(self, distribution_name: str) -> str | None:
        canonical = _canonical_name(distribution_name)
        if canonical in self._import_names:
            return self._import_names[canonical]
        candidates = {
            module for module, distributions in self._packages_distributions().items()
            if module.isidentifier() and "." not in module
            and any(_canonical_name(item) == canonical for item in distributions)
        }
        conventional = distribution_name.replace("-", "_").replace(".", "_")
        if conventional in candidates:
            return conventional
        if len(candidates) == 1:
            return next(iter(candidates))
        if not candidates and conventional.isidentifier():
            return conventional
        return None

    def resolve(self, dependency: str) -> DependencyResolution:
        if not isinstance(dependency, str) or not dependency or dependency != dependency.strip():
            return DependencyResolution(str(dependency), DependencyStatus.INVALID_UNSUPPORTED, "Invalid package declaration.")
        match = _CLAIM.fullmatch(dependency)
        if match is None:
            return DependencyResolution(dependency, DependencyStatus.INVALID_UNSUPPORTED, "Only package names and simple numeric version comparisons are supported.")
        distribution_name = match.group("name")
        version_spec = match.group("spec") or None
        required = version_spec
        if distribution_name.lower() in sys.stdlib_module_names:
            if version_spec is not None:
                return DependencyResolution(dependency, DependencyStatus.INVALID_UNSUPPORTED, "Standard-library modules cannot have package version requirements.", required_version=required)
            declaration = DependencyDeclaration(distribution_name, distribution_name)
            return DependencyResolution(dependency, DependencyStatus.AVAILABLE, "Python standard-library module.", declaration)
        try:
            installed_version = self._distribution_version(distribution_name)
        except importlib.metadata.PackageNotFoundError:
            return DependencyResolution(dependency, DependencyStatus.MISSING, "Distribution is not installed.", required_version=required)
        except Exception:
            return DependencyResolution(dependency, DependencyStatus.INVALID_UNSUPPORTED, "Installed distribution metadata could not be read.", required_version=required)
        import_name = self._import_name(distribution_name)
        if import_name is None:
            return DependencyResolution(dependency, DependencyStatus.INVALID_UNSUPPORTED, "Import name is ambiguous; provide a trusted mapping.", installed_version=installed_version, required_version=required)
        declaration = DependencyDeclaration(distribution_name, import_name, version_spec)
        try:
            module_spec = self._find_spec(import_name)
        except Exception:
            module_spec = None
        if module_spec is None:
            return DependencyResolution(dependency, DependencyStatus.MISSING, "Distribution is installed but its import module is unavailable.", declaration, installed_version, required)
        if version_spec is not None:
            compatible = _version_satisfies(installed_version, version_spec)
            if compatible is None:
                return DependencyResolution(dependency, DependencyStatus.INVALID_UNSUPPORTED, "Installed or requested version format is unsupported.", declaration, installed_version, required)
            if not compatible:
                return DependencyResolution(dependency, DependencyStatus.INCOMPATIBLE, "Installed version does not satisfy the requirement.", declaration, installed_version, required)
        return DependencyResolution(dependency, DependencyStatus.AVAILABLE, "Installed distribution and import module are available.", declaration, installed_version, required)

    def resolve_many(self, dependencies: tuple[str, ...] | list[str]) -> tuple[DependencyResolution, ...]:
        return tuple(self.resolve(dependency) for dependency in dependencies)


def dependency_block_message(
    results: tuple[DependencyResolution, ...],
    unavailable: tuple[str, ...],
) -> str:
    """Give the user a short reason without treating declarations as missing."""

    blocked = [result for result in results if result.status is not DependencyStatus.AVAILABLE]
    if len(blocked) == 1:
        item = blocked[0]
        name = item.declaration.distribution_name if item.declaration else item.dependency[:80]
        if item.status is DependencyStatus.MISSING:
            return f"La skill está preparada, pero falta la dependencia '{name}'."
        if item.status is DependencyStatus.INCOMPATIBLE:
            return f"La skill está preparada, pero la versión instalada de '{name}' no cumple {item.required_version}."
        return f"La skill está preparada, pero la declaración de dependencia '{name}' no es válida o no está admitida."
    names = ", ".join(item[:80] for item in unavailable)
    return f"La skill está preparada, pero hay dependencias ausentes, incompatibles o no admitidas: {names}."


__all__ = [
    "DependencyDeclaration", "DependencyResolution", "DependencyResolver",
    "DependencyStatus", "dependency_block_message",
]
