from __future__ import annotations

import importlib.metadata
import subprocess
import unittest
from unittest.mock import patch

from jarvis.core.dependency_resolver import (
    DependencyResolver,
    DependencyStatus,
    dependency_block_message,
)


def resolver(
    installed: dict[str, str] | None = None,
    modules: set[str] | None = None,
    mappings: dict[str, str] | None = None,
) -> DependencyResolver:
    installed = installed or {}
    modules = modules or set()

    def version(name: str) -> str:
        if name.lower() not in installed:
            raise importlib.metadata.PackageNotFoundError(name)
        return installed[name.lower()]

    return DependencyResolver(
        distribution_version=version,
        find_spec=lambda name: object() if name in modules else None,
        packages_distributions=lambda: {},
        import_names=mappings,
    )


class DependencyResolverTests(unittest.TestCase):
    def test_installed_requests_legacy_declaration_is_available(self) -> None:
        result = resolver({"requests": "2.34.2"}, {"requests"}).resolve("requests")
        self.assertEqual(result.status, DependencyStatus.AVAILABLE)
        self.assertEqual(result.declaration.distribution_name, "requests")
        self.assertEqual(result.declaration.import_name, "requests")
        self.assertEqual(result.installed_version, "2.34.2")
        self.assertNotIn("falta", dependency_block_message((result,), ()))

    def test_missing_and_mixed_dependencies(self) -> None:
        checker = resolver({"requests": "2.34.2"}, {"requests"})
        results = checker.resolve_many(("requests", "never-installed-package"))
        self.assertEqual([item.status for item in results], [
            DependencyStatus.AVAILABLE, DependencyStatus.MISSING,
        ])
        self.assertEqual(
            dependency_block_message(results, ("never-installed-package",)),
            "La skill está preparada, pero falta la dependencia 'never-installed-package'.",
        )
        self.assertNotIn("requests", dependency_block_message(results, ("never-installed-package",)))

    def test_multiple_available_dependencies_do_not_block(self) -> None:
        checker = resolver(
            {"requests": "2.34.2", "beautifulsoup4": "4.13.0"},
            {"requests", "bs4"},
        )
        results = checker.resolve_many(("requests", "beautifulsoup4", "json"))
        self.assertTrue(all(item.status is DependencyStatus.AVAILABLE for item in results))

    def test_stdlib_is_available_without_distribution_lookup(self) -> None:
        checker = resolver()
        for name in ("json", "pathlib", "datetime", "re"):
            with self.subTest(name=name):
                self.assertEqual(checker.resolve(name).status, DependencyStatus.AVAILABLE)

    def test_known_distribution_import_name_mappings(self) -> None:
        checker = resolver(
            {"beautifulsoup4": "4.13.0", "pyyaml": "6.0", "pillow": "11.0"},
            {"bs4", "yaml", "PIL"},
        )
        for distribution, module in (
            ("beautifulsoup4", "bs4"), ("PyYAML", "yaml"), ("Pillow", "PIL"),
        ):
            with self.subTest(distribution=distribution):
                result = checker.resolve(distribution)
                self.assertEqual(result.status, DependencyStatus.AVAILABLE)
                self.assertEqual(result.declaration.import_name, module)

    def test_extensible_mapping_and_installed_metadata_mapping(self) -> None:
        checker = resolver({"custom-dist": "1.0"}, {"custom_module"}, {"custom-dist": "custom_module"})
        self.assertEqual(checker.resolve("custom-dist").status, DependencyStatus.AVAILABLE)
        inferred = DependencyResolver(
            distribution_version=lambda _name: "1.0",
            find_spec=lambda name: object() if name == "metadata_module" else None,
            packages_distributions=lambda: {"metadata_module": ["other-dist"]},
        )
        self.assertEqual(inferred.resolve("other-dist").declaration.import_name, "metadata_module")

    def test_version_compatible_and_incompatible(self) -> None:
        checker = resolver({"requests": "2.34.2"}, {"requests"})
        compatible = checker.resolve("requests>=2.30,<3")
        incompatible = checker.resolve("requests>=3.0")
        self.assertEqual(compatible.status, DependencyStatus.AVAILABLE)
        self.assertEqual(compatible.required_version, ">=2.30,<3")
        self.assertEqual(incompatible.status, DependencyStatus.INCOMPATIBLE)
        self.assertEqual(incompatible.installed_version, "2.34.2")

    def test_installed_distribution_without_module_is_missing(self) -> None:
        result = resolver({"requests": "2.34.2"}).resolve("requests")
        self.assertEqual(result.status, DependencyStatus.MISSING)
        self.assertIn("import module", result.reason)

    def test_unsupported_version_format_fails_closed(self) -> None:
        result = resolver({"requests": "2.34.2rc1"}, {"requests"}).resolve("requests>=2.30")
        self.assertEqual(result.status, DependencyStatus.INVALID_UNSUPPORTED)

    def test_invalid_urls_git_flags_paths_and_commands(self) -> None:
        checker = resolver()
        for declaration in (
            "bad name",
            "https://example.invalid/pkg.whl", "git+https://example.invalid/repo",
            "-r requirements.txt", "--index-url=example.invalid", "../local-pkg",
            r"C:\\local-pkg", "requests; echo unsafe", "requests && whoami",
        ):
            with self.subTest(declaration=declaration):
                self.assertEqual(checker.resolve(declaration).status, DependencyStatus.INVALID_UNSUPPORTED)

    def test_resolver_never_imports_module_or_starts_process(self) -> None:
        checker = resolver({"requests": "2.34.2"}, {"requests"})
        with patch("importlib.import_module", side_effect=AssertionError("imported")), patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess")
        ), patch.object(subprocess, "Popen", side_effect=AssertionError("pip")):
            self.assertEqual(checker.resolve("requests").status, DependencyStatus.AVAILABLE)


if __name__ == "__main__":
    unittest.main()
