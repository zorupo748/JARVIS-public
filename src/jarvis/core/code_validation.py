"""Structured local validation for candidate code.

This module deliberately performs static checks and may run only a known unittest
suite under an explicit project root. It is not an operating-system sandbox and it
never executes candidate source directly.
"""

from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
import traceback as traceback_module
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Sequence

from jarvis.core.dynamic_skill_contract import DynamicSkillContractError, validate_entrypoint_signature
from jarvis.core.external_data_requirements import inspect_external_data_source


DEFAULT_CONTROLLED_TEST_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class ValidationCheck:
    name: str
    success: bool
    details: str


@dataclass(frozen=True)
class ValidationReport:
    success: bool
    checks: tuple[ValidationCheck, ...]
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    timed_out: bool = False
    traceback: str | None = None

    def to_prompt_context(self) -> str:
        """Return deterministic JSON for a reviewer prompt without executing code."""

        return json.dumps(
            {
                "success": self.success,
                "checks": [asdict(check) for check in self.checks],
                "stdout": self.stdout,
                "stderr": self.stderr,
                "return_code": self.return_code,
                "timed_out": self.timed_out,
                "traceback": self.traceback,
            },
            ensure_ascii=False,
            sort_keys=True,
        )


class _EntrypointBindings(ast.NodeVisitor):
    """Count module-scope bindings without treating function locals as exports."""

    def __init__(self) -> None:
        self.count = 0

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == "ejecutar_skill" and isinstance(node.ctx, (ast.Store, ast.Del)):
            self.count += 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.count += node.name == "ejecutar_skill"

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def visit_Import(self, node: ast.Import) -> None:
        self.count += sum((alias.asname or alias.name.split(".")[0]) == "ejecutar_skill" for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.count += sum((alias.asname or alias.name) in ("ejecutar_skill", "*") for alias in node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.count += node.name == "ejecutar_skill"
        self.generic_visit(node)


def _scope_nodes(nodes: Sequence[ast.AST]):
    """Walk a function's statements without borrowing nested function returns."""
    for node in nodes:
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield from _scope_nodes(list(ast.iter_child_nodes(node)))


def _literal_command_test(test: ast.AST) -> bool:
    for node in ast.walk(test):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            operands = (node.left, node.comparators[0])
            if (isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn))
                    and any(isinstance(item, ast.Name) and item.id == "comando" for item in operands)
                    and any(isinstance(item, ast.Constant) and isinstance(item.value, str)
                            and item.value.strip() for item in operands)):
                return True
    return False


def _has_operation(nodes: Sequence[ast.AST]) -> bool:
    return any(isinstance(node, ast.Call) and not (
        isinstance(node.func, ast.Name) and node.func.id == "print"
    ) for node in _scope_nodes(nodes))


def _stops_activation(nodes: Sequence[ast.stmt], *, terminal: bool) -> bool:
    if not nodes:
        return False
    last = nodes[-1]
    if isinstance(last, ast.Raise):
        return True
    if isinstance(last, ast.Return):
        return last.value is None or isinstance(last.value, ast.Constant)
    # A terminal diagnostic-only branch returns None implicitly. A print in
    # a branch followed by the common capability is harmless and is not a gate.
    return terminal and all(
        isinstance(node, ast.Pass) or isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "print" for node in nodes
    )


def _dynamic_functional_checks(tree: ast.Module, entry: ast.FunctionDef) -> tuple[ValidationCheck, ...]:
    gate_errors = []
    for index, node in enumerate(entry.body):
        if not isinstance(node, ast.If) or not _literal_command_test(node.test):
            continue
        # If a common operation already ran, a later comparison may just select
        # output formatting; do not reinterpret it as capability activation.
        if _has_operation(entry.body[:index]):
            continue
        tail = entry.body[index + 1:]
        for branch, other in ((node.body, node.orelse), (node.orelse, node.body)):
            last = branch[-1] if branch else None
            explicit_rejection = isinstance(last, ast.Raise) or isinstance(last, ast.Return) and (
                last.value is None or isinstance(last.value, ast.Constant) and (
                    last.value.value is None or isinstance(last.value.value, str) and any(
                        text in last.value.value.casefold()
                        for text in ("comando no reconocido", "unrecognized command", "unsupported command")
                    )
                )
            )
            answer = any(isinstance(item, ast.Return) and item.value is not None
                         and not (isinstance(item.value, ast.Constant) and item.value.value is None)
                         for item in _scope_nodes(other + tail))
            if (_stops_activation(branch, terminal=not tail) and not _has_operation(branch)
                    and (_has_operation(other + tail) or explicit_rejection and answer)):
                gate_errors.append(f"Line {node.lineno}: comando is gated by a literal phrase; "
                                   "execute the selected capability directly and use comando as context.")
                break

    text_errors = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            loops = [(node.target, node.iter, list(node.body))]
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            values = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            loops = [(gen.target, gen.iter, values + gen.ifs) for gen in node.generators]
            # A subsequent generator may shadow the first variable.
            if len(node.generators) != 1:
                continue
        else:
            continue
        for target, iterable, region in loops:
            if (not isinstance(target, ast.Name) or not isinstance(iterable, ast.Call)
                    or not isinstance(iterable.func, ast.Attribute)
                    or iterable.func.attr not in ("split", "splitlines")):
                continue
            nodes = list(_scope_nodes(region))
            # A parsed/reassigned line may now be a dict. Do not infer its type.
            if any(isinstance(item, ast.Name) and item.id == target.id
                   and isinstance(item.ctx, (ast.Store, ast.Del)) for item in nodes):
                continue
            for item in nodes:
                if (isinstance(item, ast.Subscript) and isinstance(item.value, ast.Name)
                        and item.value.id == target.id and isinstance(item.slice, ast.Constant)
                        and isinstance(item.slice.value, str)):
                    text_errors.append(f"Line {item.lineno}: Loop variable {target.id!r} is text from "
                                       f"{iterable.func.attr}() but is indexed with string key {item.slice.value!r}. "
                                       "Use the text line directly or explicitly parse it into a dictionary first.")

    returns_value = any(
        isinstance(node, ast.Return) and node.value is not None
        and not (isinstance(node.value, ast.Constant) and node.value.value is None)
        and not (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "print")
        for node in _scope_nodes(entry.body)
    )
    return (
        ValidationCheck("dynamic_command_gate", not gate_errors,
                        "\n".join(gate_errors) or "No literal phrase activation gate detected."),
        ValidationCheck("dynamic_text_index", not text_errors,
                        "\n".join(text_errors) or "No string-key indexing of direct split/splitlines loop text detected."),
        ValidationCheck("dynamic_result", returns_value,
                        "Entrypoint has a value return." if returns_value else
                        "ejecutar_skill has no return with a value other than None; print() is not a result. "
                        "Return the requested response to JARVIS."),
    )


def with_dynamic_skill_entrypoint_validation(
    report: ValidationReport,
    source: str,
    *,
    filename: str = "<candidate>",
    user_request: str | None = None,
    verified_external_endpoints: tuple[str, ...] | None = None,
    verified_external_source: str | None = None,
) -> ValidationReport:
    """Add AST-only ABI and functional checks to SOURCE, never generated tests."""

    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, TypeError, ValueError):
        # The existing syntax validator owns syntax errors and their diagnostics.
        external_data = inspect_external_data_source(
            source,
            user_request,
            verified_endpoints=verified_external_endpoints,
            verified_source=verified_external_source,
        )
        external_data_check = ValidationCheck(
            "dynamic_external_data",
            external_data.valid,
            external_data.details,
        )
        return replace(
            report,
            success=report.success and external_data_check.success,
            checks=report.checks + (external_data_check,),
        )
    try:
        entries = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "ejecutar_skill"]
        if len(entries) != 1:
            raise DynamicSkillContractError("Define exactly one module-level synchronous function ejecutar_skill")
        entry = entries[0]
        bindings = _EntrypointBindings()
        bindings.visit(tree)
        if bindings.count != 1 or entry.decorator_list:
            raise DynamicSkillContractError("ejecutar_skill must not be decorated, replaced, or rebound")
        # Skip nested function/class bodies when checking whether this entrypoint
        # itself yields, so a local generator helper remains allowed.
        pending = list(entry.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                raise DynamicSkillContractError("ejecutar_skill must not be a generator")
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                pending.extend(ast.iter_child_nodes(node))
        positional = entry.args.posonlyargs + entry.args.args
        required_count = len(positional) - len(entry.args.defaults)
        parameters = [
            inspect.Parameter(
                item.arg,
                inspect.Parameter.POSITIONAL_ONLY if index < len(entry.args.posonlyargs)
                else inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=inspect.Parameter.empty if index < required_count else None,
            ) for index, item in enumerate(positional)
        ]
        if entry.args.vararg:
            parameters.append(inspect.Parameter(entry.args.vararg.arg, inspect.Parameter.VAR_POSITIONAL))
        parameters.extend(
            inspect.Parameter(item.arg, inspect.Parameter.KEYWORD_ONLY,
                              default=inspect.Parameter.empty if default is None else None)
            for item, default in zip(entry.args.kwonlyargs, entry.args.kw_defaults)
        )
        if entry.args.kwarg:
            parameters.append(inspect.Parameter(entry.args.kwarg.arg, inspect.Parameter.VAR_KEYWORD))
        validate_entrypoint_signature(inspect.Signature(parameters))
    except (DynamicSkillContractError, ValueError) as exc:
        check = ValidationCheck("dynamic_entrypoint", False, f"DynamicSkillContractError: {exc}")
    else:
        check = ValidationCheck("dynamic_entrypoint", True, "ejecutar_skill is compatible with the comando ABI.")
    functional = _dynamic_functional_checks(tree, entry) if check.success else ()
    persistence_check = _persistent_state_usage_check(tree, user_request)
    external_data = inspect_external_data_source(
        source,
        user_request,
        verified_endpoints=verified_external_endpoints,
        verified_source=verified_external_source,
    )
    external_data_check = ValidationCheck(
        "dynamic_external_data",
        external_data.valid,
        external_data.details,
    )
    return replace(
        report,
        success=report.success and check.success and all(item.success for item in functional)
        and persistence_check.success and external_data_check.success,
        checks=report.checks + functional + (persistence_check, external_data_check, check),
    )


def _persistent_state_usage_check(
    tree: ast.Module,
    user_request: str | None,
) -> ValidationCheck:
    request_text = " ".join((user_request or "").casefold().split())
    persistence_requested = any(
        phrase in request_text
        for phrase in (
            "persist",
            "entre ejecuciones",
            "entre sesiones",
            "entre llamadas",
            "future executions",
            "across executions",
            "between executions",
            "future runs",
            "across runs",
            "between runs",
            "future invocations",
            "remember between",
            "remember across",
            "remember previous",
            "recuerda consultas anteriores",
            "memoria entre ejecuciones",
            "cross-execution state",
            "initial state may validly be {}",
        )
    )
    if not persistence_requested:
        return ValidationCheck(
            "dynamic_persistence_state",
            True,
            "No cross-execution persistence requirement was detected.",
        )

    invalid_patterns = []
    direct_state_reads: set[str] = set()
    guarded_state_keys: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "ejecutar_skill"
            and (node.attr == "__dict__" or isinstance(node.ctx, ast.Store))
        ):
            invalid_patterns.append(node.lineno)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "estado"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
            and isinstance(node.ctx, ast.Load)
        ):
            direct_state_reads.add(node.slice.value)
        if isinstance(node, ast.Compare):
            operands = (node.left, *node.comparators)
            if any(isinstance(item, ast.Name) and item.id == "estado" for item in operands):
                guarded_state_keys.update(
                    item.value for item in operands
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                )
    if invalid_patterns:
        lines = ", ".join(str(line) for line in sorted(set(invalid_patterns)))
        return ValidationCheck(
            "dynamic_persistence_state",
            False,
            "Function attributes do not persist across subprocess executions; use the central estado ABI. "
            f"Suspicious ejecutar_skill attribute usage on line(s): {lines}.",
        )
    unguarded_state_keys = sorted(direct_state_reads - guarded_state_keys)
    if unguarded_state_keys:
        keys = ", ".join(repr(key) for key in unguarded_state_keys)
        return ValidationCheck(
            "dynamic_persistence_state",
            False,
            "The initial central state may be {}; direct estado[key] access can raise KeyError. "
            f"Use .get(), a membership check, or initialize the key before reading it: {keys}.",
        )
    return ValidationCheck(
        "dynamic_persistence_state",
        True,
        "No function-attribute persistence pattern was detected.",
    )


class LocalCodeValidator:
    """Perform safe static validation and controlled known-test execution.

    ``run_controlled_unittest`` runs only Python's unittest discovery inside the
    project's own ``tests`` directory. Callers still decide which trusted test
    pattern is appropriate; this is a containment boundary, not a sandbox.
    """

    def validate_python_source(
        self,
        source: str,
        *,
        filename: str = "<candidate>",
    ) -> ValidationReport:
        """Parse and compile source in memory without importing or executing it."""

        checks: list[ValidationCheck] = []
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, TypeError, ValueError) as exc:
            details = f"AST parse failed: {exc}"
            checks.append(ValidationCheck("ast_parse", False, details))
            checks.append(
                ValidationCheck(
                    "in_memory_compile",
                    False,
                    "Skipped because AST parsing failed.",
                )
            )
            return self._report(checks, traceback=traceback_module.format_exc())

        checks.append(ValidationCheck("ast_parse", True, "AST parsed successfully."))
        try:
            compile(tree, filename, "exec")
        except (SyntaxError, TypeError, ValueError) as exc:
            checks.append(
                ValidationCheck("in_memory_compile", False, f"Compilation failed: {exc}")
            )
            return self._report(checks, traceback=traceback_module.format_exc())

        checks.append(
            ValidationCheck(
                "in_memory_compile",
                True,
                "Compilation succeeded without importing or executing source.",
            )
        )
        return self._report(checks)

    def validate_dynamic_skill_source(
        self,
        source: str,
        *,
        filename: str = "<candidate>",
        user_request: str | None = None,
    ) -> ValidationReport:
        report = self.validate_python_source(source, filename=filename)
        return with_dynamic_skill_entrypoint_validation(
            report,
            source,
            filename=filename,
            user_request=user_request,
        )

    def run_controlled_unittest(
        self,
        *,
        project_root: Path | str,
        pattern: str,
        timeout_seconds: float = DEFAULT_CONTROLLED_TEST_TIMEOUT_SECONDS,
    ) -> ValidationReport:
        """Run a known unittest pattern with no shell and a bounded timeout.

        The command is fixed to ``python -B -m unittest discover`` and discovery
        is constrained to ``<project_root>/tests``. Candidate source is never
        passed to the interpreter as a command or imported by this method.
        """

        root = Path(project_root).resolve()
        tests_dir = (root / "tests").resolve()
        self._validate_controlled_test_request(root, tests_dir, pattern, timeout_seconds)
        command: Sequence[str] = (
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(tests_dir),
            "-p",
            pattern,
            "-v",
        )
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = self._as_text(exc.stdout)
            stderr = self._as_text(exc.stderr)
            checks = (
                ValidationCheck(
                    "controlled_unittest",
                    False,
                    f"Timed out after {timeout_seconds:g} seconds.",
                ),
            )
            return self._report(
                checks,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
                traceback=traceback_module.format_exc(),
            )
        except OSError as exc:
            checks = (
                ValidationCheck("controlled_unittest", False, f"Could not start: {exc}"),
            )
            return self._report(
                checks,
                stderr=str(exc),
                traceback=traceback_module.format_exc(),
            )

        success = completed.returncode == 0
        checks = (
            ValidationCheck(
                "controlled_unittest",
                success,
                "Known test suite passed."
                if success
                else f"Known test suite failed with return code {completed.returncode}.",
            ),
        )
        return self._report(
            checks,
            stdout=completed.stdout,
            stderr=completed.stderr,
            return_code=completed.returncode,
        )

    @staticmethod
    def _validate_controlled_test_request(
        root: Path,
        tests_dir: Path,
        pattern: str,
        timeout_seconds: float,
    ) -> None:
        if not root.is_dir():
            raise ValueError("project_root must be an existing directory")
        try:
            tests_dir.relative_to(root)
        except ValueError as exc:
            raise ValueError("tests directory must remain within project_root") from exc
        if not tests_dir.is_dir():
            raise ValueError("project_root must contain a tests directory")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("pattern must be a non-empty unittest pattern")
        if "/" in pattern or "\\" in pattern or ".." in pattern:
            raise ValueError("pattern must not contain a path")
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    @staticmethod
    def _as_text(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    @staticmethod
    def _report(
        checks: Sequence[ValidationCheck],
        *,
        stdout: str = "",
        stderr: str = "",
        return_code: int | None = None,
        timed_out: bool = False,
        traceback: str | None = None,
    ) -> ValidationReport:
        return ValidationReport(
            success=all(check.success for check in checks) and not timed_out,
            checks=tuple(checks),
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            timed_out=timed_out,
            traceback=traceback,
        )


__all__ = [
    "DEFAULT_CONTROLLED_TEST_TIMEOUT_SECONDS",
    "LocalCodeValidator",
    "ValidationCheck",
    "ValidationReport",
    "with_dynamic_skill_entrypoint_validation",
]
