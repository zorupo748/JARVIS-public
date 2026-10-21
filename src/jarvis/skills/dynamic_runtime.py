"""Runtime loader for explicitly enabled historical dynamic skills.

This module is not a sandbox. The safe execution boundary must verify policy,
metadata, and hash before invoking its internal authorized primitive.
"""

from __future__ import annotations

import importlib.util
import inspect
import traceback
from pathlib import Path
from typing import Mapping

from jarvis.core.config import DYNAMIC_SKILLS_DISABLED_MESSAGE, dynamic_skills_enabled
from jarvis.core.dynamic_skill_contract import DynamicSkillContractError, prepare_entrypoint_call


class DynamicSkillsDisabledError(PermissionError):
    """Raised when an operation attempts to load a dynamic skill while disabled."""


class DynamicSkillAuthorizationRequiredError(DynamicSkillsDisabledError):
    """Raised when a legacy caller bypasses the safe execution boundary."""


class DynamicSkillEntrypointError(RuntimeError):
    """Structured exception raised only when installed entrypoint code fails."""

    def __init__(self, error_type: str, message: str, traceback_text: str) -> None:
        self.error_type = error_type
        self.original_message = message
        self.traceback_text = traceback_text
        super().__init__(f"{error_type}: {message}")


def _invoke_entrypoint(entrypoint, arguments: Mapping[str, object]) -> object:
    try:
        return entrypoint(**arguments)
    except Exception as exc:
        raise DynamicSkillEntrypointError(
            type(exc).__name__,
            str(exc),
            traceback.format_exc(),
        ) from exc


def execute_existing_dynamic_skill(
    nombre: str,
    dynamic_dir: Path,
    parameters: Mapping[str, object] | None = None,
) -> object:
    """Fail closed for legacy direct execution requests.

    Dynamic artifacts may only be invoked after the safe execution service has
    verified deployment metadata, source hash and PolicyCore authorization.
    This compatibility function cannot bypass the authorized execution service.
    """

    del nombre, dynamic_dir, parameters
    raise DynamicSkillAuthorizationRequiredError(
        f"{DYNAMIC_SKILLS_DISABLED_MESSAGE} La ejecucion directa requiere la ruta autorizada."
    )


def _execute_authorized_dynamic_skill(
    nombre: str,
    dynamic_dir: Path,
    parameters: Mapping[str, object] | None = None,
) -> object:
    """Load an artifact only from the parent-authorized child worker.

    This internal primitive is not a public execution API or an operating-system
    sandbox. The parent verifies policy and metadata; the worker rechecks the
    source hash immediately before reaching this function.
    """

    if not dynamic_skills_enabled():
        raise DynamicSkillsDisabledError(DYNAMIC_SKILLS_DISABLED_MESSAGE)
    if not isinstance(nombre, str) or not nombre:
        raise ValueError("El nombre de la skill dinamica debe ser texto no vacio.")
    safe_parameters = dict(parameters or {})
    if any(not isinstance(key, str) for key in safe_parameters):
        raise TypeError("Los parametros de una skill dinamica deben tener claves de texto.")

    root = dynamic_dir.resolve()
    ruta = (root / f"{nombre}.py").resolve()
    try:
        ruta.relative_to(root)
    except ValueError as exc:
        raise ValueError("La ruta de la skill dinamica queda fuera del directorio permitido.") from exc

    spec = importlib.util.spec_from_file_location(f"dynamic_{nombre}", ruta)
    if spec is None or spec.loader is None:
        raise ImportError(f"No se pudo preparar la skill '{nombre}'.")

    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)

    if "ejecutar_skill" in vars(modulo):
        entrada = modulo.ejecutar_skill
        if not inspect.isfunction(entrada) or entrada.__module__ != modulo.__name__:
            raise DynamicSkillContractError("ejecutar_skill must be a Python function defined by the skill")
        arguments = prepare_entrypoint_call(entrada, safe_parameters)
        return _invoke_entrypoint(entrada, arguments)

    for nombre_entrada in ("run", "main"):
        entrada = getattr(modulo, nombre_entrada, None)
        if callable(entrada):
            arguments = prepare_entrypoint_call(entrada, safe_parameters)
            return _invoke_entrypoint(entrada, arguments)

    funciones_publicas = [
        funcion
        for funcion in vars(modulo).values()
        if inspect.isfunction(funcion)
        and funcion.__module__ == modulo.__name__
        and not funcion.__name__.startswith("_")
    ]
    if funciones_publicas:
        entrada = funciones_publicas[0]
        arguments = prepare_entrypoint_call(entrada, safe_parameters)
        return _invoke_entrypoint(entrada, arguments)
    raise AttributeError(f"La skill '{nombre}' no tiene una funcion ejecutable.")
