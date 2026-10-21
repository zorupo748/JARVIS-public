"""Centralized exception handling, model-based triage, and user routing for skills.

Intercepts failures during skill authoring and execution, conducts architectural
triage via reasoning/coding models, attempts self-repair when feasible, and
guarantees clean, 1-paragraph executive summaries in Spanish without technical traces
or internal file paths.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

_PATH_PATTERN = re.compile(
    r"""(?xi)
    (?:[a-zA-Z]:[\\/][^ \r\n,;'"<>]+)|
    (?:/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+)
    """
)

_TRACEBACK_PATTERN = re.compile(
    r"""(?xi)
    Traceback\s+\(most\s+recent\s+call\s+last\):.*?(?=(?:[A-Z][a-zA-Z0-9_.]*Error|[A-Z][a-zA-Z0-9_.]*Exception):\s*|\Z)
    """,
    re.DOTALL,
)

_EXCEPTION_CLASS_PATTERN = re.compile(
    r"""^(?:[a-zA-Z0-9_.]*(?:Error|Exception|FailureKind)):\s*"""
)


def sanitize_error_text(error: object) -> str:
    """Strip internal file paths, stack traces, and raw exception prefixes."""
    if error is None:
        return "error desconocido"
    raw = str(error).strip()
    if not raw:
        return "error sin detalle"

    # Remove python traceback blocks
    cleaned = _TRACEBACK_PATTERN.sub("", raw).strip()

    # Remove internal file paths
    cleaned = _PATH_PATTERN.sub("<ruta_interna>", cleaned)

    # Remove lines that look like File "...", line X, in Y
    lines = []
    for line in cleaned.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("File \"") or line_stripped.startswith("line "):
            continue
        lines.append(line)
    cleaned = " ".join(lines).strip()

    # Remove exception class prefix if present
    cleaned = _EXCEPTION_CLASS_PATTERN.sub("", cleaned).strip()

    # Normalize whitespace
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned or "error en la operación de la skill"


def clean_executive_summary(text: str) -> str:
    """Ensure the executive summary is a single paragraph without leaked technical traces."""
    if not text or not isinstance(text, str):
        return (
            "No ha sido posible completar la operación debido a una incidencia técnica. "
            "Como alternativa, puedes intentar la acción por los canales habituales o verificar los datos facilitados."
        )

    # Remove internal file paths and raw exceptions
    cleaned = _PATH_PATTERN.sub("", text)
    cleaned = _EXCEPTION_CLASS_PATTERN.sub("", cleaned)
    cleaned = re.sub(r"Traceback.*?\n", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"\b(?:ValueError|RuntimeError|TypeError|OSError|KeyError)\b:?", "", cleaned)

    # Flatten to single paragraph
    paragraph = " ".join(part.strip() for part in cleaned.splitlines() if part.strip())
    paragraph = re.sub(r"\s+", " ", paragraph).strip()

    if not paragraph:
        return (
            "No ha sido posible completar la operación debido a una limitación en el procesamiento. "
            "Como alternativa, puedes verificar los datos solicitados manualmente o intentar reformular la orden."
        )

    # Ensure max 1 paragraph (reasonable length bound)
    if len(paragraph) > 420:
        sentence_end = paragraph.rfind(".", 0, 415)
        if sentence_end > 100:
            paragraph = paragraph[: sentence_end + 1].strip()
        else:
            paragraph = paragraph[:415].rstrip() + "..."

    return paragraph


def generate_fallback_summary(
    error_text: str,
    user_request: str,
    skill_name: str | None = None,
    phase: str = "creación",
) -> str:
    """Generate a polite, clear 1-paragraph Spanish executive summary with an alternative."""
    error_lower = error_text.lower()
    subject = f"'{skill_name}'" if skill_name else "solicitada"

    if "insufficient_research" in error_lower or "spa" in error_lower or "javascript was not executed" in error_lower or "1688track" in error_lower:
        return (
            "No he podido consultar automáticamente la información de la página externa "
            "porque el sitio web requiere navegación dinámica e interactiva no disponible mediante consulta directa. "
            "Como alternativa, puedes comprobar el estado directamente en el portal oficial o proporcionarme datos directos de consulta."
        )

    if "timeout" in error_lower or "timed out" in error_lower or "tiempo de espera" in error_lower:
        return (
            f"La comunicación con el servicio externo durante la {phase} de la skill {subject} "
            "ha tardado más de lo previsto y se ha cancelado por seguridad. "
            "Como alternativa, te sugiero comprobar la disponibilidad de la conexión y volver a intentarlo en unos instantes."
        )

    if "permission" in error_lower or "denied" in error_lower or "autoriz" in error_lower:
        return (
            f"La política de seguridad de JARVIS requiere una confirmación expresa o permisos adicionales "
            f"para autorizar la {phase} de la skill {subject}. "
            "Como alternativa, puedes solicitar explícitamente la confirmación para conceder los permisos requeridos."
        )

    if "dependenc" in error_lower or "módulo no permitido" in error_lower or "import" in error_lower:
        return (
            f"La skill {subject} necesita dependencias de software adicionales que no están autorizadas o disponibles. "
            "Como alternativa, puedes verificar la lista de librerías permitidas o solicitar una implementación alternativa sin dependencias externas."
        )

    return (
        f"Se ha producido una incidencia imprevista durante la {phase} de la skill {subject}. "
        "El incidente ha sido registrado para su análisis; mientras tanto, puedes intentar reformular la petición "
        "o realizar la consulta a través del procedimiento manual habitual."
    )


@dataclass(frozen=True)
class SkillTriageDecision:
    can_repair: bool
    repair_strategy: str
    root_cause: str
    executive_summary: str
    repaired_result: Any | None = None


class SkillErrorHandler:
    """Interception, triage, and self-repair router for JARVIS skills."""

    def __init__(self, model_router: object | None = None) -> None:
        self._router = model_router

    def triage(
        self,
        error: object,
        *,
        phase: str = "creación",
        user_request: str = "",
        skill_name: str | None = None,
        auto_repair_callback: Optional[Callable[[str], Any]] = None,
    ) -> SkillTriageDecision:
        """Route the error to the reasoning engine, determine root cause, attempt self-repair, or summarize."""
        cleaned_error = sanitize_error_text(error)
        root_cause = cleaned_error
        can_repair = False
        repair_strategy = "none"
        executive_summary = ""

        # 1. Architectural triage via ModelRouter if available
        if self._router is not None and hasattr(self._router, "route"):
            try:
                from jarvis.core.model_router import ModelRole

                triage_prompt = f"""Eres el arquitecto senior de JARVIS especializado en triage y recuperación de fallos en el pipeline de skills.
Ha ocurrido una incidencia técnica durante la fase de {phase}.

Detalles de la incidencia:
- Petición original del usuario: {user_request}
- Nombre de la skill: {skill_name or 'nueva_skill'}
- Fase del ciclo de vida: {phase}
- Error técnico observado: {cleaned_error}

Instrucciones de análisis arquitectónico:
1. Analiza la causa raíz técnica del error.
2. Determina si el error es subsanable automáticamente mediante un cambio de estrategia:
   - "dynamic_browser_inspection": si falló la investigación estática porque la web es una SPA de JavaScript y debe renderizarse con Playwright/SecureWebSession.
   - "auto_code_repair": si falló el código generado o la ejecución de la skill y el coder puede auto-corregirlo.
   - "none": si no es reparable automáticamente sin intervención del usuario.
3. Si NO es subsanable de inmediato (o si la auto-reparación no aplica), genera un resumen ejecutivo en español, claro y conciso (MÁXIMO 1 PÁRRAFO), explicando educadamente qué ha pasado y qué alternativa práctica existe.
REGLA INQUEBRANTABLE: Queda terminantemente prohibido incluir trazas técnicas (tracebacks), líneas de archivo o rutas internas de archivos en el resumen ejecutivo.

Devuelve EXCLUSIVAMENTE un objeto JSON válido con este formato:
{{
  "can_repair": true,
  "repair_strategy": "dynamic_browser_inspection",
  "root_cause": "breve explicación técnica",
  "executive_summary": "Resumen ejecutivo en español para el usuario."
}}"""

                raw_model_response = self._router.route(
                    ModelRole.DEEP_REASONING, triage_prompt
                )
                parsed = self._extract_json(str(raw_model_response))
                if isinstance(parsed, dict):
                    can_repair = bool(parsed.get("can_repair", False))
                    repair_strategy = str(parsed.get("repair_strategy", "none"))
                    root_cause = str(parsed.get("root_cause", cleaned_error))
                    candidate_summary = parsed.get("executive_summary")
                    if isinstance(candidate_summary, str) and candidate_summary.strip():
                        executive_summary = clean_executive_summary(candidate_summary)
            except Exception as exc:
                logger.warning("SkillErrorHandler model triage call failed: %s", exc)

        # Heuristic triage fallback if model was not available or gave no summary
        if not executive_summary:
            # Check if this is an SPA / external research issue
            err_lower = cleaned_error.lower()
            if (
                "insufficient_research" in err_lower
                or "spa" in err_lower
                or "javascript was not executed" in err_lower
                or "1688track" in err_lower
            ):
                can_repair = True
                repair_strategy = "dynamic_browser_inspection"
                root_cause = "Static HTTP analysis failed on dynamic JavaScript SPA"

            executive_summary = generate_fallback_summary(
                cleaned_error, user_request, skill_name, phase=phase
            )

        # 2. Attempt self-repair if feasible and callback provided
        repaired_result = None
        if can_repair and auto_repair_callback is not None:
            try:
                logger.info(
                    "SkillErrorHandler attempting auto-repair with strategy: %s",
                    repair_strategy,
                )
                repaired_result = auto_repair_callback(repair_strategy)
            except Exception as exc:
                logger.warning("Auto-repair callback execution failed: %s", exc)
                repaired_result = None

        return SkillTriageDecision(
            can_repair=can_repair,
            repair_strategy=repair_strategy,
            root_cause=root_cause,
            executive_summary=clean_executive_summary(executive_summary),
            repaired_result=repaired_result,
        )

    @staticmethod
    def _extract_json(model_output: str) -> Optional[dict[str, Any]]:
        """Extract a JSON object from text that may contain markdown code fences."""
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", model_output, re.DOTALL)
        candidate = match.group(1) if match else model_output.strip()
        try:
            val = json.loads(candidate)
            return val if isinstance(val, dict) else None
        except ValueError:
            start = candidate.find("{")
            end = candidate.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    val = json.loads(candidate[start : end + 1])
                    return val if isinstance(val, dict) else None
                except ValueError as exc:
                    logger.debug("Triage JSON fallback extraction failed: %s", exc)
        return None
