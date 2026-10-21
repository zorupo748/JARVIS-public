"""Deterministic routing for deciding whether a missing capability needs a skill."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping


class CapabilityDecision(str, Enum):
    DIRECT_RESPONSE = "DIRECT_RESPONSE"
    USE_EXISTING_TOOL = "USE_EXISTING_TOOL"
    USE_EXISTING_SKILL = "USE_EXISTING_SKILL"
    CREATE_SKILL = "CREATE_SKILL"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class CapabilityRoute:
    decision: CapabilityDecision
    reason: str
    confidence: float
    skill_name: str | None = None
    native_tool_name: str | None = None
    source: str = "rule"


@dataclass(frozen=True)
class NativeCapability:
    name: str
    description: str


NATIVE_CAPABILITIES: tuple[NativeCapability, ...] = (
    NativeCapability("conversation", "Conversación y respuestas de conocimiento general."),
    NativeCapability("web_search", "Búsqueda web puntual de información actual."),
    NativeCapability("vision", "Captura y análisis visual de la pantalla."),
    NativeCapability("reminders", "Crear recordatorios puntuales."),
    NativeCapability("scheduler", "Programar skills instaladas que tengan autorización."),
    NativeCapability("workspace", "Leer y listar archivos del workspace."),
    NativeCapability("klipper", "Consultar y controlar la impresora 3D Klipper."),
)

_REUSABLE_PATTERNS = (
    r"\bcada vez\b",
    r"\bcuando te (?:pregunte|pida)\b",
    r"\b(?:en|para) el futuro\b",
    r"\b(?:recuerda|recordar|guarda|guardar)\b.{0,70}\b(?:ultima(?:s)?(?:\s+version(?:es)?)?\s+(?:vez|estado|version)|la proxima|cambio|estado)\b",
    r"\b(?:compara|comparar|detecta|detectar)\b.{0,40}\b(?:cambios?|versiones?|estado)\b",
    r"\b(?:monitoriza|monitorizar|vigila|automatiza|automatizar)\b",
    r"\bquiero que puedas\b",
    r"\bquiero poder repetir\b",
    r"\bquiero poder preguntarte\b",
    r"\b(?:diariamente|semanalmente|mensualmente|periodicamente)\b",
)
_PUBLIC_EXTERNAL_PATTERNS = (
    r"\b(?:web|sitio|pagina|api|endpoint|servicio|fuente)\b",
    r"\b(?:version|proyecto)\b",
)
_PACKAGE_TRACKING_PATTERNS = (
    r"\b(?:paquete|envio)\b",
)
_PACKAGE_LOCATION_PATTERNS = (
    r"\b(?:donde esta|ubicacion|tracking|seguimiento|1688track|codigo ox[a-z0-9]+)\b",
)
_PERSISTENT_COMPARISON_PATTERNS = (
    r"\b(?:recuerda|recordar|recuerdes|estado anterior|ultimo estado|ultima vez|ha cambiado|cambios?)\b",
)
_TRACKING_SUBJECT_PATTERNS = (
    r"\b(?:paquete|paquetes|envio|envios|pedido|paqueteria)\b",
    r"\box[a-z0-9]{6,38}\b",
    r"\b1688\s?track\b",
)
_TRACKING_ACTION_PATTERNS = (
    r"\b(?:donde (?:esta|va|anda|se encuentra)|ubicacion|rastrea(?:r|me)?|rastreo|seguimiento|tracking)\b",
    r"\b(?:estado|situacion)\b.{0,20}\b(?:paquete|envio|pedido)\b",
    r"\b(?:como va|ha llegado|cuando llega)\b",
    r"\bsigue\b.{0,15}\b(?:paquete|envio)\b",
)
_SOFTWARE_PACKAGE_PATTERNS = (
    r"\b(?:pip|npm|python|numpy|pandas|libreria|dependencia|dependencias|conda|apt|requirements|modulo)\b",
)
_EXPLICIT_IMPOSSIBILITY_PATTERNS = (
    r"\b(?:no tengo|sin|no hay|no esta disponible)\b.{0,50}\b(?:acceso al hardware|hardware necesario|dispositivo fisico)\b",
    r"\b(?:dispositivo|hardware)\b.{0,80}\b(?:no esta conectado|desconectado|no conectado)\b.{0,100}\b(?:ninguna interfaz|sin interfaz|no existe interfaz)\b",
    r"\b(?:ninguna interfaz|sin interfaz|no existe interfaz)\b.{0,100}\b(?:dispositivo|hardware|control fisico)\b",
    r"\b(?:credenciales privadas|autenticacion privada|autenticacion obligatoria)\b.{0,100}\b(?:no (?:las )?(?:tengo|he proporcionado|puedo proporcionar)|no existe mecanismo|sin mecanismo)\b",
    r"\b(?:no (?:las )?(?:tengo|he proporcionado|puedo proporcionar)|no existe mecanismo|sin mecanismo)\b.{0,100}\b(?:credenciales privadas|autenticacion privada|autenticacion obligatoria)\b",
    r"\b(?:sin|no tengo|no hay|no esta disponible)\b.{0,50}\b(?:credenciales privadas|autenticacion privada)\b",
    r"\b(?:viola|elude|evade|salta)\b.{0,50}\b(?:seguridad|politica|restricciones|autorizacion)\b",
)
_KNOWLEDGE_PATTERNS = (
    r"^\s*(?:que es|qué es|quien fue|quién fue|por que|por qué)\b",
    r"^\s*(?:explica|explícame|explicame)\b",
    r"\bexplica(?:me)?\s+que hace este codigo\b",
    r"\b(?:que significa|qué significa)\b",
)
_WEB_PATTERNS = (
    r"\bbusca(?:r)?\b",
    r"\bconsulta(?:r)? en internet\b",
    r"\b(?:noticias|precio|version|versión|tiempo|resultado)\b.{0,25}\b(?:hoy|actual|actualizado|ahora|reciente)\b",
    r"\b(?:hoy|actual|actualizado|ahora|reciente)\b.{0,25}\b(?:noticias|precio|version|versión|tiempo|resultado)\b",
)
_VISION_PATTERNS = (
    r"\b(?:captura|pantalla|screenshot)\b",
    r"\b(?:que ves|qué ves|describe la imagen|analiza la imagen)\b",
)
_WORKSPACE_PATTERNS = (
    r"\b(?:lee|leer|abre|abrir|lista|listar)\b.{0,35}\b(?:archivo|workspace|repositorio|proyecto)\b",
    r"\b(?:archivo activo|archivo del workspace|archivos del repositorio)\b",
)
_KLIPPER_PATTERNS = (
    r"\b(?:impresora 3d|klipper|g-code|gcode)\b",
)
_REMINDER_PATTERNS = (
    r"\b(?:recu[eé]rdame|ponme un recordatorio|crear un recordatorio)\b",
)


class CapabilityRouter:
    """Prioritize installed skills and native tools before considering authoring."""

    def __init__(
        self,
        model_classifier: Callable[[str], str] | None = None,
        *,
        native_capabilities: tuple[NativeCapability, ...] = NATIVE_CAPABILITIES,
        create_confidence_threshold: float = 0.80,
        decision_confidence_threshold: float = 0.75,
        tracking_skill_name: str | None = None,
    ) -> None:
        self._model_classifier = model_classifier
        self._native_capabilities = native_capabilities
        self._create_confidence_threshold = create_confidence_threshold
        self._decision_confidence_threshold = decision_confidence_threshold
        self._tracking_skill_name = tracking_skill_name

    @property
    def native_catalog_description(self) -> str:
        return "\n".join(
            f"- {capability.name}: {capability.description}"
            for capability in self._native_capabilities
        )

    def decide(
        self,
        original_user_request: str,
        *,
        existing_skill_name: str | None = None,
        installed_skills: Mapping[str, str] | None = None,
        external_user_request: bool = True,
    ) -> CapabilityRoute:
        """Select a safe route; invalid or uncertain model output never creates code."""

        if not external_user_request:
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "internal_input", 1.0)
        if not isinstance(original_user_request, str) or not original_user_request.strip():
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "empty_request", 1.0)

        request = original_user_request.strip()
        if existing_skill_name:
            return self._route(
                CapabilityDecision.USE_EXISTING_SKILL,
                "installed_skill_match",
                1.0,
                skill_name=existing_skill_name,
            )
        if self._tracking_skill_name and self.is_package_tracking_request(request):
            return self._route(
                CapabilityDecision.USE_EXISTING_SKILL,
                "installed_skill_match",
                1.0,
                skill_name=self._tracking_skill_name,
            )

        if self._matches_native_tool(request):
            return self._route(
                CapabilityDecision.USE_EXISTING_TOOL,
                "native_tool_match",
                0.95,
                native_tool_name=self._native_tool_for_request(request),
            )
        if self._is_simple_calculation(request) or self._is_knowledge_request(request):
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "ordinary_question", 0.98)
        if self._matches_impossible_capability(request):
            return self._route(CapabilityDecision.UNSUPPORTED, "unavailable_requirement", 0.95)

        reusable_intent = self._has_reusable_intent(request)
        if reusable_intent and self._is_reusable_external_tracking_request(request):
            return self._route(
                CapabilityDecision.CREATE_SKILL,
                "reusable_external_tracking",
                0.96,
            )
        if not reusable_intent or self._model_classifier is None:
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "no_reusable_capability", 0.85)

        model_route = self._classify_ambiguous_request(request, installed_skills or {})
        if model_route is None:
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "invalid_model_output", 0.5)
        if model_route.decision is CapabilityDecision.CREATE_SKILL:
            if model_route.confidence < self._create_confidence_threshold:
                return self._route(CapabilityDecision.DIRECT_RESPONSE, "low_create_confidence", model_route.confidence)
            if not reusable_intent:
                return self._route(CapabilityDecision.DIRECT_RESPONSE, "not_reusable", model_route.confidence)
            return model_route
        if model_route.decision is CapabilityDecision.UNSUPPORTED:
            if model_route.confidence < self._decision_confidence_threshold:
                return self._route(CapabilityDecision.DIRECT_RESPONSE, "low_unsupported_confidence", model_route.confidence)
            return model_route
        if model_route.decision is CapabilityDecision.USE_EXISTING_TOOL:
            if self._matches_native_tool(request):
                return self._route(
                    CapabilityDecision.USE_EXISTING_TOOL,
                    model_route.reason,
                    model_route.confidence,
                    native_tool_name=self._native_tool_for_request(request),
                )
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "unmatched_native_tool", model_route.confidence)
        if model_route.decision is CapabilityDecision.USE_EXISTING_SKILL:
            if model_route.skill_name and model_route.skill_name in (installed_skills or {}):
                return model_route
            return self._route(CapabilityDecision.DIRECT_RESPONSE, "unmatched_installed_skill", model_route.confidence)
        return model_route

    def route(
        self,
        original_user_request: str,
        *,
        existing_skill_name: str | None = None,
        installed_skills: Mapping[str, str] | None = None,
        external_user_request: bool = True,
    ) -> CapabilityRoute:
        """Compatibility-friendly routing entry point."""
        return self.decide(
            original_user_request,
            existing_skill_name=existing_skill_name,
            installed_skills=installed_skills,
            external_user_request=external_user_request,
        )

    def _classify_ambiguous_request(
        self,
        request: str,
        installed_skills: Mapping[str, str],
    ) -> CapabilityRoute | None:
        assert self._model_classifier is not None
        installed_description = "\n".join(
            f"- {name}: {description}" for name, description in installed_skills.items()
        ) or "(ninguna)"
        prompt = (
            "Clasifica la petición externa para elegir una ruta. No generes código ni "
            "autorices ejecución o instalación. Elige CREATE_SKILL solo para una "
            "capacidad ejecutable, reutilizable y ausente; no para preguntas, búsquedas "
            "puntuales ni acciones que ya cubren las herramientas. Una web o API pública "
            "puede justificar CREATE_SKILL, incluso si los detalles exactos de acceso o "
            "scraping aún no están claros. No declares UNSUPPORTED solo porque una "
            "implementación no esté demostrada de antemano: UNSUPPORTED exige una "
            "limitación concreta y evidente, como hardware no conectado sin interfaz, "
            "credenciales privadas obligatorias ausentes sin mecanismo para obtenerlas, "
            "o una restricción de seguridad. Ante incertidumbre técnica sobre un sitio "
            "público, prefiere CREATE_SKILL para que el pipeline verifique la viabilidad. "
            "En caso de duda no autorices acciones. Responde solo JSON con las claves "
            "decision, reason, confidence.\n"
            f"Capacidades nativas:\n{self.native_catalog_description}\n"
            f"Skills instaladas:\n{installed_description}\n"
            f"Petición original:\n{request}\n"
            'Formato: {"decision":"DIRECT_RESPONSE","reason":"...","confidence":0.0}'
        )
        try:
            raw_result = self._model_classifier(prompt)
        except Exception:
            return None
        return self.normalize_model_output(raw_result)

    @classmethod
    def normalize_model_output(cls, raw_output: object) -> CapabilityRoute | None:
        """Validate the complete JSON response and reject unknown or ambiguous values."""

        if not isinstance(raw_output, str) or not raw_output.strip():
            return None
        try:
            payload = json.loads(raw_output.strip())
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(payload, dict) or set(payload) != {"decision", "reason", "confidence"}:
            return None

        raw_decision = payload.get("decision")
        raw_reason = payload.get("reason")
        raw_confidence = payload.get("confidence")
        if not isinstance(raw_decision, str) or not isinstance(raw_reason, str):
            return None
        if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, (int, float)):
            return None
        confidence = float(raw_confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            return None
        try:
            decision = CapabilityDecision(raw_decision.strip().upper())
        except ValueError:
            return None
        reason = re.sub(r"\s+", " ", raw_reason).strip()[:160]
        if not reason:
            return None
        return cls._route(decision, reason, confidence, source="model")

    def _matches_native_tool(self, request: str) -> bool:
        normalized = self._normalize(request)
        reusable = self._has_reusable_intent(request)
        for capability in self._native_capabilities:
            if capability.name == "web_search":
                if not reusable and any(re.search(pattern, normalized) for pattern in _WEB_PATTERNS):
                    return True
            elif capability.name == "vision" and any(
                re.search(pattern, normalized) for pattern in _VISION_PATTERNS
            ):
                return True
            elif capability.name == "workspace" and any(
                re.search(pattern, normalized) for pattern in _WORKSPACE_PATTERNS
            ):
                return True
            elif capability.name == "klipper" and any(
                re.search(pattern, normalized) for pattern in _KLIPPER_PATTERNS
            ):
                return self._native_tool_for_request(request) is not None
            elif capability.name == "reminders" and any(
                re.search(pattern, normalized) for pattern in _REMINDER_PATTERNS
            ):
                return True
        return False

    def _native_tool_for_request(self, request: str) -> str | None:
        normalized = self._normalize(request)
        if any(re.search(pattern, normalized) for pattern in _WEB_PATTERNS):
            return "buscar_en_internet"
        if any(re.search(pattern, normalized) for pattern in _VISION_PATTERNS):
            return "tomar_captura_pantalla"
        if any(re.search(pattern, normalized) for pattern in _WORKSPACE_PATTERNS):
            return "leer_archivo_workspace"
        if any(re.search(pattern, normalized) for pattern in _REMINDER_PATTERNS):
            return None
        if "klipper" in normalized or "impresora 3d" in normalized:
            if any(word in normalized for word in ("estado", "status", "online")):
                return "estado_impresora"
            if any(word in normalized for word in ("lista", "listar", "archivos", "gcode")):
                return "listar_archivos"
            if any(word in normalized for word in ("parada", "emergencia", "deten", "stop")):
                return "parada_emergencia"
        return None

    @classmethod
    def _has_reusable_intent(cls, request: str) -> bool:
        normalized = cls._normalize(request)
        return any(re.search(pattern, normalized) for pattern in _REUSABLE_PATTERNS)

    @classmethod
    def is_package_tracking_request(cls, request: str) -> bool:
        """True for requests about where a package/shipment is or what its status is."""
        normalized = cls._normalize(request)
        if any(re.search(pattern, normalized) for pattern in _SOFTWARE_PACKAGE_PATTERNS):
            return False
        return any(
            re.search(pattern, normalized) for pattern in _TRACKING_SUBJECT_PATTERNS
        ) and any(re.search(pattern, normalized) for pattern in _TRACKING_ACTION_PATTERNS)

    @classmethod
    def _is_knowledge_request(cls, request: str) -> bool:
        normalized = cls._normalize(request)
        return any(re.search(pattern, normalized) for pattern in _KNOWLEDGE_PATTERNS)

    @staticmethod
    def _is_simple_calculation(request: str) -> bool:
        text = request.strip().lower()
        if not re.match(r"^(?:cuanto es|cuánto es|calcula|calcular)\b", text):
            return False
        expression = re.sub(r"^(?:cuanto es|cuánto es|calcula|calcular)\s*", "", text)
        expression = expression.rstrip(" ?")
        return bool(re.fullmatch(r"[\d\s()+\-*/.,%]+", expression))

    @classmethod
    def _matches_impossible_capability(cls, request: str) -> bool:
        normalized = cls._normalize(request)
        return any(
            re.search(pattern, normalized)
            for pattern in _EXPLICIT_IMPOSSIBILITY_PATTERNS
        )

    @classmethod
    def _is_reusable_external_tracking_request(cls, request: str) -> bool:
        normalized = cls._normalize(request)
        reusable = any(re.search(pattern, normalized) for pattern in _REUSABLE_PATTERNS)
        public_external = any(
            re.search(pattern, normalized) for pattern in _PUBLIC_EXTERNAL_PATTERNS
        )
        package_tracking = (
            any(re.search(pattern, normalized) for pattern in _PACKAGE_TRACKING_PATTERNS)
            and any(re.search(pattern, normalized) for pattern in _PACKAGE_LOCATION_PATTERNS)
            and any(
                re.search(pattern, normalized)
                for pattern in _PERSISTENT_COMPARISON_PATTERNS
            )
        )
        return reusable and (public_external or package_tracking)

    @staticmethod
    def _normalize(value: str) -> str:
        normalized = unicodedata.normalize("NFKD", value)
        return "".join(character for character in normalized if not unicodedata.combining(character)).casefold()

    @staticmethod
    def _route(
        decision: CapabilityDecision,
        reason: str,
        confidence: float,
        *,
        skill_name: str | None = None,
        native_tool_name: str | None = None,
        source: str = "rule",
    ) -> CapabilityRoute:
        return CapabilityRoute(
            decision,
            reason,
            confidence,
            skill_name,
            native_tool_name,
            source,
        )


__all__ = [
    "CapabilityDecision",
    "CapabilityRoute",
    "CapabilityRouter",
    "NativeCapability",
    "NATIVE_CAPABILITIES",
]
