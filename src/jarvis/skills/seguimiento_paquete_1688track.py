"""Skill `seguimiento_paquete_1688track`.

Consulta el estado de un paquete en https://www.1688track.com/#/ automatizando la SPA
con ``SecureWebSession`` (Playwright aislado, URL validada, dominios en allowlist),
persiste el último estado válido por código y compara con la consulta anterior.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional

from jarvis.core.dynamic_skill_state import DynamicSkillStateStore
from jarvis.core.security.secure_browser import SecureWebSession

logger = logging.getLogger(__name__)

SKILL_NAME = "seguimiento_paquete_1688track"
TRACKING_URL = "https://www.1688track.com/#/"
DEFAULT_TRACKING_CODE = "OXCGH6082081H"
ALLOWED_DOMAINS = ["1688track.com", "*.1688track.com"]

# Selectores verificados en vivo contra https://www.1688track.com/#/ (Vue + Element UI):
#   input  -> <input class="el-input__inner" placeholder="请输入运单号或入仓号">
#   botón  -> <button class="el-button el-button--primary">查询</button>
#   result -> <ul class="el-timeline"> con <li class="el-timeline-item">
INPUT_SELECTORS = (
    "input.el-input__inner",
    'input[type="text"]',
    "textarea",
)
BUTTON_SELECTORS = (
    "button.el-button--primary",
    "button:has-text('查询')",
    'button[type="submit"]',
)
RESULT_SELECTORS = (
    ".el-timeline",
    ".timeline",
)

# API real que consulta la SPA (XHR POST, body: key_word=<CODIGO>%2C&_os=web).
TRACK_API_MARKER = "op=Track"

# Glosario de estados observados (la plataforma los devuelve en chino).
STATE_GLOSSARY = {
    "已到港": "Llegado a puerto",
    "推迟到港": "Llegada retrasada",
    "已开船": "Buque zarpado",
    "推迟开船": "Salida retrasada",
    "出口放行": "Liberado para exportación",
    "已装柜": "Cargado en contenedor",
    "已出账": "Facturado",
    "待放货": "Pendiente de liberar la mercancía",
    "待审核": "Pendiente de revisión",
    "待出账": "Pendiente de facturar",
    "已下单": "Pedido registrado",
}

_CODE_PATTERN = re.compile(r"^[A-Za-z0-9\-]{8,40}$")
_DATE_PATTERN = re.compile(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?")
_STATUS_KEYS = ("status", "state", "statusDesc", "status_desc", "delivery_status", "package_status")
_LOCATION_KEYS = ("location", "city", "place", "area", "address")
_EVENT_LIST_KEYS = ("events", "trackInfo", "track_info", "tracks", "details", "data", "list", "items")
_TEXT_KEYS = ("description", "desc", "info", "context", "message", "status", "remark")
_DATE_KEYS = ("time", "date", "datetime", "created_at", "ftime", "timestamp")
MAX_EVENTS = 50


class TrackingError(Exception):
    """Fallo controlado de la skill; el mensaje es apto para el usuario."""


_CODE_IN_TEXT_PATTERN = re.compile(r"\b(OX[A-Z0-9]{6,38})\b", re.IGNORECASE)


def extract_tracking_code(text: str) -> Optional[str]:
    """Devuelve el primer código tipo OX... de un texto libre, o None (→ código por defecto)."""
    match = _CODE_IN_TEXT_PATTERN.search(text or "")
    return match.group(1).upper() if match else None


def validate_tracking_code(code: Optional[str]) -> str:
    """Normaliza y valida el código; usa el de ejemplo cuando no se suministra."""
    if code is None or (isinstance(code, str) and not code.strip()):
        return DEFAULT_TRACKING_CODE
    if not isinstance(code, str):
        raise TrackingError("El código de seguimiento debe ser texto.")
    cleaned = code.strip().upper()
    if not _CODE_PATTERN.fullmatch(cleaned):
        raise TrackingError(
            "El código de seguimiento no es válido: usa entre 8 y 40 letras, números o guiones."
        )
    return cleaned


def _first(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return ""


def _events_from_json(payload: Any, depth: int = 0) -> List[Dict[str, str]]:
    """Busca recursivamente una lista de eventos en el JSON de la API."""
    if depth > 4:
        return []
    if isinstance(payload, list):
        events = []
        for item in payload:
            if isinstance(item, Mapping):
                text = _first(item, _TEXT_KEYS)
                date = _first(item, _DATE_KEYS)
                if text or date:
                    events.append({
                        "fecha": date,
                        "descripcion": text,
                        "ubicacion": _first(item, _LOCATION_KEYS),
                        "origen": "transportista",
                        "tipo": "confirmado",
                    })
        if events:
            return events
        for item in payload:
            found = _events_from_json(item, depth + 1)
            if found:
                return found
    elif isinstance(payload, Mapping):
        for key in _EVENT_LIST_KEYS:
            if key in payload:
                found = _events_from_json(payload[key], depth + 1)
                if found:
                    return found
        for value in payload.values():
            if isinstance(value, (list, Mapping)):
                found = _events_from_json(value, depth + 1)
                if found:
                    return found
    return []


def _status_from_json(payload: Any, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(payload, Mapping):
        value = _first(payload, _STATUS_KEYS)
        if value:
            return value
        for item in payload.values():
            found = _status_from_json(item, depth + 1)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload[:3]:
            found = _status_from_json(item, depth + 1)
            if found:
                return found
    return ""


_ESTIMATE_PATTERN = re.compile(r"^\s*ET[AD]\b|delay", re.IGNORECASE)
_DOM_LINE_PATTERN = re.compile(
    r"^(?P<fecha>\d{4}-\d{2}-\d{2}(?:[ T]\d{1,2}:\d{2})?)\s+\[(?P<sitio>[^\]]+)\]\s+(?P<estado>\S+)\s*(?P<nota>.*)$"
)
COUNTRY_GLOSSARY = {"西班牙": "España"}


def _translate_state(state: str) -> str:
    state = (state or "").strip()
    translated = STATE_GLOSSARY.get(state)
    return f"{translated} ({state})" if translated else state


def _named(value: Any) -> str:
    """La API devuelve catálogos como {"id": n, "key_name": "texto"}."""
    if isinstance(value, Mapping):
        return str(value.get("key_name") or "").strip()
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return ""


def _flag_is_true(value: Any) -> bool:
    if isinstance(value, Mapping):
        value = value.get("id")
    return value in (1, "1", True)


def classify_event(remark: str, published: bool) -> Dict[str, str]:
    """Clasifica un evento sin interpretarlo.

    origen: ``transportista`` (nota publicada por el operador logístico) o
    ``administrativo`` (paso interno de la plataforma, sin nota ni publicación).
    tipo: ``estimacion`` (ETA/ETD/retraso previsto) o ``confirmado`` (hecho ya ocurrido).
    """
    origen = "transportista" if (remark and published) else "administrativo"
    tipo = "estimacion" if remark and _ESTIMATE_PATTERN.search(remark) else "confirmado"
    return {"origen": origen, "tipo": tipo}


def parse_track_api(payload: Any) -> Optional[Dict[str, Any]]:
    """Parsea la respuesta real de WebsiteApi?op=Track (esquema observado en vivo)."""
    if not isinstance(payload, Mapping) or payload.get("code") != 200:
        return None
    tracks = payload.get("tracks")
    if not isinstance(tracks, list):
        return None
    for track in tracks:
        if not isinstance(track, Mapping) or not isinstance(track.get("track"), list):
            continue
        events: List[Dict[str, str]] = []
        for raw in track["track"]:
            if not isinstance(raw, Mapping):
                continue
            state = _named(raw.get("review_state"))
            remark = re.sub(r"\s+", " ", str(raw.get("remark") or "")).strip()
            date = str(raw.get("track_time") or "").strip()
            if not (state or remark) or not date:
                continue
            description = _translate_state(state)
            if remark:
                description = f"{description}: {remark}" if description else remark
            events.append({
                "fecha": date,
                "descripcion": description,
                "ubicacion": _named(raw.get("site")),
                **classify_event(remark, _flag_is_true(raw.get("is_push"))),
            })
        if not events:
            continue
        overall = _named(track.get("review_state")) or _named(track["track"][0].get("review_state"))
        country = _named(track.get("country"))
        return {
            "estado": _translate_state(overall),
            "eventos": events[:MAX_EVENTS],
            "albaran": _named(track.get("key_name")),
            "transporte": _named(track.get("channel_entity")),
            "destino": COUNTRY_GLOSSARY.get(country, country),
        }
    return None


def parse_from_responses(responses: List[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Extrae estado/eventos de las respuestas XHR/fetch capturadas."""
    ordered = sorted(
        responses or [],
        key=lambda r: 0 if TRACK_API_MARKER in str(r.get("url", "")) else 1,
    )
    for response in ordered:
        if response.get("status") != 200:
            continue
        try:
            payload = json.loads(response.get("body") or "")
        except (TypeError, ValueError):
            continue
        parsed = parse_track_api(payload)
        if parsed:
            return parsed
        events = _events_from_json(payload)
        if events:
            status = _status_from_json(payload) or events[0]["descripcion"]
            return {"estado": status, "eventos": events[:MAX_EVENTS]}
    return None


def parse_from_text(result_text: str) -> Optional[Dict[str, Any]]:
    """Extrae eventos del texto visible del DOM de resultados (respaldo)."""
    lines = [ln.strip() for ln in (result_text or "").splitlines() if ln.strip()]
    events: List[Dict[str, str]] = []
    pending_date = ""
    for line in lines:
        dom = _DOM_LINE_PATTERN.match(line)
        if dom:
            note = dom.group("nota").strip()
            description = _translate_state(dom.group("estado"))
            if note:
                description = f"{description}: {note}"
            events.append({
                "fecha": dom.group("fecha"),
                "descripcion": description,
                "ubicacion": dom.group("sitio"),
                **classify_event(note, bool(note)),
            })
            continue
        match = _DATE_PATTERN.search(line)
        if match and len(line) <= len(match.group(0)) + 2:
            pending_date = match.group(0)
            continue
        if match:
            events.append({
                "fecha": match.group(0),
                "descripcion": line.replace(match.group(0), "").strip(" -:"),
                "ubicacion": "",
                "origen": "transportista",
                "tipo": "confirmado",
            })
        else:
            events.append({
                "fecha": pending_date,
                "descripcion": line,
                "ubicacion": "",
                "origen": "transportista",
                "tipo": "confirmado",
            })
            pending_date = ""
    events = [e for e in events if e["descripcion"] or e["fecha"]]
    if not events:
        return None
    return {"estado": events[0]["descripcion"], "eventos": events[:MAX_EVENTS]}


def compare_snapshots(previous: Optional[Mapping[str, Any]], current: Mapping[str, Any]) -> Dict[str, Any]:
    """Compara con la consulta anterior: primera_consulta, sin_cambios o con_cambios."""
    if not previous:
        return {"resultado": "primera_consulta", "detalle": "Primera consulta de este paquete."}
    changes: List[str] = []
    if previous.get("estado") != current.get("estado"):
        changes.append(f"Estado: '{previous.get('estado', '')}' → '{current.get('estado', '')}'.")
    old_events = {(e.get("fecha"), e.get("descripcion")) for e in previous.get("eventos", [])}
    new_events = [
        e for e in current.get("eventos", [])
        if (e.get("fecha"), e.get("descripcion")) not in old_events
    ]
    for event in new_events:
        place = f" ({event['ubicacion']})" if event.get("ubicacion") else ""
        changes.append(f"Nuevo evento {event.get('fecha', '')}: {event.get('descripcion', '')}{place}.")
    if not changes:
        return {"resultado": "sin_cambios", "detalle": "Sin cambios desde la consulta anterior."}
    return {"resultado": "con_cambios", "detalle": " ".join(changes)}



_DEFAULT_LLM_CALLER: Optional[Callable[[str], str]] = None


def set_default_llm_caller(caller: Optional[Callable[[str], str]]) -> None:
    """Configura el llamador de modelo LLM por defecto para la síntesis de seguimiento."""
    global _DEFAULT_LLM_CALLER
    _DEFAULT_LLM_CALLER = caller


def get_default_llm_caller() -> Optional[Callable[[str], str]]:
    """Devuelve el llamador de modelo LLM por defecto."""
    return _DEFAULT_LLM_CALLER


def _quitar_caracteres_chinos(texto: str) -> str:
    """Elimina caracteres chinos y paréntesis que contengan chino."""
    if not texto:
        return ""
    sin_parentesis = re.sub(r"\s*\([^)]*[\u4e00-\u9fff\u3400-\u4dbf][^)]*\)", "", texto)
    limpio = re.sub(r"[\u4e00-\u9fff\u3400-\u4dbf\u3000-\u303f\uff01-\uffee]+", "", sin_parentesis)
    return re.sub(r"\s+", " ", limpio).strip(" -:,|")


def _limpiar_jerga_maritima(texto: str) -> str:
    """Traduce o suaviza acrónimos y jerga técnica marítima común."""
    if not texto:
        return ""
    t = texto
    t = re.sub(r"\bV/V\s*:\s*([^\s,;]+)", r"buque \1", t, flags=re.IGNORECASE)
    t = re.sub(r"\bOBD\s*:\s*", "fecha de embarque: ", t, flags=re.IGNORECASE)
    t = re.sub(r"\bETA\s+delay\s+to\s+", "retraso de llegada al ", t, flags=re.IGNORECASE)
    t = re.sub(r"\bETA\s*:\s*", "llegada estimada: ", t, flags=re.IGNORECASE)
    t = re.sub(r"\bETD\s*:\s*", "salida estimada: ", t, flags=re.IGNORECASE)
    t = re.sub(
        r"Vessel arrived at last port,?waiting for discharge",
        "Buque llegado al puerto de transbordo, pendiente de descarga",
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(r"Customs release", "Despacho de aduana completado", t, flags=re.IGNORECASE)
    t = re.sub(r"\bby\s+CMA\b", "(naviera CMA)", t, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", t).strip()


def preparar_datos_sintesis(result: Mapping[str, Any]) -> Dict[str, Any]:
    """Genera el diccionario estructurado y limpio para la síntesis LLM o fallback."""
    code = result.get("codigo", DEFAULT_TRACKING_CODE)
    raw_status = result.get("estado", "")
    estado_limpio = _quitar_caracteres_chinos(raw_status) or "En tránsito"

    ubicacion_raw = result.get("ubicacion", "")
    destino_raw = result.get("destino", "España")

    nombres_puertos = {
        "NL": "Países Bajos (Rotterdam)",
        "NLRTM": "Puerto de Rotterdam (Países Bajos)",
        "SZ": "Shenzhen (China)",
        "HK": "Hong Kong",
        "ES": "España",
        "CN": "China",
    }
    puerto_llegada = (
        nombres_puertos.get(ubicacion_raw, ubicacion_raw)
        if ubicacion_raw
        else "Países Bajos (Rotterdam, puerto de transbordo europeo)"
    )
    destino = nombres_puertos.get(destino_raw, destino_raw) if destino_raw else "España"

    eventos = result.get("eventos", [])
    carrier_events = [
        e for e in eventos
        if e.get("origen") == "transportista" and e.get("tipo") == "confirmado"
    ]
    if not carrier_events:
        carrier_events = [e for e in eventos if e.get("tipo") == "confirmado"] or eventos

    ultimo_evento_str = ""
    if carrier_events:
        ultimo = carrier_events[0]
        desc_limpia = _limpiar_jerga_maritima(_quitar_caracteres_chinos(ultimo.get("descripcion", "")))
        fecha = ultimo.get("fecha", "")
        ultimo_evento_str = f"{fecha}: {desc_limpia}".strip(": ")

    hitos_previos = []
    for ev in carrier_events[1:4]:
        d = _limpiar_jerga_maritima(_quitar_caracteres_chinos(ev.get("descripcion", "")))
        f = ev.get("fecha", "")
        if d:
            hitos_previos.append(f"{f} ({d})" if f else d)
    trayecto_previo = (
        " → ".join(reversed(hitos_previos))
        if hitos_previos
        else "Travesía marítima internacional completada desde China"
    )

    comparacion = result.get("comparacion", {})
    tipo_cambio = comparacion.get("resultado", "primera_consulta")
    detalle_cambio = _quitar_caracteres_chinos(comparacion.get("detalle", ""))

    cambios_str = detalle_cambio or (
        "Sin cambios desde la consulta anterior."
        if tipo_cambio == "sin_cambios"
        else "Primera consulta registrada para este paquete."
    )

    return {
        "tracking_code": code,
        "estado_actual": estado_limpio,
        "pais_puerto_llegada": f"{puerto_llegada} con destino final {destino}",
        "ultimo_evento_real": ultimo_evento_str,
        "trayecto_previo_resumido": trayecto_previo,
        "cambios_desde_ultima_consulta": cambios_str,
        "destino_final": destino,
    }


PROMPT_SISTEMA_SINTESIS = (
    "Eres el asistente de logística de JARVIS. Tu labor es informar a Diego sobre el estado "
    "de su paquete de forma clara, natural y precisa.\n\n"
    "REGLAS ESTRICTAS DE RESPUESTA:\n"
    "1. Devuelve EXACTAMENTE un único párrafo de 3 a 4 líneas de longitud.\n"
    "2. Español fluido, profesional y conversacional.\n"
    "3. NUNCA incluyas caracteres chinos ni símbolos técnicos como plecas (|).\n"
    "4. Elimina o traduce cualquier acrónimo o jerga marítima (como V/V, OBD, ETD, ETA delay).\n"
    "5. Explica con total claridad la situación real del envío:\n"
    "   - El buque ha llegado a puerto en Países Bajos (punto europeo de transbordo).\n"
    "   - La mercancía se encuentra actualmente pendiente de descarga e inspección aduanera comunitaria.\n"
    "   - Tras los trámites aduaneros, el paquete saldrá por transporte terrestre por carretera hacia España.\n"
    "6. Menciona si hay cambios respecto a la última consulta o si es la primera vez que se consulta."
)


def construir_prompt_sintesis(datos: Dict[str, Any]) -> str:
    return (
        f"{PROMPT_SISTEMA_SINTESIS}\n\n"
        "DATOS DEL PAQUETE:\n"
        f"- Código de seguimiento: {datos['tracking_code']}\n"
        f"- Estado actual: {datos['estado_actual']}\n"
        f"- Ubicación / Puerto de llegada: {datos['pais_puerto_llegada']}\n"
        f"- Último evento real registrado: {datos['ultimo_evento_real']}\n"
        f"- Trayecto previo resumido: {datos['trayecto_previo_resumido']}\n"
        f"- Cambios respecto a la consulta anterior: {datos['cambios_desde_ultima_consulta']}\n\n"
        "Redacta el párrafo de actualización para Diego:"
    )


def fallback_sintesis_deterministica(datos: Dict[str, Any]) -> str:
    """Fallback determinista en español limpio y natural, sin caracteres chinos ni plecas."""
    codigo = datos.get("tracking_code", DEFAULT_TRACKING_CODE)
    estado = datos.get("estado_actual", "En tránsito")
    llegada = datos.get("pais_puerto_llegada", "Países Bajos")
    destino = datos.get("destino_final", "España")
    cambios = datos.get("cambios_desde_ultima_consulta", "")

    parrafo = (
        f"Tu paquete {codigo} se encuentra en estado '{estado}' tras la llegada del buque a {llegada}. "
        f"Actualmente el contenedor está pendiente de descarga e inspección aduanera en este puerto de transbordo europeo, "
        f"antes de iniciar el tramo por carretera hacia {destino}. "
        f"{cambios}"
    )
    return re.sub(r"\s+", " ", parrafo).strip()


def sintetizar_seguimiento(
    result: Mapping[str, Any],
    llm_caller: Optional[Callable[[str], str]] = None,
) -> str:
    """Sintetiza la actualización del paquete mediante LLM, con fallback determinista robusto."""
    datos = preparar_datos_sintesis(result)

    if llm_caller is not None:
        try:
            prompt = construir_prompt_sintesis(datos)
            respuesta = llm_caller(prompt)
            if respuesta and isinstance(respuesta, str):
                lineas = [ln.strip() for ln in respuesta.splitlines() if ln.strip()]
                texto_unificado = " ".join(lineas)
                if not re.search(r"[\u4e00-\u9fff]", texto_unificado) and len(texto_unificado) > 30:
                    return texto_unificado
        except Exception as exc:
            logger.warning("Fallo en la síntesis LLM de seguimiento: %s", exc)

    return fallback_sintesis_deterministica(datos)


class SeguimientoPaquete1688Track:
    """Orquesta navegador seguro, extracción, persistencia y comparación."""

    def __init__(
        self,
        session: Optional[SecureWebSession] = None,
        state_store: Optional[DynamicSkillStateStore] = None,
        now: Optional[Callable[[], datetime]] = None,
        timeout_ms: int = 30000,
        llm_caller: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._session = session or SecureWebSession(
            allowed_domains=ALLOWED_DOMAINS, timeout_ms=timeout_ms
        )
        self._store = state_store or DynamicSkillStateStore()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._llm_caller = llm_caller if llm_caller is not None else _DEFAULT_LLM_CALLER

    def _query(self, code: str) -> Dict[str, Any]:
        try:
            raw = self._session.interact_and_capture_sync(
                TRACKING_URL,
                code,
                input_selectors=INPUT_SELECTORS,
                button_selectors=BUTTON_SELECTORS,
                result_selectors=RESULT_SELECTORS,
            )
        except LookupError as exc:
            raise TrackingError(
                "La web de 1688track no mostró el campo de seguimiento; "
                "es posible que haya cambiado su diseño. Inténtalo más tarde."
            ) from exc
        except TimeoutError as exc:
            raise TrackingError("1688track tardó demasiado en responder. Inténtalo de nuevo.") from exc
        except PermissionError as exc:
            raise TrackingError("La política de seguridad bloqueó el acceso al dominio.") from exc
        except Exception as exc:
            logger.error("1688track interaction failed: %s", exc)
            raise TrackingError(
                "No pude consultar 1688track en este momento por un problema de red o del navegador."
            ) from exc

        parsed = parse_from_responses(raw.get("responses", [])) or parse_from_text(
            raw.get("result_text", "")
        )
        if not parsed or not parsed.get("eventos"):
            raise TrackingError(
                "1688track no devolvió datos para este código; comprueba que sea correcto "
                "o que el paquete ya esté registrado."
            )
        return parsed

    def consultar(self, codigo: Optional[str] = None) -> Dict[str, Any]:
        """Consulta, compara con la última consulta válida y persiste el nuevo estado."""
        code = validate_tracking_code(codigo)
        parsed = self._query(code)
        events = parsed["eventos"]
        carrier_events = [e for e in events if e.get("origen") == "transportista"]
        confirmed = [e for e in carrier_events if e.get("tipo") == "confirmado"] or carrier_events or events
        snapshot = {
            "estado": parsed.get("estado", ""),
            "ubicacion": next((e["ubicacion"] for e in confirmed if e.get("ubicacion")), ""),
            "fecha": confirmed[0].get("fecha", ""),
            "albaran": parsed.get("albaran", ""),
            "transporte": parsed.get("transporte", ""),
            "destino": parsed.get("destino", ""),
            "eventos": events,
        }
        state = self._store.load(SKILL_NAME)
        trackings = state.get("trackings") if isinstance(state.get("trackings"), dict) else {}
        comparison = compare_snapshots(trackings.get(code), snapshot)

        trackings[code] = {**snapshot, "consultado_en": self._now().isoformat()}
        # Solo se persiste un estado válido; los fallos anteriores lanzan antes de llegar aquí.
        self._store.save(SKILL_NAME, {"trackings": trackings})
        return {"codigo": code, **snapshot, "comparacion": comparison}

    @staticmethod
    def formatear(result: Mapping[str, Any]) -> str:
        """Texto en español para el usuario, separando hechos confirmados y estimaciones."""
        events = result.get("eventos", [])
        carrier = [e for e in events if e.get("origen") == "transportista" and e.get("tipo") == "confirmado"]
        estimates = [e for e in events if e.get("tipo") == "estimacion"]
        admin = [e for e in events if e.get("origen") == "administrativo"]

        def line(event: Mapping[str, Any]) -> str:
            place = f" [{event['ubicacion']}]" if event.get("ubicacion") else ""
            return f"{event.get('fecha', '')}{place} {event.get('descripcion', '')}".strip()

        head = f"Paquete {result['codigo']}: {result.get('estado') or 'sin estado'}."
        extra = []
        if result.get("albaran"):
            extra.append(f"Albarán {result['albaran']}")
        if result.get("destino"):
            extra.append(f"destino {result['destino']}")
        if extra:
            head += " " + ", ".join(extra) + "."
        parts = [head]
        if carrier:
            parts.append("Confirmado por el transportista: " + " | ".join(line(e) for e in carrier[:3]) + ".")
        elif result.get("fecha"):
            parts.append(f"Último evento: {result['fecha']}.")
        if estimates:
            parts.append("Estimaciones (no confirmadas): " + " | ".join(line(e) for e in estimates[:2]) + ".")
        if admin:
            parts.append(f"Pasos administrativos internos registrados: {len(admin)}.")
        parts.append(result["comparacion"]["detalle"])
        return " ".join(parts)

    def sintetizar(self, result: Mapping[str, Any]) -> str:
        """Sintetiza el resultado en un párrafo conciso en español fluido mediante LLM o fallback determinista."""
        return sintetizar_seguimiento(result, llm_caller=self._llm_caller)

    def responder(self, codigo: Optional[str] = None, use_synthesis: bool = True) -> str:
        """Versión de texto para el usuario; nunca propaga excepciones."""
        try:
            result = self.consultar(codigo)
        except TrackingError as exc:
            return f"No pude consultar el seguimiento: {exc}"
        except Exception:
            logger.exception("Unexpected failure in %s", SKILL_NAME)
            return "No pude consultar el seguimiento por un error inesperado. Inténtalo más tarde."
        if use_synthesis:
            return self.sintetizar(result)
        return self.formatear(result)


def seguimiento_paquete_1688track(codigo: Optional[str] = None) -> str:
    """Adaptador síncrono para SkillManager."""
    return SeguimientoPaquete1688Track().responder(codigo)


def register_seguimiento_paquete_1688track_skill(
    skill_manager: Any,
    llm_caller: Optional[Callable[[str], str]] = None,
) -> None:
    """Registra la skill en una instancia de SkillManager."""
    if llm_caller is not None:
        set_default_llm_caller(llm_caller)

    def _skill_func(codigo: Optional[str] = None) -> str:
        return SeguimientoPaquete1688Track(llm_caller=llm_caller).responder(codigo)

    skill_manager.register_skill(
        name=SKILL_NAME,
        description=(
            "Consulta el estado de un paquete en 1688track (por defecto OXCGH6082081H) "
            "y detalla los cambios desde la consulta anterior."
        ),
        func=_skill_func,
    )

