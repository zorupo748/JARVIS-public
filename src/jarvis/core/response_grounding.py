"""Conservative grounding for conversation without observed tool results."""

import re

DIRECT_RESPONSE_EVIDENCE_CONTRACT = """No hay un resultado externo verificado para este turno.
No afirmes datos externos actuales que no hayas observado: ubicación de un paquete,
precios, versión publicada, estado de servicios o resultados de tracking.
Un identificador, la memoria o una respuesta previa del asistente no son evidencia
de una consulta actual. Si falta una consulta real, dilo y pide contexto; nunca
inventa una ubicación, estado, precio o resultado a partir de un código.
Puedes responder preguntas generales usando conocimientos estables."""


def unbound_identifier_response(user_request: str) -> str | None:
    """An isolated code supplies no observed facts and must not trigger guessing."""
    text = user_request.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{5,127}", text) and any(c.isalpha() for c in text) and any(c.isdigit() for c in text):
        return "He recibido un identificador, pero no tengo una consulta verificada asociada. Dime qué quieres consultar y en qué servicio."
    return None
