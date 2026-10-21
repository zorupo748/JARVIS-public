import os
import re
import traceback
import ast
import json
import queue
import sys
import threading
from datetime import datetime, timedelta
import unicodedata
from pathlib import Path
from tavily import TavilyClient
from jarvis.core.config import (
    DYNAMIC_SKILLS_DISABLED_MESSAGE,
    dynamic_skills_enabled,
    get_gemini_api_key,
    get_local_device_credentials,
)
from jarvis.core.model_router import ModelRouter, ModelRole
from jarvis.core.orchestrator import (
    PlanExecutor,
    TaskPlan,
    TaskStep,
    create_sequential_plan,
    create_task_plan,
    es_peticion_compuesta,
    generar_plan_dinamico,
)
from jarvis.ui.overlay import mostrar_notificacion
from jarvis.core.game_detector import GameDetector
from jarvis.core.capability_router import (
    CapabilityDecision,
    CapabilityRouter,
)
from jarvis.skills.base import SkillManager
from jarvis.skills.seguimiento_paquete_1688track import (
    SKILL_NAME as TRACKING_SKILL_NAME,
    extract_tracking_code,
    register_seguimiento_paquete_1688track_skill,
)
from jarvis.skills.printer_3d import KlipperPrinterSkill
from jarvis.tools.web.web_search import WebSearchTool
from jarvis.core.memory import MemoryManager
from jarvis.skills.vision_skill import VisionSkill
from jarvis.core.audio_queue_manager import SpeechQueueManager
from jarvis.core.tts_engine import HybridTTS
from jarvis.core.stt_engine import STTEngine
from jarvis.skills.workspace_skill import WorkspaceSkill
from jarvis.scheduler.task_scheduler import TaskScheduler
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.security.policy_core import ConfirmationLedger, DeterministicPolicyEvaluator
from jarvis.security.session import SecuritySession
from jarvis.security.local_console_verifier import LocalConsoleVerifier
from jarvis.identity.registry import UserRegistry
from jarvis.core.input_events import InputSource, PendingInput, classify_stdin_source
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService
from jarvis.core.trusted_external_source_research import TrustedWebExternalSourceResearchProvider
from jarvis.core.dependency_resolver import dependency_block_message
from jarvis.core.safe_skill_deployment import SafeSkillDeploymentService
from jarvis.core.safe_skill_execution import ExecutionFailureKind, SafeSkillExecutionService
from jarvis.core.dynamic_skill_state import DynamicSkillStateStore
from jarvis.core.safe_skill_pipeline import PendingSkillExecution, PendingSkillInstallation, SafeSkillPipeline
from jarvis.core.dynamic_skill_response import synthesize_dynamic_skill_response
from jarvis.core.dynamic_skill_input import DynamicSkillInputSession
from jarvis.core.response_grounding import DIRECT_RESPONSE_EVIDENCE_CONTRACT, unbound_identifier_response
from jarvis.core.session_skill_grants import SessionSkillGrantStore
from jarvis.core.dynamic_skill_repair import (
    DynamicSkillRepairCoordinator,
    PendingDynamicSkillRepairRetry,
    PreparedDynamicSkillRepair,
)

# --- ESTADO GLOBAL DEL SISTEMA ---
class JarvisState:
    simulacion: bool = False
    responder_con_voz: bool = False  # Nuevo interruptor dinámico
    gaming_mode: bool = False        # Modo Gaming: VRAM al 0% para videojuegos

estado = JarvisState()
DYNAMIC_SKILLS_DIR = Path("src/jarvis/skills/dynamic")

CONTEXTO_USUARIO = """Eres JARVIS. 
Usuario: Diego. 
Responde de forma directa, conversacional y sin introducciones largas.
REGLA CRÍTICA: Tienes la capacidad de buscar en internet ('buscar_en_internet'). Si te preguntan por datos en tiempo real, eventos, fechas, resultados o información factual que no está en tu memoria, NUNCA sugieras preguntar a otros asistentes (Siri/Google) ni digas que no sabes. Utiliza siempre la herramienta de búsqueda."""

print("\n=== INICIANDO JARVIS (SISTEMA INTEGRAL) ===")
router = ModelRouter(
    groq_api_key=os.getenv("GROQ_API_KEY", None),
    gemini_api_key=get_gemini_api_key(),
)
capability_router = CapabilityRouter(
    model_classifier=lambda prompt: router.route(ModelRole.SPEECH, prompt),
    tracking_skill_name=TRACKING_SKILL_NAME,
)
skills = SkillManager()
confirmation_ledger = ConfirmationLedger()
policy_evaluator = DeterministicPolicyEvaluator(
    confirmation_ledger=confirmation_ledger,
)
skill_dispatcher = SkillDispatcher(
    skills,
    evaluator=policy_evaluator,
    confirmation_ledger=confirmation_ledger,
)

user_registry = UserRegistry()

local_device_id, local_device_token = get_local_device_credentials()

local_console_verifier = LocalConsoleVerifier(
    user_registry,
    device_id=local_device_id,
    device_token=local_device_token,
    trusted_devices_path=Path(__file__).resolve().parent
    / "data"
    / "trusted_devices.json",
)
security_session = SecuritySession(
    registry=user_registry,
    trusted_issuers=(local_console_verifier.issuer,),
)
safe_skill_authoring = SafeSkillAuthoringService(
    router,
    external_source_research=TrustedWebExternalSourceResearchProvider(),
)
safe_skill_deployment = SafeSkillDeploymentService(
    dynamic_skills_dir=DYNAMIC_SKILLS_DIR,
    evaluator=policy_evaluator,
    confirmation_ledger=confirmation_ledger,
)
dynamic_skill_state_store = DynamicSkillStateStore()
safe_skill_execution = SafeSkillExecutionService(
    skill_dispatcher,
    dynamic_skills_dir=DYNAMIC_SKILLS_DIR,
    state_store=dynamic_skill_state_store,
)
safe_skill_pipeline = SafeSkillPipeline(
    safe_skill_authoring,
    safe_skill_deployment,
    safe_skill_execution,
    model_router=router,
)
dynamic_skill_repair_coordinator = DynamicSkillRepairCoordinator(
    safe_skill_pipeline,
    dynamic_skills_dir=DYNAMIC_SKILLS_DIR,
    state_store=dynamic_skill_state_store,
)
scheduler = TaskScheduler()
memory = MemoryManager(storage_path="memory/jarvis_memory.json")
tts = HybridTTS()
stt = STTEngine()
chat_history = []
pending_inputs = queue.Queue()
cancel_event = threading.Event()
pending_skill_installation: PendingSkillInstallation | None = None
pending_skill_execution: PendingSkillExecution | None = None
pending_dynamic_skill_repair: PreparedDynamicSkillRepair | None = None
pending_dynamic_skill_repair_retry: PendingDynamicSkillRepairRetry | None = None
session_skill_grants = SessionSkillGrantStore()
dynamic_skill_input_session = DynamicSkillInputSession()

# Indica cuándo el prompt principal está esperando una entrada del usuario.
# Los ENTER vacíos solo deben activar voz en ese momento.
console_prompt_active = threading.Event()

TASK_INTERRUPTED = object()

# Blindaje estricto de tipos de memoria al arrancar
if not isinstance(memory.data, dict):
    memory.data = {}
if not isinstance(memory.data.get("facts"), list):
    memory.data["facts"] = []

try:
    # --- SUBSISTEMA DE RED (BÚSQUEDA WEB) ---
    web_tool = WebSearchTool()

    def buscar_en_internet_wrapper(query: str) -> str:
        print(f" > [RED] Buscando en internet: '{query}'...")
        try:
            resultado = web_tool.execute(query=query)
            texto_resultado = str(resultado.content)
            if len(texto_resultado) < 150 or "no se encontraron resultados" in texto_resultado.lower():
                return "[Aviso del sistema: El buscador web no ha retornado información útil o está vacía para esta consulta.]"
            return texto_resultado
        except Exception as e:
            return f"[Aviso del sistema: Error en la búsqueda web: {e}]"

    skills.register_skill("buscar_en_internet", "Busca en internet en tiempo real.", buscar_en_internet_wrapper)
    print("[OK] Subsistema de Búsqueda Web conectado.")

    # --- SUBSISTEMA KLIPPER ---
    printer = KlipperPrinterSkill(host="http://192.168.1.145")
    skills.register_skill("estado_impresora", "Consulta estado de la impresora 3D", printer.get_status)
    skills.register_skill("listar_archivos", "Muestra los G-Code listos para imprimir", printer.list_files)
    skills.register_skill("subir_e_imprimir", "Sube un archivo .gcode e inicia la impresión.", printer.upload_and_print_local_file)
    skills.register_skill("parada_emergencia", "Detiene la impresión 3D en curso.", printer.emergency_stop)
    print("[OK] Subsistema Klipper conectado.")

    # --- SUBSISTEMA DE VISIÓN ---
    vision_skill = VisionSkill()
    skills.register_skill("tomar_captura_pantalla", "Toma una captura del monitor.", vision_skill.tomar_captura_pantalla)
    skills.register_skill(
        "analizar_codigo_activo",
        "Analiza el archivo activo de VS Code y usa visión como fallback.",
        router.ejecutar_pipeline_cognitivo,
    )
    print("[OK] Subsistema de Visión conectado.")
except Exception as e:
    print(f"[WARN] Error al cargar subsistemas: {e}")

    # --- SUBSISTEMA DE WORKSPACE ---
    workspace = WorkspaceSkill()
    skills.register_skill("leer_archivo_workspace", "Lee un archivo de código del repositorio.", workspace.leer_archivo)
    skills.register_skill("listar_archivos_workspace", "Lista los archivos del repositorio.", workspace.listar_archivos)
    print("[OK] Subsistema de Workspace conectado.")

# Fallbacks seguros si alguno de los subsistemas no pudo cargarse
if "buscar_en_internet" not in skills.get_catalog():
    def buscar_en_internet_fallback(query: str) -> str:
        return "No pude acceder a internet en este momento."
    skills.register_skill("buscar_en_internet", "Fallback para búsqueda web.", buscar_en_internet_fallback)

if "tomar_captura_pantalla" not in skills.get_catalog():
    def tomar_captura_pantalla_fallback() -> str:
        return "No se pudo inicializar la captura de pantalla."
    skills.register_skill("tomar_captura_pantalla", "Fallback para captura de pantalla.", tomar_captura_pantalla_fallback)

# --- SUBSISTEMA DE MEMORIA PERMANENTE ---
def guardar_hecho_wrapper(hecho: str) -> str:
    return memory.add_fact(hecho)

skills.register_skill("guardar_hecho", "Guarda información personal o preferencias de Diego.", guardar_hecho_wrapper)
print("[OK] Subsistema de Memoria Permanente conectado.")

# --- SKILL DE SEGUIMIENTO DE PAQUETES (1688track, navegador aislado) ---
register_seguimiento_paquete_1688track_skill(
    skills,
    llm_caller=lambda prompt: router.route(ModelRole.SPEECH, prompt),
)
print("[OK] Skill de seguimiento de paquetes conectada.")

def emitir_mensaje(texto: str):
    """Callback secuencial para la cola de voz y mensajes."""
    print(f"\nJARVIS: {texto}")
    # Proyectar en el HUD flotante sin robar el foco
    mostrar_notificacion("JARVIS", str(texto)[:180], duracion_ms=5000)
    # Solo ejecuta el motor TTS si el interruptor está activado
    if estado.responder_con_voz:
        tts.speak(texto)

emitir_mensaje.stop = getattr(tts, "stop", lambda: None)


def es_comando_cancelacion(texto: str) -> bool:
    """Detecta órdenes explícitas de cancelación (cancela, detén, para, etc.) evitando falsos positivos."""
    if not texto or not isinstance(texto, str):
        return False
    t = texto.strip().lower()
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = re.sub(r"[^\w\s]", "", t).strip()

    patron = r"^(?:oye\s+)?(?:jarvis\s+)?(?:cancela|cancelar|deten|detente|detener|para|parar|abortar|stop)(?:\s+(?:la\s+)?(?:tarea|ejecucion|plan|accion|operacion|proceso|todo|esto))?$"
    if re.match(patron, t):
        return True

    frases_cancelacion = {
        "cancela", "cancelar",
        "deten", "detente", "detener",
        "para", "parar", "parate",
        "abortar", "stop",
        "jarvis cancela", "jarvis para", "jarvis deten", "jarvis detente",
        "cancela la tarea", "cancela el plan", "cancela la ejecucion",
        "deten la tarea", "deten el plan", "deten la ejecucion",
        "para la tarea", "para el plan", "para la ejecucion",
        "deten esto", "cancela esto", "para esto",
    }
    return t in frases_cancelacion


def es_comando_cancelacion_impresora(texto: str) -> bool:
    """Distingue si una orden de parada va dirigida explícitamente a la impresora 3D."""
    if not texto or not isinstance(texto, str):
        return False
    t = texto.lower()
    return any(k in t for k in ("impresora", "impresion", "impresión", "imprimir", "3d", "klipper", "m112"))


def es_comando_modo_juego(texto: str) -> tuple[bool, bool]:
    """Determina si la entrada es un comando para activar o desactivar el Modo Gaming."""
    if not texto or not isinstance(texto, str):
        return False, False
    t = texto.lower().strip()
    if not any(k in t for k in ("modo juego", "modo gaming", "gaming mode")):
        return False, False
    if any(w in t for w in ("desactiv", "quitar", "apagar", "off", "cancelar", "cerrar")):
        return True, False
    if any(w in t for w in ("activ", "iniciar", "poner", "encender", "on", "start", "entrar")):
        return True, True
    return False, False


def registrar_en_historial(role: str, content: object) -> None:
    """Mantiene las últimas 10 intervenciones para el contexto del modelo."""
    chat_history.append({"role": role, "content": str(content)})
    del chat_history[:-10]


def responder_dynamic_skill(
    skill_name: str,
    original_command: str,
    execution_result,
    identity_context=None,
) -> str:
    """Show input prompts directly; synthesize only completed visible results."""
    identity_context = identity_context or security_session.context()
    respuesta = dynamic_skill_input_session.accept_result(
        execution_result, original_command=original_command, user_id=identity_context.user_id,
    )
    if respuesta is None:
        respuesta = synthesize_dynamic_skill_response(router, skill_name, original_command, execution_result.result)
    print(f"[SKILL:{skill_name}] Resultado: {respuesta}")
    speech_queue.add_message(respuesta)
    registrar_en_historial("assistant", respuesta)
    memory.add_interaction("jarvis", respuesta)
    return respuesta


def intentar_autorreparacion_dynamic_skill(
    skill_name: str,
    original_command: str,
    execution_result,
    identity_context,
):
    """Prepare at most one reviewed repair; deployment still awaits confirmation."""
    global pending_dynamic_skill_repair
    if not dynamic_skill_repair_coordinator.is_repairable_failure(execution_result):
        return False

    error = execution_result.failure_reason or "error interno sin detalle"
    aviso = (
        f"He visto que la skill '{skill_name}' ha fallado por \"{error}\". "
        "Voy a intentar repararla."
    )
    print(f"[SKILL:{skill_name}] {aviso}")
    speech_queue.add_message(aviso)
    repair_preparation = ejecutar_cancelable(
        dynamic_skill_repair_coordinator.prepare_repair,
        execution_result,
        original_command=original_command,
        identity=identity_context,
    )
    if repair_preparation is TASK_INTERRUPTED:
        return True
    if not repair_preparation.ready_for_confirmation:
        reason = repair_preparation.failure_reason or "la revisión segura no aprobó la reparación"
        respuesta = f"No he podido reparar automáticamente '{skill_name}': {reason}."
        print(f"[SKILL:{skill_name}] {respuesta}")
        speech_queue.add_message(respuesta)
        registrar_en_historial("assistant", respuesta)
        return True

    pending_dynamic_skill_repair = repair_preparation
    respuesta = (
        f"He preparado una reparación para '{skill_name}'. "
        "¿Quieres instalarla?"
    )
    print(f"[SKILL:{skill_name}] {respuesta}")
    speech_queue.add_message(respuesta)
    registrar_en_historial("assistant", respuesta)
    return True


def extraer_dato_personal(texto: str) -> str | None:
    """Extrae hechos explícitos del usuario sin convertir conversación genérica en memoria."""
    patrones = (
        r"\b(?:apunta|anota|recuerda|guarda)\s+(?:que\s+)?(.+)$",
        r"\bme llamo\s+(.+)$",
        r"\bmi nombre es\s+(.+)$",
        r"\bestudio\s+(.+)$",
        r"\btrabajo como\s+(.+)$",
        r"\bvivo en\s+(.+)$",
        r"\bmi dispositivo(?: principal)? es\s+(.+)$",
    )
    for patron in patrones:
        coincidencia = re.search(patron, texto.strip(), re.IGNORECASE)
        if coincidencia:
            hecho = coincidencia.group(1).strip(" .,!?")
            if hecho:
                return hecho
    return None


def analizar_recordatorio(texto: str) -> tuple[str, datetime] | None:
    """Interpreta recordatorios relativos en minutos/horas o con hora HH:MM."""
    coincidencia = re.search(
        r"recu(?:é|e)rd(?:ame|arme)\s+(.+?)\s+en\s+(\d+)\s+(minuto|minutos|hora|horas)\b",
        texto,
        re.IGNORECASE,
    )
    if coincidencia:
        mensaje = coincidencia.group(1).strip(" .,!? ")
        cantidad = int(coincidencia.group(2))
        unidad = coincidencia.group(3).lower()
        delta = timedelta(minutes=cantidad if unidad.startswith("min") else cantidad * 60)
        return mensaje, datetime.now() + delta

    coincidencia = re.search(
        r"recu(?:é|e)rd(?:ame|arme)\s+(.+?)\s+a\s+las\s+(\d{1,2}):(\d{2})\b",
        texto,
        re.IGNORECASE,
    )
    if coincidencia:
        mensaje = coincidencia.group(1).strip(" .,!? ")
        objetivo = datetime.now().replace(
            hour=int(coincidencia.group(2)),
            minute=int(coincidencia.group(3)),
            second=0,
            microsecond=0,
        )
        if objetivo <= datetime.now():
            objetivo += timedelta(days=1)
        return mensaje, objetivo
    return None


def mostrar_recordatorios_pendientes() -> None:
    """Muestra y marca como atendidos los recordatorios vencidos al iniciar."""
    for recordatorio in memory.get_due_reminders():
        print(
            f"[RECORDATORIO] {recordatorio['mensaje']} "
            f"(programado: {recordatorio['timestamp_objetivo']})"
        )
        memory.complete_reminder(recordatorio["id"])


def ejecutar_cancelable(func, *args, **kwargs):
    """Ejecuta una tarea en segundo plano y descarta su resultado si llega una entrada.

    La cancelación es cooperativa: propaga la señal al objeto ejecutor, purga colas
    obsoletas de audio y descarta resultados tardíos.
    """
    resultado = queue.Queue(maxsize=1)
    tarea_cancelada = threading.Event()

    def worker():
        try:
            valor = func(*args, **kwargs)
            if not tarea_cancelada.is_set():
                resultado.put((True, valor))
        except Exception as exc:
            if not tarea_cancelada.is_set():
                resultado.put((False, exc))

    threading.Thread(target=worker, daemon=True).start()

    while True:
        try:
            ok, valor = resultado.get(timeout=0.1)
            if ok:
                return valor
            raise valor
        except queue.Empty:
            try:
                nuevo_input = pending_inputs.get_nowait()
            except queue.Empty:
                continue

            tarea_cancelada.set()
            cancel_event.set()

            # Propagación explícita de cancelación al objeto ejecutor
            target_obj = getattr(func, "__self__", func)
            if hasattr(target_obj, "cancel") and callable(target_obj.cancel):
                try:
                    target_obj.cancel()
                except Exception as cancel_exc:
                    print(f" > [CANCEL] Error notificando cancelación: {cancel_exc}")

            # Limpieza de cola de audio obsoleta e interrupción de sonido
            try:
                speech_queue.clear()
                tts.stop()
            except Exception:
                pass

            pending_inputs.put(nuevo_input)
            print("[INTERRUPCIÓN] Tarea cancelada; procesando la nueva directiva.")
            return TASK_INTERRUPTED


def iniciar_lector_de_consola() -> None:
    """Lee entradas sin pintar UI; el bucle principal controla el prompt visible."""
    def lector():
        input_source = classify_stdin_source(sys.stdin)

        while True:
            try:
                entrada = sys.stdin.readline()

                if not entrada:
                    pending_inputs.put(
                        PendingInput("salir", input_source)
                    )
                    return

                texto = entrada.strip()

                # Mientras JARVIS está trabajando permitimos interrupciones escritas,
                # pero ignoramos ENTER vacíos para que no queden en cola y activen
                # accidentalmente el micrófono en la siguiente interacción.
                if not texto and not console_prompt_active.is_set():
                    continue

                pending_inputs.put(
                    PendingInput(texto, input_source)
                )
            except (EOFError, KeyboardInterrupt):
                pending_inputs.put(
                    PendingInput("salir", input_source)
                )
                return

    threading.Thread(target=lector, daemon=True, name="jarvis-console-reader").start()


def es_correccion_explicita(texto: str) -> bool:
    texto_lower = texto.lower()
    return any(frase in texto_lower for frase in (
        "eso no funciona",
        "no funciona",
        "está mal",
        "esta mal",
        "te has equivocado",
        "corrige esto",
        "corrígelo",
        "corrigelo",
        "hazlo bien",
    ))


def es_problema_tecnico(texto: str) -> bool:
    texto_lower = texto.lower()
    return any(termino in texto_lower for termino in (
        "código", "codigo", "error", "fallo", "bug", "script", "api",
        "subprocess", "comando", "hardware", "gpu", "cpu", "ram",
        "sqlite", "base de datos", "impresora", "klipper", "red local",
    ))


def aprender_skill_de_caso(objetivo: str) -> None:
    """Keep legacy automatic repair fail-closed until an explicit /skill request."""

    del objetivo
    print(
        "[APRENDIZAJE] La reparacion automatica de skills legacy esta desactivada. "
        "Usa una solicitud explicita /skill para iniciar el pipeline seguro."
    )

def es_peticion_de_skill(texto: str) -> bool:
    """Detecta creación o mantenimiento de skills antes de memoria y del router."""
    texto_lower = texto.lower()
    if texto_lower.startswith("/skill "):
        return True

    frases_factoría = (
        "crea una skill",
        "crear una skill",
        "genera una skill",
        "generar una skill",
        "programa una skill",
        "programar una skill",
        "modifica la skill",
        "modificar la skill",
        "reescribe la skill",
        "reescribir la skill",
        "actualiza la skill",
        "actualizar la skill",
        "crea una habilidad",
        "crear una habilidad",
        "programa una habilidad",
        "programar una habilidad",
        "modifica la habilidad",
        "modificar la habilidad",
        "reescribe la habilidad",
        "reescribir la habilidad",
        "actualiza la habilidad",
        "actualizar la habilidad",
    )
    if any(frase in texto_lower for frase in frases_factoría):
        return True

    verbos_mantenimiento = (
        "modifica", "modificar", "arregla", "arreglar", "reescribe", "reescribir",
        "cambia", "cambiar", "actualiza", "actualizar",
    )
    if not any(verbo in texto_lower for verbo in verbos_mantenimiento):
        return False

    dynamic_dir = DYNAMIC_SKILLS_DIR
    nombres_skills = {
        archivo.stem.lower()
        for archivo in dynamic_dir.glob("*.py")
        if archivo.is_file() and archivo.name != "__init__.py"
    }
    return any(
        re.search(rf"(?<![\w-]){re.escape(nombre)}(?![\w-])", texto_lower)
        for nombre in nombres_skills
    )


def obtener_skill_existente(texto: str) -> str | None:
    """Devuelve el nombre de una skill dinámica mencionada en el texto."""
    texto_lower = texto.lower()
    dynamic_dir = DYNAMIC_SKILLS_DIR
    for archivo in dynamic_dir.glob("*.py"):
        if archivo.is_file() and archivo.name != "__init__.py":
            nombre = archivo.stem
            if re.search(rf"(?<![\w-]){re.escape(nombre.lower())}(?![\w-])", texto_lower):
                return nombre
    return None


def obtener_skill_a_ejecutar(texto: str) -> str | None:
    """Detecta un comando verbal seguido del nombre de una skill dinámica."""
    texto_lower = texto.lower()
    verbos_ejecucion = r"(?:ejecuta|corre|lanza|activa)"
    dynamic_dir = DYNAMIC_SKILLS_DIR
    for archivo in dynamic_dir.glob("*.py"):
        if not archivo.is_file() or archivo.name == "__init__.py":
            continue
        nombre = archivo.stem
        patron = rf"\b{verbos_ejecucion}\b.*?(?<![\w-]){re.escape(nombre.lower())}(?![\w-])"
        if re.search(patron, texto_lower):
            return nombre
    return None


def analizar_programacion_skill(texto: str) -> tuple[str, int, int] | None:
    """Detecta órdenes naturales para programar una skill diariamente."""
    texto_lower = texto.lower()
    if not any(verbo in texto_lower for verbo in ("programa", "programar", "planifica", "agenda")):
        return None
    coincidencia_hora = re.search(r"\b(?:a las|para las)\s+(\d{1,2}):(\d{2})\b", texto_lower)
    if not coincidencia_hora:
        return None

    nombre_skill = obtener_skill_existente(texto)
    if not nombre_skill:
        nombre_skill = obtener_skill_a_ejecutar(texto)
    if not nombre_skill:
        return None
    return nombre_skill, int(coincidencia_hora.group(1)), int(coincidencia_hora.group(2))


def ejecutar_skill_existente(
    nombre: str,
    identity_context,
    parameters: dict[str, object] | None = None,
):
    """Execute only through hash verification and SkillDispatcher authorization."""

    return safe_skill_pipeline.execute_installed(
        nombre,
        identity=identity_context,
        parameters=parameters or {},
    )


def clasificar_confirmacion_instalacion(texto: str) -> bool | None:
    """Return an explicit textual confirmation without granting permission itself."""

    normalizado = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode().casefold().strip()
    if normalizado in {"si", "s", "confirmar", "instalar"}:
        return True
    if normalizado in {"no", "n", "cancelar"}:
        return False
    return None


def resumir_fallo_authoring(resultado) -> str:
    """Give the user one actionable issue without leaking proposal internals."""

    if resultado.failure_reason:
        from jarvis.core.skill_error_handler import clean_executive_summary
        return clean_executive_summary(resultado.failure_reason)
    if resultado.review_results and resultado.review_results[-1].issues:
        return resultado.review_results[-1].issues[0].description
    return "la propuesta no superó la validación y revisión técnica."


def autorizar_skill_solicitada(
    solicitud_original: str,
    identity_context,
    *,
    mensaje_inicio: str = "Estoy preparando la skill...",
):
    """Run the same authoring and installation-preflight flow for every entry point."""
    print(f"[SKILL] {mensaje_inicio}")
    try:
        authoring_result = ejecutar_cancelable(
            safe_skill_pipeline.author,
            solicitud_original,
            existing_skill_name=obtener_skill_existente(solicitud_original),
        )
    except Exception as exc:
        from jarvis.core.skill_error_handler import SkillErrorHandler
        handler = SkillErrorHandler(model_router=router)
        decision = handler.triage(exc, phase="creación", user_request=solicitud_original)
        return (f"No pude crear la skill: {decision.executive_summary}", None)

    if authoring_result is TASK_INTERRUPTED:
        return TASK_INTERRUPTED, None
    if not authoring_result.success:
        return (
            f"No pude crear la skill: {resumir_fallo_authoring(authoring_result)}",
            None,
        )

    if authoring_result.unavailable_dependencies:
        return (
            dependency_block_message(
                authoring_result.dependency_results,
                authoring_result.unavailable_dependencies,
            ),
            None,
        )

    preparation = safe_skill_pipeline.prepare_installation(
        authoring_result,
        original_user_request=solicitud_original,
        identity=identity_context,
    )
    if preparation.confirmation_required and preparation.pending is not None:
        dependencias = ", ".join(authoring_result.declared_dependencies) or "ninguna"
        return (
            f"La skill '{preparation.pending.skill_name}' ha superado validacion y revision. "
            f"Dependencias: {dependencias}. Quieres instalarla?",
            preparation.pending,
        )
    return (
        "No pude preparar la instalacion de la skill: "
        f"{preparation.deployment_result.failure_reason or 'la politica exige mas verificaciones.'}",
        None,
    )


_TOKENS_GENERICOS_SKILL = {
    "actual", "actuales", "actualizacion", "actualizaciones", "anterior",
    "anteriores", "cambio", "cambios", "comprobar", "comprueba", "consulta",
    "consultar", "datos", "ejecutar", "estado", "estados", "informacion",
    "mira", "mirar", "resultado", "resultados", "revisar", "revisa", "guardar",
    "guarda", "recordar", "recuerda", "ultima", "ultimas", "ultimo", "ultimos",
    "version", "versiones", "skill", "skills", "ver", "saber", "dime", "donde",
    "paquete", "paquetes", "quiero", "puedas", "cuando", "pregunte", "preguntar",
    "cada", "vez", "para", "con", "desde", "sobre", "una", "unos", "unas",
    "que", "como", "del", "por", "las", "los", "buscar", "busqueda", "muestra",
}


def _tokens_semanticos_skill(valor: str) -> set[str]:
    normalizado = unicodedata.normalize("NFKD", valor)
    normalizado = "".join(
        caracter for caracter in normalizado if not unicodedata.combining(caracter)
    ).casefold().replace("_", " ")
    normalizado = re.sub(r"\bprecio\b", "price", normalizado)
    normalizado = re.sub(r"\bbitcoin\b", "btc bitcoin", normalizado)
    normalizado = re.sub(r"\bethereum\b", "eth ethereum", normalizado)
    return {
        token
        for token in re.findall(r"[a-z0-9]{3,}", normalizado)
        if token not in _TOKENS_GENERICOS_SKILL
    }


def indexar_skills_dinamicas() -> dict[str, str]:
    """Index only names and explicit skill documentation; never inspect implementation."""
    indice: dict[str, str] = {}
    dynamic_dir = DYNAMIC_SKILLS_DIR
    for archivo in dynamic_dir.glob("*.py"):
        if not archivo.is_file() or archivo.name == "__init__.py":
            continue
        try:
            arbol = ast.parse(archivo.read_text(encoding="utf-8"))
            descripciones = [archivo.stem.replace("_", " ")]
            module_docstring = ast.get_docstring(arbol)
            if module_docstring:
                descripciones.append(module_docstring)
            for nodo in arbol.body:
                if (
                    isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and nodo.name == "ejecutar_skill"
                ):
                    entrypoint_docstring = ast.get_docstring(nodo)
                    if entrypoint_docstring:
                        descripciones.append(entrypoint_docstring)
                    break
            if archivo.stem.lower() == "hardwae_monitoring":
                descripciones.extend([
                    "hardware rendimiento estado del sistema sistema pc ordenador equipo",
                    "carga recursos consumo cpu ram gpu gráfica grafica tarjeta gráfica",
                    "temperatura memoria uso monitorización monitorizacion salud del equipo",
                ])
            indice[archivo.stem] = " ".join(dict.fromkeys(descripciones))
        except (OSError, SyntaxError) as exc:
            print(f"[INTENT ROUTER] No se pudo indexar {archivo.name}: {exc}")
    return indice


def resolver_intencion_skill(texto: str) -> str | None:
    """Devuelve la skill cuya descripción coincide claramente con una petición natural."""
    if es_peticion_de_skill(texto) or obtener_skill_a_ejecutar(texto):
        return None

    tokens_usuario = _tokens_semanticos_skill(texto)
    if not tokens_usuario:
        return None

    hardware_terms = {
        "hardware", "rendimiento", "recursos", "recurso", "carga", "consumo",
        "cpu", "ram", "gpu", "grafica", "graficas", "nvidia", "temperatura",
        "ordenador", "computador", "pc", "equipo",
    }
    hardware_context = {
        "estado", "sistema", "revisa", "revisar", "comprueba", "comprobar",
        "mide", "medir", "monitoriza", "monitorizar", "salud", "uso",
    }

    candidatos: list[tuple[str, int, bool]] = []
    for nombre, descripcion in indexar_skills_dinamicas().items():
        anclas_nombre = _tokens_semanticos_skill(nombre)
        tokens_descripcion = _tokens_semanticos_skill(descripcion)
        anclas_encontradas = tokens_usuario & anclas_nombre
        coincidencias_documentadas = tokens_usuario & tokens_descripcion

        if nombre.lower() == "hardwae_monitoring":
            tokens_sin_filtro = set(
                re.findall(
                    r"[a-z0-9]{3,}",
                    unicodedata.normalize("NFKD", texto)
                    .encode("ascii", "ignore")
                    .decode()
                    .casefold(),
                )
            )
            tiene_senal_hardware = bool(tokens_sin_filtro & hardware_terms)
            tiene_contexto_hardware = bool(tokens_sin_filtro & hardware_context)
            if tiene_senal_hardware and (len(coincidencias_documentadas) >= 2 or tiene_contexto_hardware):
                candidatos.append((nombre, 100 + len(coincidencias_documentadas), True))
            continue

        if anclas_encontradas:
            puntuacion = (100 * len(anclas_encontradas)) + (
                2 * len(coincidencias_documentadas)
            )
            candidatos.append((nombre, puntuacion, True))
        elif len(coincidencias_documentadas) >= 2:
            candidatos.append((nombre, 2 * len(coincidencias_documentadas), False))

    if not candidatos:
        return None

    candidatos.sort(key=lambda candidato: candidato[1], reverse=True)
    mejor_nombre, mejor_puntuacion, tiene_ancla = candidatos[0]
    if len(candidatos) > 1:
        segundo_nombre, segundo_puntuacion, segundo_tiene_ancla = candidatos[1]
        margen_requerido = 20 if tiene_ancla or segundo_tiene_ancla else 2
        if (
            mejor_nombre != segundo_nombre
            and mejor_puntuacion - segundo_puntuacion < margen_requerido
        ):
            return None

    if mejor_nombre.lower() == "hardwae_monitoring":
        texto_normalizado = unicodedata.normalize("NFKD", texto)
        tokens_sin_filtro = set(
            re.findall(
                r"[a-z0-9]{3,}",
                texto_normalizado.encode("ascii", "ignore").decode().casefold(),
            )
        )
        tiene_senal_hardware = bool(tokens_sin_filtro & hardware_terms)
        tiene_contexto_hardware = bool(tokens_usuario & hardware_context)
        if tiene_senal_hardware and (mejor_puntuacion >= 2 or tiene_contexto_hardware):
            return mejor_nombre
        return None

    return mejor_nombre if tiene_ancla or mejor_puntuacion >= 4 else None


def resolver_skill_prioritaria(texto: str) -> str | None:
    """Resuelve primero comandos explícitos y después intención semántica."""
    return obtener_skill_a_ejecutar(texto) or resolver_intencion_skill(texto)


def cargar_prompt_de_recuperacion() -> None:
    """Reinyecta una directiva guardada por supervisor.py y consume su archivo."""
    recovery_file = os.getenv("JARVIS_RECOVERY_FILE")
    if not recovery_file:
        return

    recovery_path = Path(recovery_file)
    try:
        payload = json.loads(recovery_path.read_text(encoding="utf-8"))
        prompt = str(payload.get("last_prompt", "")).strip()
        if prompt:
            pending_inputs.put(
                PendingInput(prompt, InputSource.RECOVERY)
            )
            print("[RECUPERACIÓN] Reinyectando la última directiva del usuario.")
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[RECUPERACIÓN] No se pudo leer {recovery_path}: {exc}")
    finally:
        try:
            recovery_path.unlink(missing_ok=True)
        except OSError as exc:
            print(f"[RECUPERACIÓN] No se pudo consumir {recovery_path}: {exc}")


if __name__ == "__main__":
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    print("\nSistemas listos. Ollama: Activo | Simulación: OFF\n")
    speech_queue = SpeechQueueManager(tts_engine_callback=emitir_mensaje)
    mostrar_recordatorios_pendientes()
    scheduler.start()
    print("[OK] Planificador de tareas en segundo plano iniciado.")
    game_detector = GameDetector(
        model_router=router,
        overlay_notifier=mostrar_notificacion,
        check_interval_seconds=3.0,
        state_callback=lambda activo: setattr(estado, "gaming_mode", activo),
    )
    game_detector.start()
    print("[OK] Monitor automático de juegos iniciado.")
    cargar_prompt_de_recuperacion()
    iniciar_lector_de_consola()
    
    while True:
        try:
            # La UI solo reaparece cuando el TTS y la respuesta anterior terminaron.
            speech_queue.queue.join()

            print("\n" + "-"*40)
            print("Tú (Escribe o pulsa ENTER para hablar): ", end="", flush=True)

            console_prompt_active.set()
            try:
                pending_input = pending_inputs.get()
            finally:
                console_prompt_active.clear()

            entrada = pending_input.text
            input_source = pending_input.source

            voice_utterance = None

            if entrada:
                usuario = entrada
                estado.responder_con_voz = False
            else:
                voice_utterance = stt.capture()
                if voice_utterance is None:
                    continue

                usuario = stt.transcribe(voice_utterance)
                estado.responder_con_voz = True

                if not usuario:
                    continue

                print(f"Tú (Voz): {usuario}")

            usuario_limpio = usuario.strip()
            if usuario.lower() in ['salir', 'exit', 'quit']:
                speech_queue.stop()
                scheduler.stop()
                game_detector.stop()
                print("Apagando sistemas...")
                break

            # --- CONMUTADOR DE MODO GAMING (VRAM CERO) ---
            es_gaming, activar_gaming = es_comando_modo_juego(usuario_limpio)
            if es_gaming:
                msg = router.set_gaming_mode(activar_gaming)
                estado.gaming_mode = activar_gaming
                print(f"[MODO JUEGO] {msg}")
                speech_queue.add_message(msg)
                registrar_en_historial("assistant", msg)
                memory.add_interaction("jarvis", msg)
                mostrar_notificacion(
                    "JARVIS - Modo Gaming",
                    "Modo Gaming ACTIVADO: VRAM al 0% para videojuegos." if activar_gaming else "Modo Gaming DESACTIVADO: Modelos locales listos.",
                    duracion_ms=5000,
                )
                continue

            # Gestión de órdenes de cancelación recibidas cuando no hay una tarea en curso
            if es_comando_cancelacion(usuario_limpio):
                if es_comando_cancelacion_impresora(usuario_limpio):
                    try:
                        dispatch_res = skill_dispatcher.dispatch(
                            "parada_emergencia", {}, identity=security_session.context()
                        )
                        msg = f"Orden enviada a la impresora: {dispatch_res.result or dispatch_res.message}"
                    except Exception as err:
                        msg = f"Error al emitir orden de parada a la impresora: {err}"
                else:
                    msg = "No hay ninguna tarea activa que cancelar."
                print(f"\nJARVIS: {msg}")
                speech_queue.add_message(msg)
                registrar_en_historial("assistant", msg)
                memory.add_interaction("jarvis", msg)
                continue

            security_session.begin_interaction()

            if input_source is InputSource.LOCAL_CONSOLE and entrada:
                try:
                    verification = local_console_verifier.verify()
                except RuntimeError as exc:
                    print(f"[SEGURIDAD] Consola local no autenticada: {exc}")
                else:
                    if not security_session.apply_verification(verification):
                        print(
                            "[SEGURIDAD] La verificacion de la consola local "
                            "fue rechazada."
                        )

            identity_context = security_session.context()

            # A real answer to structured skill input precedes every intent,
            # CapabilityRouter, web and general-conversation path.
            if input_source is not InputSource.RECOVERY:
                input_turn = dynamic_skill_input_session.handle_message(
                    usuario_limpio, pipeline=safe_skill_pipeline,
                    grants=session_skill_grants, identity=identity_context,
                )
                if input_turn.handled:
                    if input_turn.pending_execution is not None:
                        pending_skill_execution = input_turn.pending_execution
                    elif input_turn.execution_result is not None:
                        input_execution = input_turn.execution_result
                        if input_execution.executed:
                            responder_dynamic_skill(input_turn.skill_name, input_turn.original_command,
                                                    input_execution, identity_context=identity_context)
                            continue
                        if intentar_autorreparacion_dynamic_skill(
                            input_turn.skill_name, input_turn.original_command, input_execution, identity_context,
                        ):
                            continue
                    respuesta_input = input_turn.message or (
                        "No pude continuar con la skill: " +
                        (input_turn.execution_result.failure_reason or "la política no lo autorizó.")
                    )
                    print(f"[SKILL INPUT] {respuesta_input}")
                    speech_queue.add_message(respuesta_input)
                    registrar_en_historial("assistant", respuesta_input)
                    continue
            elif dynamic_skill_input_session.has_pending_interaction:
                # Recovery cannot answer an input or consume its confirmation.
                continue

            if pending_dynamic_skill_repair is not None:
                confirmation_choice = clasificar_confirmacion_instalacion(usuario_limpio)
                if confirmation_choice is not None:
                    repair_to_install = pending_dynamic_skill_repair
                    pending_dynamic_skill_repair = None
                    if not confirmation_choice:
                        respuesta_cancelacion = "Instalacion de la reparacion cancelada."
                        print(f"[SKILL:{repair_to_install.context.skill_name}] {respuesta_cancelacion}")
                        speech_queue.add_message(respuesta_cancelacion)
                        registrar_en_historial("assistant", respuesta_cancelacion)
                        continue

                    repair_context = repair_to_install.context
                    installation_result = safe_skill_pipeline.confirm_installation(
                        repair_to_install.pending_installation,
                        identity=identity_context,
                    )
                    if not installation_result.installed or not installation_result.source_hash:
                        reason = installation_result.failure_reason or "PolicyCore no autorizo la instalacion."
                        respuesta_instalacion = (
                            f"No he podido instalar la reparacion de '{repair_context.skill_name}': {reason}"
                        )
                        print(f"[SKILL:{repair_context.skill_name}] {respuesta_instalacion}")
                        speech_queue.add_message(respuesta_instalacion)
                        registrar_en_historial("assistant", respuesta_instalacion)
                        continue

                    session_skill_grants.revoke(
                        repair_context.skill_name,
                        repair_context.source_hash,
                    )
                    pending_dynamic_skill_repair_retry = PendingDynamicSkillRepairRetry(
                        skill_name=repair_context.skill_name,
                        failed_source_hash=repair_context.source_hash,
                        installed_source_hash=installation_result.source_hash,
                        original_command=repair_context.original_command,
                    )
                    retry_preparation = safe_skill_pipeline.prepare_execution(
                        repair_context.skill_name,
                        identity=identity_context,
                        parameters={"comando": repair_context.original_command},
                    )
                    if (
                        retry_preparation.confirmation_required
                        and retry_preparation.pending is not None
                    ):
                        pending_skill_execution = retry_preparation.pending
                        respuesta_reintento = (
                            "La reparacion esta instalada. Como el codigo de la skill ha cambiado, "
                            "necesito tu confirmacion para volver a intentar la peticion original."
                        )
                        print(f"[SKILL:{repair_context.skill_name}] {respuesta_reintento}")
                        speech_queue.add_message(respuesta_reintento)
                        registrar_en_historial("assistant", respuesta_reintento)
                    elif retry_preparation.execution_result.executed:
                        pending_dynamic_skill_repair_retry = None
                        responder_dynamic_skill(
                            repair_context.skill_name,
                            repair_context.original_command,
                            retry_preparation.execution_result,
                        )
                    else:
                        pending_dynamic_skill_repair_retry = None
                        reason = (
                            retry_preparation.execution_result.failure_reason
                            or "PolicyCore no autorizo el retry."
                        )
                        respuesta_reintento = (
                            f"La reparacion esta instalada, pero no pude reintentar "
                            f"la peticion original: {reason}"
                        )
                        print(f"[SKILL:{repair_context.skill_name}] {respuesta_reintento}")
                        speech_queue.add_message(respuesta_reintento)
                        registrar_en_historial("assistant", respuesta_reintento)
                    continue

                pending_dynamic_skill_repair = None
                print("[SKILL] Reparacion pendiente cancelada por una nueva directiva.")

            if pending_skill_installation is not None:
                confirmation_choice = clasificar_confirmacion_instalacion(usuario_limpio)
                if confirmation_choice is not None:
                    pending_to_confirm = pending_skill_installation
                    pending_skill_installation = None
                    if not confirmation_choice:
                        respuesta_cancelacion = "Instalacion de skill cancelada."
                        print(f"[SKILL] {respuesta_cancelacion}")
                        speech_queue.add_message(respuesta_cancelacion)
                        registrar_en_historial("assistant", respuesta_cancelacion)
                        continue

                    deployment_result = safe_skill_pipeline.confirm_installation(
                        pending_to_confirm,
                        identity=identity_context,
                    )
                    if deployment_result.installed:
                        respuesta_despliegue = (
                            f"Skill '{deployment_result.skill_name}' instalada. "
                            "No se ha ejecutado todavia."
                        )
                    else:
                        respuesta_despliegue = (
                            f"No pude instalar '{pending_to_confirm.skill_name}': "
                            f"{deployment_result.failure_reason or 'la politica no lo autorizo.'}"
                        )
                    print(f"[SKILL] {respuesta_despliegue}")
                    speech_queue.add_message(respuesta_despliegue)
                    registrar_en_historial("assistant", respuesta_despliegue)
                    continue

                pending_skill_installation = None
                print("[SKILL] Instalacion pendiente cancelada por una nueva directiva.")

            if pending_skill_execution is not None:
                confirmation_choice = clasificar_confirmacion_instalacion(usuario_limpio)
                if confirmation_choice is not None:
                    pending_to_execute = pending_skill_execution
                    pending_skill_execution = None
                    repair_retry = pending_dynamic_skill_repair_retry
                    if not confirmation_choice:
                        pending_dynamic_skill_repair_retry = None
                        dynamic_skill_input_session.cancel()
                        respuesta_cancelacion = "Ejecucion de skill cancelada."
                        print(f"[SKILL] {respuesta_cancelacion}")
                        speech_queue.add_message(respuesta_cancelacion)
                        registrar_en_historial("assistant", respuesta_cancelacion)
                        continue

                    execution_result = safe_skill_pipeline.confirm_execution(
                        pending_to_execute,
                        identity=identity_context,
                    )
                    session_skill_grants.grant_from_confirmed_execution(
                        execution_result,
                        identity_context.user_id,
                    )
                    if not execution_result.executed:
                        dynamic_skill_input_session.cancel()
                    if execution_result.executed:
                        pending_dynamic_skill_repair_retry = None
                        responder_dynamic_skill(
                            pending_to_execute.skill_name,
                            str(pending_to_execute.parameters.get("comando", "")),
                            execution_result,
                        )
                    elif repair_retry is not None:
                        pending_dynamic_skill_repair_retry = None
                        if (
                            execution_result.failure_kind is ExecutionFailureKind.SKILL_EXCEPTION
                            and execution_result.allowed
                            and execution_result.hash_verified
                        ):
                            respuesta_ejecucion = (
                                "La skill sigue fallando después de la reparación automática: "
                                f"{execution_result.failure_reason or 'error interno sin detalle'}."
                            )
                        else:
                            respuesta_ejecucion = (
                                "No pude reintentar la petición original: "
                                f"{execution_result.failure_reason or 'falló la autorización o el runtime'}."
                            )
                        print(f"[SKILL:{pending_to_execute.skill_name}] {respuesta_ejecucion}")
                        speech_queue.add_message(respuesta_ejecucion)
                        registrar_en_historial("assistant", respuesta_ejecucion)
                    elif intentar_autorreparacion_dynamic_skill(
                        pending_to_execute.skill_name,
                        str(pending_to_execute.parameters.get("comando", "")),
                        execution_result,
                        identity_context,
                    ):
                        continue
                    else:
                        respuesta_ejecucion = (
                            f"No pude ejecutar '{pending_to_execute.skill_name}': "
                            f"{execution_result.failure_reason or 'la politica no lo autorizo.'}"
                        )
                        print(f"[SKILL] {respuesta_ejecucion}")
                        speech_queue.add_message(respuesta_ejecucion)
                        registrar_en_historial("assistant", respuesta_ejecucion)
                    continue

                pending_skill_execution = None
                pending_dynamic_skill_repair_retry = None
                dynamic_skill_input_session.cancel()
                print("[SKILL] Ejecucion pendiente cancelada por una nueva directiva.")

            registrar_en_historial("user", usuario)

            recordatorio = analizar_recordatorio(usuario)
            if recordatorio:
                mensaje_recordatorio, timestamp_objetivo = recordatorio
                recordatorio_id = memory.add_reminder(
                    mensaje_recordatorio, timestamp_objetivo
                )
                respuesta_recordatorio = (
                    f"Recordatorio guardado para {timestamp_objetivo:%Y-%m-%d %H:%M} "
                    f"(id {recordatorio_id}): {mensaje_recordatorio}"
                )
                print(f"[RECORDATORIO] {respuesta_recordatorio}")
                speech_queue.add_message(respuesta_recordatorio)
                registrar_en_historial("assistant", respuesta_recordatorio)
                continue

            programacion = analizar_programacion_skill(usuario_limpio)
            if programacion:
                if not dynamic_skills_enabled():
                    print(f"[SCHEDULER] {DYNAMIC_SKILLS_DISABLED_MESSAGE}")
                    speech_queue.add_message(DYNAMIC_SKILLS_DISABLED_MESSAGE)
                    registrar_en_historial("assistant", DYNAMIC_SKILLS_DISABLED_MESSAGE)
                    continue

                skill_programada, hora, minuto = programacion
                if not skill_dispatcher.has_registered_action(skill_programada):
                    mensaje_bloqueo = "La skill programada no tiene una politica de seguridad registrada."
                    print(f"[SCHEDULER] {mensaje_bloqueo}")
                    speech_queue.add_message(mensaje_bloqueo)
                    registrar_en_historial("assistant", mensaje_bloqueo)
                    continue

                job_id = f"daily_{skill_programada}"
                scheduler.add_skill_job_daily(
                    job_id,
                    skill_programada,
                    skill_dispatcher,
                    hora,
                    minuto,
                )
                respuesta_programacion = (
                    f"He programado '{skill_programada}' para ejecutarse cada día a "
                    f"las {hora:02d}:{minuto:02d}."
                )
                print(f"[SCHEDULER] {respuesta_programacion}")
                speech_queue.add_message(respuesta_programacion)
                registrar_en_historial("assistant", respuesta_programacion)
                continue

            # PRIORIDAD CERO: resolver skills antes de memoria, visión, web o Arquitecto IA.
            print("[INTENT ROUTER] Evaluando intención de skill...")
            skill_a_ejecutar = resolver_skill_prioritaria(usuario_limpio)
            if skill_a_ejecutar:
                print(f"[INTENT ROUTER] Ejecutando skill dinamica detectada: {skill_a_ejecutar}")
                preparation = ejecutar_cancelable(
                    safe_skill_pipeline.prepare_execution,
                    skill_a_ejecutar,
                    identity=identity_context,
                    parameters={"comando": usuario_limpio},
                )
                if preparation is TASK_INTERRUPTED:
                    continue
                if preparation.confirmation_required and preparation.pending is not None:
                    pending_execution = preparation.pending
                    verified_hash = (
                        preparation.execution_result.action.metadata.get("source_hash")
                        if preparation.execution_result.hash_verified
                        and preparation.execution_result.action is not None
                        else None
                    )
                    session_authorization = (
                        session_skill_grants.authorization_for(
                            pending_execution.skill_name,
                            verified_hash,
                            identity_context.user_id,
                        )
                        if isinstance(verified_hash, str)
                        else None
                    )
                    if session_authorization is None:
                        pending_skill_execution = pending_execution
                        respuesta_skill = (
                            f"La skill '{skill_a_ejecutar}' requiere confirmacion fresca antes de ejecutarse."
                        )
                        print(f"[SKILL:{skill_a_ejecutar}] {respuesta_skill}")
                        speech_queue.add_message(respuesta_skill)
                        registrar_en_historial("assistant", respuesta_skill)
                        continue
                    resultado_skill = safe_skill_pipeline.execute_installed(
                        pending_execution.skill_name,
                        identity=identity_context,
                        parameters=pending_execution.parameters,
                        session_skill_authorization=session_authorization,
                    )
                else:
                    resultado_skill = preparation.execution_result
                if not resultado_skill.executed:
                    if intentar_autorreparacion_dynamic_skill(
                        skill_a_ejecutar,
                        usuario_limpio,
                        resultado_skill,
                        identity_context,
                    ):
                        continue
                    from jarvis.core.skill_error_handler import clean_executive_summary
                    mensaje_error_skill = clean_executive_summary(
                        resultado_skill.failure_reason
                        or "La política no autorizó la ejecución de la skill dinámica."
                    )
                    respuesta_skill = f"No pude ejecutar '{skill_a_ejecutar}': {mensaje_error_skill}"
                    print(f"[SKILL:{skill_a_ejecutar}] {respuesta_skill}")
                    speech_queue.add_message(respuesta_skill)
                    registrar_en_historial("assistant", respuesta_skill)
                    continue

                responder_dynamic_skill(
                    skill_a_ejecutar,
                    usuario_limpio,
                    resultado_skill,
                )
                continue
            solicitud_skill = None
            if usuario_limpio.lower().startswith("/skill "):
                objetivo_skill = usuario_limpio[len("/skill "):].strip()
                if not objetivo_skill:
                    respuesta_skill = "Debes indicar el objetivo despues de '/skill '."
                    print(f"[SKILL] {respuesta_skill}")
                    speech_queue.add_message(respuesta_skill)
                    continue
                solicitud_skill = usuario
            elif es_peticion_de_skill(usuario_limpio):
                solicitud_skill = usuario

            if solicitud_skill is not None:
                respuesta_skill, pending_installation = autorizar_skill_solicitada(
                    solicitud_skill,
                    identity_context,
                )
                if respuesta_skill is TASK_INTERRUPTED:
                    continue
                pending_skill_installation = pending_installation
                print(f"[SKILL] {respuesta_skill}")
                speech_queue.add_message(respuesta_skill)
                registrar_en_historial("assistant", respuesta_skill)
                continue
            if es_correccion_explicita(usuario_limpio):
                contexto_correccion = "\n".join(
                    f"{item['role']}: {item['content']}" for item in chat_history[-6:]
                )
                try:
                    aprender_skill_de_caso(
                        f"Crear una skill que resuelva correctamente esta corrección del usuario:\n"
                        f"{usuario_limpio}\n\nContexto reciente:\n{contexto_correccion}"
                    )
                except Exception as aprendizaje_error:
                    print(f"[APRENDIZAJE] Error al generar skill desde corrección: {aprendizaje_error}")
                continue

            capability_route = None
            native_tool_name = None
            direct_conversation = False
            if input_source is not InputSource.RECOVERY:
                capability_route = ejecutar_cancelable(
                    lambda: capability_router.decide(
                        usuario,
                        installed_skills=indexar_skills_dinamicas(),
                        external_user_request=True,
                    )
                )
                if capability_route is TASK_INTERRUPTED:
                    continue

                safe_reason = capability_route.reason
                if safe_reason not in {
                    "installed_skill_match",
                    "native_tool_match",
                    "ordinary_question",
                    "unavailable_requirement",
                    "no_reusable_capability",
                    "invalid_model_output",
                    "low_create_confidence",
                    "not_reusable",
                    "unsupported_by_classifier",
                    "reusable_external_tracking",
                    "internal_input",
                    "empty_request",
                }:
                    safe_reason = capability_route.decision.value.lower()
                print(
                    "[CAPABILITY ROUTER] "
                    f"decision={capability_route.decision.value} "
                    f"reason={safe_reason} source={capability_route.source}"
                )

                if capability_route.decision is CapabilityDecision.CREATE_SKILL:
                    respuesta_skill, pending_installation = autorizar_skill_solicitada(
                        usuario,
                        identity_context,
                        mensaje_inicio=(
                            "Necesito añadir una capacidad reutilizable. Voy a prepararla."
                        ),
                    )
                    if respuesta_skill is TASK_INTERRUPTED:
                        continue
                    pending_skill_installation = pending_installation
                    print(f"[SKILL] {respuesta_skill}")
                    speech_queue.add_message(respuesta_skill)
                    registrar_en_historial("assistant", respuesta_skill)
                    continue
                if (
                    capability_route.decision is CapabilityDecision.USE_EXISTING_SKILL
                    and capability_route.skill_name == TRACKING_SKILL_NAME
                ):
                    print(" > [SISTEMA] Consultando seguimiento del paquete...")
                    codigo_paquete = extract_tracking_code(usuario_limpio)
                    tracking_result = ejecutar_cancelable(
                        skill_dispatcher.dispatch,
                        TRACKING_SKILL_NAME,
                        {"codigo": codigo_paquete} if codigo_paquete else {},
                        identity=identity_context,
                    )
                    if tracking_result is TASK_INTERRUPTED:
                        continue
                    if tracking_result.executed:
                        respuesta_tracking = str(tracking_result.result)
                    else:
                        respuesta_tracking = str(tracking_result.message)
                    speech_queue.add_message(respuesta_tracking)
                    registrar_en_historial("assistant", respuesta_tracking)
                    memory.add_interaction("jarvis", respuesta_tracking)
                    continue
                if capability_route.decision is CapabilityDecision.UNSUPPORTED:
                    respuesta_no_soportada = (
                        "No puedo preparar esa capacidad porque requiere recursos o accesos "
                        "que no están disponibles."
                    )
                    speech_queue.add_message(respuesta_no_soportada)
                    registrar_en_historial("assistant", respuesta_no_soportada)
                    continue
                if capability_route.decision is CapabilityDecision.DIRECT_RESPONSE:
                    identifier_response = unbound_identifier_response(usuario_limpio)
                    if identifier_response is not None:
                        speech_queue.add_message(identifier_response)
                        registrar_en_historial("assistant", identifier_response)
                        continue
                    direct_conversation = True
                elif capability_route.decision is CapabilityDecision.USE_EXISTING_TOOL:
                    native_tool_name = capability_route.native_tool_name
            
            memory.add_interaction("usuario", usuario)
            hecho_personal = extraer_dato_personal(usuario)
            if hecho_personal:
                resultado_hecho = skill_dispatcher.dispatch(
                    "guardar_hecho",
                    {"hecho": hecho_personal},
                    identity=identity_context,
                )
                if resultado_hecho.executed:
                    print(f"[MEMORIA] {resultado_hecho.result}")
                else:
                    print(f"[SECURITY] {resultado_hecho.message}")
            texto_lower = usuario.lower()
            texto_para_ia = texto_lower

            # 1. FILTRO DETERMINISTA DE SIMULACIÓN
            if "simulacion" in texto_lower or "simulación" in texto_lower:
                if any(w in texto_lower for w in ["desactiva", "quita", "apaga"]):
                    estado.simulacion = False
                    speech_queue.add_message("Modo simulación desactivado. Sistema armado.")
                else:
                    estado.simulacion = True
                    speech_queue.add_message("Modo simulación activado. Acciones físicas bloqueadas.")
                continue

            # 2. ATAJO DETERMINISTA PARA MEMORIA
            if any(kw in texto_lower for kw in ["guarda", "recuerda", "apunta"]):
                match = re.search(r"(?:guarda|recuerda|apunta)(?:\s+en\s+tu\s+memoria)?(?:\s+esto)?[:,\s]*(.*)", usuario, re.IGNORECASE)
                hecho_a_guardar = match.group(1).strip(" ,:.-") if match else ""
                if hecho_a_guardar.lower().startswith("esto "):
                    hecho_a_guardar = hecho_a_guardar[5:].strip(" ,:.-")
                
                if hecho_a_guardar:
                    resultado_memoria = skill_dispatcher.dispatch(
                        "guardar_hecho",
                        {"hecho": hecho_a_guardar},
                        identity=identity_context,
                    )
                    respuesta_memoria = (
                        str(resultado_memoria.result)
                        if resultado_memoria.executed
                        else resultado_memoria.message
                    )
                    speech_queue.add_message(respuesta_memoria)
                    registrar_en_historial("assistant", respuesta_memoria)
                    memory.add_interaction("jarvis", respuesta_memoria)
                    continue

            if not texto_para_ia:
                continue

            # 3. PROCESAMIENTO PRINCIPAL CONTEXTUAL (ORQUESTADOR O ACCIONES DIRECTAS)
            if es_peticion_compuesta(usuario_limpio):
                print(f"\n > [ORQUESTADOR] Petición multi-paso detectada: '{usuario_limpio}'")
                mostrar_notificacion("JARVIS - Orquestador", f"Planificando: {usuario_limpio[:80]}...", duracion_ms=4000)
                # Un único aviso breve y natural al inicio de planes complejos
                speech_queue.add_message("Entendido, preparo el plan.")

                plan = generar_plan_dinamico(usuario_limpio, available_tools=list(skills._skills.keys()))
                print(f" > [ORQUESTADOR] Plan generado ({plan.plan_id}) con {len(plan.steps)} pasos:")
                for paso in plan.steps:
                    print(f"    - [{paso.step_id}] ({paso.required_role.value}): {paso.description}")

                from jarvis.core.skill_error_handler import SkillErrorHandler
                cancel_token = threading.Event()
                executor = PlanExecutor(
                    plan=plan,
                    router=router,
                    error_handler=SkillErrorHandler(model_router=router),
                    tool_registry=skills,
                    prefer_groq_on_vram_limit=router.gaming_mode,
                    cancel_token=cancel_token,
                )
                resultado_plan = ejecutar_cancelable(executor.execute_plan)
                if resultado_plan is TASK_INTERRUPTED or plan.status == PlanStatus.ABORTED:
                    speech_queue.clear()
                    tts.stop()
                    completed = plan.completed_steps()
                    if completed:
                        msg_cancel = f"Plan cancelado. Se detuvieron los pasos pendientes ({len(completed)} paso(s) ya finalizado(s))."
                    else:
                        msg_cancel = "Plan cancelado. Se han detenido los pasos pendientes."
                    print(f"\n[ORQUESTADOR CANCELADO]: {msg_cancel}")
                    speech_queue.add_message(msg_cancel)
                    mostrar_notificacion("JARVIS - Orquestador", msg_cancel, duracion_ms=4000)
                    registrar_en_historial("assistant", msg_cancel)
                    memory.add_interaction("jarvis", msg_cancel)
                    continue

                if plan.has_failed() or not plan.is_completed():
                    speech_queue.clear()
                    msg_fail = "No se pudo completar la tarea debido a un error durante la ejecución."
                    print(f"\n[ORQUESTADOR ERROR]: {msg_fail}")
                    speech_queue.add_message(msg_fail)
                    mostrar_notificacion("JARVIS - Orquestador", msg_fail, duracion_ms=4000)
                    registrar_en_historial("assistant", msg_fail)
                    memory.add_interaction("jarvis", msg_fail)
                    continue

                completed = plan.completed_steps()
                if completed:
                    salida_final = str(completed[-1].result)
                else:
                    salida_final = resultado_plan.summary or "Plan completado."

                print(f"\n[ORQUESTADOR RESULTADO FINAL]:\n{salida_final}")
                speech_queue.add_message(salida_final)
                registrar_en_historial("assistant", salida_final)
                memory.add_interaction("jarvis", salida_final)
                mostrar_notificacion("JARVIS - Orquestador", salida_final[:160], duracion_ms=7000)
                continue

            if direct_conversation:
                decision = {"accion": "hablar"}
            elif native_tool_name and native_tool_name != "leer_archivo_workspace":
                native_parameters: dict[str, object] = {}
                if native_tool_name == "buscar_en_internet":
                    native_parameters["query"] = usuario
                decision = {
                    "accion": "ejecutar",
                    "skill": native_tool_name,
                    "params": native_parameters,
                    "peticion_original": usuario,
                }
            elif router._es_consulta_de_codigo(usuario):
                decision = {
                    "accion": "ejecutar",
                    "skill": "analizar_codigo_activo",
                    "params": {"prompt_usuario": usuario},
                }
            elif any(kw in texto_lower for kw in ["captura", "pantalla", "monitor"]):
                decision = {"accion": "ejecutar", "skill": "tomar_captura_pantalla", "params": {}}
            elif any(kw in texto_lower for kw in ["busca", "internet", "busquen", "buscan", "partido", "resultado", "cuándo es", "quién es", "qué es", "horario", "mira si", "cuál es"]):
                resolver_elipsis = getattr(router, "resolver_elipsis_consulta", None)
                query_final = (
                    resolver_elipsis(usuario, memory.get_session_context())
                    if callable(resolver_elipsis)
                    else usuario
                )
                decision = {"accion": "ejecutar", "skill": "buscar_en_internet", "params": {"query": query_final}}
            else:
                # Delegamos la decisión inteligente al orquestador del router
                decision_orquestador = ejecutar_cancelable(
                    router.route_inteligente, texto_para_ia
                )
                if decision_orquestador is TASK_INTERRUPTED:
                    continue
                if not isinstance(decision_orquestador, dict):
                    print("[ROUTER] La decisión del Arquitecto no tiene formato válido.")
                    continue
                
                # Comprobamos si el orquestador detectó que queremos leer un archivo del workspace
                archivo_detectado = decision_orquestador.get("archivo_a_leer")
                if archivo_detectado and archivo_detectado != "null":
                    # Si menciona un archivo, forzamos la ejecución de la skill de workspace primero
                    decision = {
                        "accion": "ejecutar", 
                        "skill": "leer_archivo_workspace", 
                        "params": {"ruta_relativa": archivo_detectado},
                        "peticion_original": usuario,
                        "rol_destino": decision_orquestador.get("rol_principal", "coding")
                    }
                else:
                    decision = {"accion": "hablar"}
            
            # --- AUTOCORRECCIÓN DEL LLM ---
            accion = decision.get("accion")
            catalogo_habilidades = skills.get_catalog()

            palabras_factuales = ["cuándo", "partido", "resultado", "quién", "dónde", "precio", "último", "noticia", "horario"]
            if accion == "hablar" and any(p in texto_lower for p in palabras_factuales):
                decision = {"accion": "ejecutar", "skill": "buscar_en_internet", "params": {"query": usuario}}
                accion = "ejecutar"

            if isinstance(accion, str) and accion in catalogo_habilidades:
                decision["skill"] = accion
                accion = "ejecutar"
            
            # --- EJECUCIÓN ---
            if accion == "hablar":
                facts_list = memory.data.get("facts", []) if isinstance(memory.data, dict) else []
                hechos = "\n".join([f"- {f}" for f in facts_list]) if facts_list else "Ninguno aún."
                prompt_base = f"{CONTEXTO_USUARIO}\n{DIRECT_RESPONSE_EVIDENCE_CONTRACT}\n[MEMORIA]:\n{hechos}"
                
                respuesta = ejecutar_cancelable(
                    router.route_with_memory,
                    ModelRole.SPEECH,
                    prompt_base,
                    chat_history[:-1],
                    texto_para_ia,
                )
                if respuesta is TASK_INTERRUPTED:
                    continue
                respuesta = str(respuesta)
                speech_queue.add_message(respuesta)
                registrar_en_historial("assistant", respuesta)
                memory.add_interaction("jarvis", respuesta)
                
            elif accion == "ejecutar":
                skill_name = decision.get("skill")
                if not isinstance(skill_name, str):
                    continue
                
                if estado.simulacion:
                    print(f" > [SIMULACIÓN] Interceptada ejecución de '{skill_name}'.")
                    continue
                
                print(f" > [SISTEMA] Ejecutando {skill_name}...")
                
                raw_params = decision.get("params", {})
                params: dict[str, object] = {}
                if isinstance(raw_params, dict):
                    params = {key: value for key, value in raw_params.items() if isinstance(key, str)}
                if not params and "query" in decision:
                    params = {"query": decision["query"]}
                
                try:
                    dispatch_result = skill_dispatcher.dispatch(
                        skill_name,
                        params,
                        identity=identity_context,
                    )
                    if not dispatch_result.executed:
                        mensaje_seguridad = dispatch_result.message
                        print(f" > [SECURITY] {mensaje_seguridad}")
                        speech_queue.add_message(mensaje_seguridad)
                        registrar_en_historial("assistant", mensaje_seguridad)
                        continue

                    resultado = dispatch_result.result
                    
                    if skill_name == "buscar_en_internet":
                        print(" > [SISTEMA] Sintetizando respuesta de la red...")
                        respuesta = ejecutar_cancelable(
                            router.sintetizar_respuesta_web,
                            usuario,
                            str(resultado),
                            memory.get_session_context(),
                        )
                        if respuesta is TASK_INTERRUPTED:
                            continue
                        respuesta = str(respuesta)
                        speech_queue.add_message(respuesta)
                        registrar_en_historial("assistant", respuesta)
                        memory.add_interaction("jarvis", respuesta)
                        if es_problema_tecnico(usuario):
                            try:
                                aprender_skill_de_caso(
                                    f"Crear una skill para resolver de forma reproducible esta consulta técnica: "
                                    f"{usuario}\n\nInformación obtenida en la búsqueda:\n{resultado}"
                                )
                            except Exception as aprendizaje_error:
                                print(f"[APRENDIZAJE] No se pudo registrar el caso técnico: {aprendizaje_error}")

                    elif skill_name == "estado_impresora" and isinstance(resultado, dict) and not resultado.get("online", True):
                        msg = "La impresora 3D está apagada o sin conexión."
                        speech_queue.add_message(msg)
                        memory.add_interaction("jarvis", msg)
                        
                    elif skill_name == "tomar_captura_pantalla" and os.path.exists(str(resultado)):
                        print(" > [SISTEMA] Iniciando Pipeline Multimodal en cadena con captura...")
                        analisis = ejecutar_cancelable(
                            router.ejecutar_pipeline_cognitivo,
                            usuario,
                            image_path=str(resultado),
                        )
                        if analisis is TASK_INTERRUPTED:
                            continue
                        analisis = str(analisis)
                        speech_queue.add_message(analisis)
                        registrar_en_historial("assistant", analisis)
                        memory.add_interaction("jarvis", analisis)

                    # --- NUEVO MANEJADOR PARA EL WORKSPACE ---
                    elif skill_name == "leer_archivo_workspace":
                        print(f" > [SISTEMA] Leyendo archivo del workspace para análisis...")
                        contenido_archivo = str(resultado)
                        
                        if "Error:" in contenido_archivo:
                            speech_queue.add_message(contenido_archivo)
                        else:
                            rol_str = decision.get("rol_destino", "coding")
                            rol_enum = ModelRole.CODING if rol_str == "coding" else ModelRole.DEEP_REASONING
                            
                            prompt_analisis = f"""El usuario ha solicitado lo siguiente sobre este archivo: "{decision.get('peticion_original')}"

--- CONTENIDO DEL ARCHIVO ({params.get('ruta_relativa')}) ---
{contenido_archivo}
-------------------------------------------------------------
Por favor, analiza el código anterior y responde de forma profesional y técnica."""

                            print(f" > [SISTEMA] Enviando código al modelo [{rol_str}]...")
                            respuesta_analisis = router.route(rol_enum, prompt_analisis)
                            speech_queue.add_message(respuesta_analisis)
                            registrar_en_historial("assistant", respuesta_analisis)
                            memory.add_interaction("jarvis", respuesta_analisis)
                    # ----------------------------------------
                        
                    else:
                        mensaje_final = str(resultado)
                        speech_queue.add_message(mensaje_final)
                        registrar_en_historial("assistant", mensaje_final)
                        memory.add_interaction("jarvis", mensaje_final)
                        
                except Exception as e_inner:
                    print(f" > [ERROR] Falló la herramienta {skill_name}: {e_inner}")
                    speech_queue.add_message(f"Hubo un fallo en los sistemas al ejecutar la tarea.")
        except (KeyboardInterrupt, SystemExit):
            print("\n[APAGADO] Interrupción detectada...")
            break
        except Exception as e_outer:
            print(f" > [ERROR] Error en el ciclo principal: {e_outer}")

    speech_queue.stop()
    scheduler.stop()
    game_detector.stop()
    print("[OK] Apagado limpio: GameDetector, Planificador y cola de audio detenidos.")


