from __future__ import annotations

import base64
import ast
import random
import requests
import io
import importlib
import os
import logging
import json
import re
import unicodedata
from builtins import ImportError
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Generator, Mapping, Optional, TypedDict, Union
import pytesseract
from PIL import Image
from jarvis.core.validator import TechnicalValidator
from jarvis.core.vram_manager import KNOWN_LOCAL_HEAVY_MODELS, VramManager
from jarvis.core.formula_memory import FormulaMemory
from jarvis.skills.workspace_skill import obtener_archivo_activo_vscode

# =========================================================
# CONFIGURACIÓN Y MODELOS LOCALES RECOMENDADOS
# =========================================================
# LOCAL: trabajadores independientes
MODEL_ORCHESTRATOR_LOCAL = "qwen3.5:4b"
MODEL_CODING_LOCAL = "qwen2.5-coder:7b-instruct-q4_K_M"
MODEL_VISION_LOCAL = "qwen3-vl:4b"
MODEL_REASONING_LOCAL = "qwen3.5:9b"

# CLOUD: trabajadores adicionales simultáneos
MODEL_GROQ_CLOUD = "qwen/qwen3.6-27b"
MODEL_GEMINI_CLOUD = "gemini-3.8-flash"
# This intentionally has its own setting: code review workload and general
# reasoning may evolve independently without changing the public route policy.
MODEL_GROQ_CODE_REVIEW = os.getenv(
    "JARVIS_GROQ_CODE_REVIEW_MODEL", MODEL_GROQ_CLOUD
)

DEFAULT_NUM_CTX = 4096
DEFAULT_GROQ_CODE_REVIEW_MAX_TOKENS = 1024
DEFAULT_LOCAL_CODE_REVIEW_NUM_PREDICT = 1536


def get_local_code_review_num_predict(environ: Mapping[str, str] | None = None) -> int:
    """Bound only the local code-review output; general reasoning is unchanged."""

    environment = os.environ if environ is None else environ
    raw_value = environment.get("JARVIS_LOCAL_CODE_REVIEW_NUM_PREDICT", "").strip()
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_LOCAL_CODE_REVIEW_NUM_PREDICT
    return value if 256 <= value <= 4096 else DEFAULT_LOCAL_CODE_REVIEW_NUM_PREDICT


def get_groq_code_review_max_tokens(
    environ: Mapping[str, str] | None = None,
) -> int:
    """Return the bounded, review-only Groq output budget.

    Invalid values use the compact default and never affect other Groq routes.
    """

    environment = os.environ if environ is None else environ
    raw_value = environment.get("JARVIS_GROQ_CODE_REVIEW_MAX_TOKENS", "").strip()
    if not raw_value:
        return DEFAULT_GROQ_CODE_REVIEW_MAX_TOKENS
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_GROQ_CODE_REVIEW_MAX_TOKENS
    return value if 64 <= value <= 4096 else DEFAULT_GROQ_CODE_REVIEW_MAX_TOKENS


class OllamaInferenceKwargs(TypedDict):
    think: bool
    temperature: float
    num_predict: int
    num_ctx: int
    keep_alive: int
    unload_after: bool


@dataclass(frozen=True)
class InferenceProfile:
    think: bool
    temperature: float
    num_predict: int
    num_ctx: int = DEFAULT_NUM_CTX
    keep_alive: int = 10
    unload_after: bool = False

    def as_ollama_kwargs(self) -> OllamaInferenceKwargs:
        return {
            "think": self.think,
            "temperature": self.temperature,
            "num_predict": self.num_predict,
            "num_ctx": self.num_ctx,
            "keep_alive": self.keep_alive,
            "unload_after": self.unload_after,
        }


ARCHITECT_INFERENCE_PROFILE = InferenceProfile(
    think=False,
    temperature=0.1,
    num_predict=128,
)
SPEECH_INFERENCE_PROFILE = InferenceProfile(
    think=False,
    temperature=0.5,
    num_predict=512,
)
CODING_INFERENCE_PROFILE = InferenceProfile(
    think=False,
    temperature=0.2,
    num_predict=1024,
    unload_after=True,
)
DEEP_REASONING_INFERENCE_PROFILE = InferenceProfile(
    think=False,
    temperature=0.2,
    num_predict=768,
    keep_alive=15,
    unload_after=True,
)
VISION_INFERENCE_PROFILE = InferenceProfile(
    think=False,
    temperature=0.0,
    num_predict=400,
    unload_after=True,
)


DEFAULT_VRAM_MANAGER = VramManager()


def ocr_pantalla(ruta_img: str) -> str:
    """Extrae el texto visible de una imagen mediante Tesseract OCR."""
    try:
        pytesseract = importlib.import_module("pytesseract")
        Image = importlib.import_module("PIL.Image")
    except ImportError as exc:
        raise RuntimeError(
            "El OCR requiere las dependencias 'pytesseract' y 'Pillow'."
        ) from exc

    return pytesseract.image_to_string(Image.open(ruta_img), lang="spa+eng")


class ModelRole(Enum):
    SPEECH = "speech"
    CODING = "coding"
    VISION = "vision"
    DEEP_REASONING = "deep_reasoning"


@dataclass
class RouterResponse:
    success: bool
    role: ModelRole
    content: str
    execution_time: float


class ModelRouter:
    """
    Router principal de JARVIS.
    Orquesta qué cerebro responde con gestión optimizada de VRAM para GPUs de 8 GB,
    fallback transparente nube/local, y ejecución directa en VRAM.
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        vram_manager: VramManager | None = None,
    ):
        self.groq_api_key = groq_api_key
        self.gemini_api_key = gemini_api_key
        self.vram_manager = (
            DEFAULT_VRAM_MANAGER if vram_manager is None else vram_manager
        )
        self.ollama_url = "http://127.0.0.1:11434"
        self._airllm_model: Any = None 
        self.formula_memory = FormulaMemory()
        self.gaming_mode: bool = False

    def set_gaming_mode(self, enabled: bool) -> str:
        """Activa o desactiva el Modo Gaming (VRAM 0% para videojuegos).

        Al activarse, descarga inmediatamente cualquier modelo local cargado en Ollama
        y enruta el 100% de las consultas a la API de Groq, asegurando que la VRAM de la GPU
        quede totalmente libre.
        """
        self.gaming_mode = bool(enabled)
        if self.gaming_mode:
            modelos_a_descargar = set(KNOWN_LOCAL_HEAVY_MODELS.keys())
            modelos_a_descargar.update([
                MODEL_ORCHESTRATOR_LOCAL,
                MODEL_CODING_LOCAL,
                MODEL_VISION_LOCAL,
                MODEL_REASONING_LOCAL,
            ])
            for model_id in modelos_a_descargar:
                try:
                    self._unload_ollama_model(model_id)
                except Exception:
                    pass
            try:
                self.vram_manager.clear_resident_model()
            except Exception:
                pass
            return (
                "Modo juego activado. Modelos locales descargados de la GPU. "
                "VRAM liberada al 0% para tus juegos. Consultas enrutadas a Groq Cloud."
            )
        else:
            return "Modo juego desactivado. Los modelos locales vuelven a estar disponibles."

    def route(
        self, role: ModelRole, prompt: str, image_bytes: Optional[bytes] = None
    ) -> str:
        # Si el modo Gaming está activo, derivar todo a la nube (Groq) para mantener VRAM al 0%
        if self.gaming_mode:
            if role == ModelRole.VISION and self.gemini_api_key and image_bytes:
                try:
                    return self._call_gemini_vision(prompt, image_bytes)
                except Exception:
                    pass
            if self.groq_api_key:
                try:
                    return self.run_groq_reasoning(prompt)
                except Exception:
                    return self._call_groq_fallback(prompt)
            return self._call_groq_fallback(prompt)

        # 1. ROL: HABLA / CONVERSACIÓN
        if role == ModelRole.SPEECH:
            return self._call_ollama(
                MODEL_ORCHESTRATOR_LOCAL,
                prompt,
                **SPEECH_INFERENCE_PROFILE.as_ollama_kwargs(),
            )

        # 2. ROL: CÓDIGO
        elif role == ModelRole.CODING:
            try:
                analysis = self._call_ollama(
                    MODEL_CODING_LOCAL,
                    prompt,
                    **CODING_INFERENCE_PROFILE.as_ollama_kwargs(),
                )
                return analysis
            except Exception as e:
                print(f"[ROUTER WARNING] Fallo en modelo de código local: {e}")
                return self._fallback_with_notice(
                    prompt, reason="el modelo de código no estaba disponible"
                )

        # 3. ROL: VISIÓN
        elif role == ModelRole.VISION:
            if not image_bytes:
                raise ValueError("El rol VISION requiere los bytes de la imagen.")
            
            if self.gemini_api_key:
                try:
                    return self._call_gemini_vision(prompt, image_bytes)
                except Exception as e_gemini:
                    print(f"[ROUTER] Gemini Vision no disponible ({e_gemini}). Cambiando a VLM local...")

            print(f" > [DEBUG] Sistema de visión en modo local ({MODEL_VISION_LOCAL})...")
            return self._call_vision_ollama_bytes(MODEL_VISION_LOCAL, prompt, image_bytes)

        # 4. ROL: RAZONAMIENTO PROFUNDO
        elif role == ModelRole.DEEP_REASONING:
            try:
                return self._call_ollama(
                    MODEL_REASONING_LOCAL,
                    prompt,
                    **DEEP_REASONING_INFERENCE_PROFILE.as_ollama_kwargs(),
                )
            except Exception as e_local:
                print(f"[ROUTER] Razonamiento local Qwen3.5 9B no disponible ({e_local}). Probando Groq Cloud...")

            if self.groq_api_key:
                try:
                    return self._call_groq_fallback(prompt)
                except Exception as e_groq:
                    print(f"[ROUTER] Groq Cloud no disponible ({e_groq}).")

            return self._fallback_with_notice(
                prompt, reason="el modelo de razonamiento profundo no ha podido cargarse"
            )

        return self._call_ollama(
            MODEL_ORCHESTRATOR_LOCAL,
            prompt,
            **SPEECH_INFERENCE_PROFILE.as_ollama_kwargs(),
        )

    def run_local_coding(self, prompt: str) -> str:
        """Run only the local coding specialist; this method never reroutes."""

        return self._call_ollama(
            MODEL_CODING_LOCAL,
            prompt,
            **CODING_INFERENCE_PROFILE.as_ollama_kwargs(),
        )

    def run_local_vision(self, prompt: str, image_bytes: bytes) -> str:
        """Run only the local vision specialist; this method never reroutes."""

        if not image_bytes:
            raise ValueError("run_local_vision requires non-empty image_bytes.")
        return self._call_vision_ollama_bytes(
            MODEL_VISION_LOCAL,
            prompt,
            image_bytes,
        )

    def run_local_reasoning(self, prompt: str) -> str:
        """Run only the local reasoning specialist; this method never reroutes."""

        return self._call_ollama(
            MODEL_REASONING_LOCAL,
            prompt,
            **DEEP_REASONING_INFERENCE_PROFILE.as_ollama_kwargs(),
        )

    @property
    def local_code_review_num_predict(self) -> int:
        return get_local_code_review_num_predict()

    def run_local_code_review(self, prompt: str) -> str:
        """Run the same local reasoning model with a review-only output budget."""

        profile = replace(
            DEEP_REASONING_INFERENCE_PROFILE,
            num_predict=self.local_code_review_num_predict,
        )
        return self._call_ollama(
            MODEL_REASONING_LOCAL,
            prompt,
            **profile.as_ollama_kwargs(),
        )

    def run_groq_reasoning(self, prompt: str) -> str:
        """Run Groq reasoning directly, leaving any fallback to the caller."""

        if not self.groq_api_key:
            raise RuntimeError("Groq is not configured for explicit reasoning.")
        return self._call_groq(prompt)

    def run_groq_code_review(self, prompt: str) -> str:
        """Run the configured Groq code reviewer directly, without fallback."""

        if not self.groq_api_key:
            raise RuntimeError("Groq is not configured for explicit code review.")
        return self._call_groq(
            prompt,
            model=MODEL_GROQ_CODE_REVIEW,
            temperature=0.0,
            max_tokens=get_groq_code_review_max_tokens(),
        )

    def run_gemini_vision(self, prompt: str, image_bytes: bytes) -> str:
        """Run Gemini vision directly, leaving any fallback to the caller."""

        if not image_bytes:
            raise ValueError("run_gemini_vision requires non-empty image_bytes.")
        if not self.gemini_api_key:
            raise RuntimeError("Gemini is not configured for explicit vision.")
        return self._call_gemini_vision(prompt, image_bytes)
    # =========================================================
    # MOTORES DE INFERENCIA Y GESTIÓN DE MEMORIA
    # =========================================================

    def _call_gemini_vision(self, prompt: str, image_bytes: bytes) -> str:
        if not self.gemini_api_key:
            raise RuntimeError("No se ha configurado la API key de Gemini.")

        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_GEMINI_CLOUD}:generateContent",
            params={"key": self.gemini_api_key},
            json={
                "contents": [{
                    "parts": [
                        {"text": prompt},
                        {
                            "inline_data": {
                                "mime_type": "image/png",
                                "data": base64.b64encode(image_bytes).decode("ascii"),
                            }
                        },
                    ]
                }]
            },
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("Gemini devolvió una respuesta sin texto.") from exc

    def _call_vision_ollama_bytes(self, model_name: str, prompt: str, image_bytes: bytes) -> str:
        url = f"{self.ollama_url}/api/generate"
        encoded_image = base64.b64encode(image_bytes).decode("utf-8")
        
        # INSTRUCCIÓN ANTI-ALUCINACIÓN VISUAL:
        # Forzamos al modelo a ser honesto si la captura no es legible.
        prompt_estricto = (
            "INSTRUCCIÓN OBLIGATORIA DE VISIÓN:\n"
            "Analiza la imagen adjunta. Si el texto del código fuente o la función que se pide "
            "está borroso, cortado, ilegible o no puedes leerlo al 100% con total certeza, "
            "ESTÁ PROHIBIDO INVENTAR CÓDIGO. En su lugar, responde exactamente con esta frase:\n"
            "'[ERROR VISUAL]: No puedo leer con suficiente claridad el código en la captura de pantalla. "
            "Por favor, pásame el fragmento de código directamente por texto para que pueda ayudarte con precisión.'\n\n"
            f"Petición original: {prompt}"
        )
        
        payload = {
            "model": model_name,
            "prompt": prompt_estricto,
            "images": [encoded_image],
            "stream": False,
            "keep_alive": f"{VISION_INFERENCE_PROFILE.keep_alive}m",
            "think": VISION_INFERENCE_PROFILE.think,
            "options": {
                "temperature": VISION_INFERENCE_PROFILE.temperature,
                "num_predict": VISION_INFERENCE_PROFILE.num_predict,
                "num_ctx": VISION_INFERENCE_PROFILE.num_ctx,
                "repeat_penalty": 1.2,
            },
        }

        def request() -> str:
            try:
                response = requests.post(url, json=payload, timeout=60)
                response.raise_for_status()
                data = response.json()
                respuesta_texto = data.get("response", "").strip()

                if not respuesta_texto:
                    return (
                        f"[Error LOCAL]: El modelo '{model_name}' devolvió una "
                        "cadena vacía."
                    )

                return respuesta_texto
            except Exception as exc:
                return f"Error en motor local de visión ({model_name}): {exc}"

        return self._execute_local_heavy_request(
            model_name,
            request,
            unload_after=VISION_INFERENCE_PROFILE.unload_after,
        )

    def _execute_local_heavy_request(
        self,
        model_name: str,
        request: Callable[[], str],
        *,
        unload_after: bool = False,
    ) -> str:
        """Run a known heavy local model under the shared VRAM slot."""

        if model_name not in KNOWN_LOCAL_HEAVY_MODELS:
            return request()

        with self.vram_manager.reserve(model_name):
            resident_model = self.vram_manager.resident_model_id
            if resident_model and resident_model != model_name:
                if not self._unload_ollama_model(resident_model):
                    raise RuntimeError(
                        "No se pudo descargar el modelo local residente "
                        f"'{resident_model}' antes de cargar '{model_name}'."
                    )
                self.vram_manager.clear_resident_model(resident_model)

            response = request()
            self.vram_manager.mark_model_resident(model_name)

            if unload_after and self._unload_ollama_model(model_name):
                self.vram_manager.clear_resident_model(model_name)

            return response

    def _call_ollama(
        self,
        model: str,
        prompt: str,
        *,
        think: bool = False,
        temperature: float = 0.5,
        num_predict: int = 512,
        num_ctx: int = DEFAULT_NUM_CTX,
        keep_alive: int = 10,
        unload_after: bool = False,
    ) -> str:
        """Call Ollama with an explicit profile under the shared VRAM slot."""
        if self.gaming_mode:
            logger.info("Modo Gaming activo (VRAM 0%%): omitiendo llamada local a '%s', usando Groq.", model)
            if self.groq_api_key:
                try:
                    return self.run_groq_reasoning(prompt)
                except Exception:
                    return self._call_groq_fallback(prompt)
            return self._call_groq_fallback(prompt)

        url = f"{self.ollama_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": f"{keep_alive}m",
            "think": think,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
                "num_ctx": num_ctx,
            },
        }

        def request() -> str:
            response = None
            try:
                response = requests.post(url, json=payload, timeout=(5, 120))
                response.raise_for_status()
                return response.json().get("response", "")
            except requests.exceptions.ConnectionError:
                return (
                    f"[ERROR OLLAMA] No se pudo conectar a {self.ollama_url}. "
                    "¿Está el daemon de Ollama arrancado?"
                )
            except requests.exceptions.Timeout:
                return (
                    f"[ERROR OLLAMA] Timeout: El modelo '{model}' tardó demasiado "
                    "en cargar o responder."
                )
            except ValueError:
                status = (
                    response.status_code if response is not None else "desconocido"
                )
                return (
                    "[ERROR OLLAMA] La respuesta del servidor no es un JSON válido. "
                    f"Status: {status}"
                )
            except Exception as exc:
                return f"[ERROR OLLAMA] Fallo crítico en inferencia: {exc}"

        return self._execute_local_heavy_request(
            model,
            request,
            unload_after=unload_after,
        )

    def _unload_ollama_model(self, model_id: str) -> bool:
        """Unload a model while the caller holds the shared VRAM slot."""

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={"model": model_id, "keep_alive": 0},
                timeout=5,
            )
            response.raise_for_status()
            print(f" > [VRAM] Modelo '{model_id}' descargado correctamente de la GPU.")
            return True
        except requests.exceptions.RequestException as exc:
            print(
                f" > [VRAM WARNING] No se pudo liberar el modelo '{model_id}' "
                f"de Ollama: {exc}"
            )
            return False
        except Exception as exc:
            print(f" > [VRAM ERROR] Excepción inesperada al descargar el modelo '{model_id}': {exc}")
            return False
    def _fallback_with_notice(self, original_prompt: str, reason: str) -> str:
        """
        Activa el modelo de habla (SPEECH) como plan de contingencia ante un fallo
        en un modelo especializado, anteponiendo un aviso obligatorio al usuario.
        """
        print(f" > [ROUTER FALLBACK] Activando contingencia con SPEECH. Motivo: {reason}")
        
        aviso_obligatorio = (
            f"No se ha podido usar el modelo correspondiente para esta tarea debido a que {reason}, "
            f"así que utilizaré el modelo de habla en su lugar solo para esta consulta."
        )
        
        system_prompt = (
            f"INSTRUCCIÓN OBLIGATORIA: Comienza tu respuesta empezando exactamente con esta frase, sin modificar ni una sola palabra:\n"
            f"\"{aviso_obligatorio}\"\n\n"
            f"A continuación, procesa y responde a la siguiente petición de la mejor manera posible:\n\n"
            f"{original_prompt}"
        )
        
        return self._call_ollama(
            MODEL_ORCHESTRATOR_LOCAL,
            system_prompt,
            **SPEECH_INFERENCE_PROFILE.as_ollama_kwargs(),
        )

    def _call_groq(
        self,
        prompt: str,
        *,
        model: str = MODEL_GROQ_CLOUD,
        temperature: float = 0.6,
        max_tokens: int | None = None,
    ) -> str:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=15,
        )
        response.raise_for_status()
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        raise RuntimeError(f"Error Groq API: {response.text}")

    def _call_groq_fallback(self, prompt: str) -> str:
        """Legacy alias retained for the pre-hybrid routing flow."""

        return self._call_groq(prompt)

    def route_with_memory(
        self, 
        role: ModelRole, 
        system_prompt: str, 
        session_history: Union[str, list], 
        user_input: str
    ) -> str:
        """
        Ensambla el prompt completo inyectando el system prompt, 
        el historial reciente y la entrada del usuario, enviándolo al router.
        """
        # 1. Normalizar y sanitizar el historial (soportar tanto str como list)
        if isinstance(session_history, list):
            # Recortamos a los últimos 10 turnos para evitar saturar la ventana de contexto del LLM
            ultimos_turnos = session_history[-10:]
            history_str = "\n".join([str(h) for h in ultimos_turnos])
        else:
            history_str = str(session_history).strip()

        # 2. Construcción condicional de la sección de historial
        history_section = f"Historial reciente de conversación:\n{history_str}\n" if history_str else ""

        # 3. Ensamblaje limpio del prompt total
        prompt_total = f"""{system_prompt.strip()}

{history_section}Usuario: {user_input.strip()}"""

        return self.route(role, prompt_total)

    def get_contextual_wait_phrase(self, prompt: str) -> str:
        texto_lower = prompt.lower()
        
        if any(kw in texto_lower for kw in ["captura", "pantalla", "monitor", "abiertas", "apps"]):
            return "Entendido Diego, un momento mientras capturo el escritorio y analizo los procesos visuales..."
            
        elif any(kw in texto_lower for kw in ["busca", "internet", "busquen", "buscan"]):
            return "Iniciando rastreo en internet para tu consulta, un segundo..."
            
        palabras_investigacion = ["cuándo", "partido", "resultado", "quién", "dónde", "precio", "último", "noticia", "horario", "cuál", "cómo", "mejor", "materiales", "dime", "qué", "arduino", "impresora"]
        if any(p in texto_lower for p in palabras_investigacion) and len(prompt.split()) > 2:
            frases_autonomas = [
                "No tengo suficiente información confirmada para esto. Dame un momento, voy a buscar en la red para asegurarme.",
                "Para darte una respuesta técnica precisa necesito consultar internet. Dame un segundo...",
                "Revisando bases de datos externas para responderte correctamente, espera un instante."
            ]
            return random.choice(frases_autonomas)
            
        elif "impresora" in texto_lower or "klipper" in texto_lower:
            return "Consultando la telemetría y el estado actual de la impresora..."
            
        else:
            return "Procesando, dame un momento..."

    def resolver_elipsis_consulta(self, usuario: str, session_context: Any) -> str:
        texto_lower = usuario.lower()
        if len(usuario.split()) < 6 and any(p in texto_lower for p in ["antes", "después", "ese", "aquel", "cuál", "y"]):
            if isinstance(session_context, list) and session_context:
                ultimo_contexto = session_context[-1]
                if isinstance(ultimo_contexto, dict):
                    contexto_texto = ultimo_contexto.get("content", "")
                elif isinstance(ultimo_contexto, str):
                    contexto_texto = ultimo_contexto
                else:
                    contexto_texto = ""
                return f"{contexto_texto} {usuario}" if contexto_texto else usuario
        return usuario

    def sintetizar_respuesta_web(self, prompt_usuario: str, datos_web: str, session_history: Any) -> str:
        print(" > [ROUTER] Iniciando Pipeline Multi-Agente en cadena...")
        respuesta_cruda = self.ejecutar_pipeline_cognitivo(prompt_usuario)
        return TechnicalValidator.audit_response(prompt_usuario, respuesta_cruda)

    def route_inteligente(self, prompt: str) -> dict:
        prompt_arquitecto = f"""Eres el Arquitecto Cognitivo de JARVIS. Analiza la petición del usuario y decide qué modelo de IA debe encargarse de resolverla o si necesita consultar un archivo del workspace.
        
Modelos disponibles:
1. "speech" (Qwen3.5 4B): Orquestación, charla y explicaciones generales.
2. "coding" (Qwen 2.5 Coder): Exclusivo para escribir código, scripts, macros de G-Code/Klipper o programar.
3. "deep_reasoning" (Qwen3.5 9B): Razonamiento de ingeniería, física y circuitos.

Petición del usuario: "{prompt}"

Responde ÚNICAMENTE con un objeto JSON plano que contenga exactamente estas claves:
{{"rol_principal": "speech" o "coding" o "deep_reasoning", "requiere_codigo": true/false, "archivo_a_leer": "nombre_del_archivo.py o null", "razon": "breve explicacion"}}
"""
        try:
            respuesta_json = self._call_ollama(
                MODEL_ORCHESTRATOR_LOCAL,
                prompt_arquitecto,
                **ARCHITECT_INFERENCE_PROFILE.as_ollama_kwargs(),
            )
            match = re.search(r'\{.*\}', respuesta_json, re.DOTALL)
            if match:
                json_str = match.group(0)
                datos = json.loads(json_str)
                print(f" > [ARQUITECTO IA] Decisión de ruta -> Rol: {datos.get('rol_principal')} | Razón: {datos.get('razon')}")
                return datos
            else:
                raise ValueError("No se encontró un objeto JSON válido en la respuesta del orquestador.")
        except Exception as e:
            print(f"[ROUTER WARNING] Fallo en el orquestador cognitivo ({e}). Usando fallback a coding por defecto.")
            return {"rol_principal": "coding", "requiere_codigo": True}

    def _build_image_pipeline(self, prompt_usuario: str) -> list[dict[str, Any]]:
        """Construye un plan de procesamiento correcto para peticiones relacionadas con imágenes.

        Las peticiones de tipo “haz una captura y dime lo que ves” deben analizar la
        propia captura, no buscar la frase del usuario dentro de un mapa estructurado
        de la pantalla. Ese segundo patrón solo es útil para localizar un texto o una
        UI concreta dentro del editor.
        """
        texto = (prompt_usuario or "").lower()

        direct_visual_keywords = (
            "dime lo que ves",
            "que ves",
            "qué ves",
            "qué hay",
            "que hay",
            "describe la imagen",
            "describe esto",
            "mira lo que ves",
            "qué se ve",
            "que se ve",
            "observa",
            "qué está",
            "que está",
        )
        capture_keywords = (
            "captura de pantalla",
            "haz una captura",
            "toma una captura",
            "captura la pantalla",
            "screenshot",
            "pantalla",
        )
        location_keywords = (
            "localiza",
            "ubicación exacta",
            "ubicacion exacta",
            "coordenada",
            "posición exacta",
            "posicion exacta",
            "dónde está el botón",
            "donde esta el boton",
            "dónde está el texto",
            "donde esta el texto",
            "en qué parte está el botón",
            "en que parte esta el boton",
            "encuentra el botón",
            "encuentra el boton",
            "encuentra el texto",
        )

        analysis_keywords = (
            "dime cómo harías",
            "dime como harias",
            "cómo harías",
            "como harias",
            "resuelve",
            "ejercicio",
            "explícame",
            "explicame",
            "analiza",
            "describe",
            "qué ves",
            "que ves",
            "qué hay",
            "que hay",
        )

        if any(kw in texto for kw in capture_keywords) and any(kw in texto for kw in direct_visual_keywords):
            return [{
                "orden": 1,
                "rol": "deep_reasoning",
                "usar_mapa_ocr": True,
                "tarea": (
                    f"Describe lo que ves en la pantalla y responde directamente a: '{prompt_usuario}'. "
                    "Usa el contenido OCR como contexto, sin buscar la pregunta como texto literal "
                    "ni mencionar coordenadas o zonas salvo que se soliciten explícitamente."
                ),
            }]

        if any(kw in texto for kw in location_keywords):
            return [
                {
                    "orden": 1,
                    "rol": "vision",
                    "tarea": f"Busca en el MAPA ESTRUCTURADO el texto exacto relacionado con: '{prompt_usuario}'. Indica únicamente la zona (Izquierda, Centro o Derecha) y si está arriba, en el medio o abajo.",
                },
                {
                    "orden": 2,
                    "rol": "deep_reasoning",
                    "tarea": f"El usuario pregunta: '{prompt_usuario}'. El paso 1 indica que está en: [RESULTADO DEL PASO 1]. Escribe una única frase muy corta diciéndole en qué parte de la pantalla lo tiene (por ejemplo: 'Lo tienes en el centro del editor de código'). PROHIBIDO dar instrucciones, prohibido pedir que haga capturas, prohibido inventar nombres raros. Sé directo.",
                },
            ]

        if any(kw in texto for kw in analysis_keywords):
            return [{
                "orden": 1,
                "rol": "deep_reasoning",
                "usar_mapa_ocr": True,
                "tarea": (
                    f"Analiza y responde directamente a la pregunta del usuario: '{prompt_usuario}'. "
                    "Usa el contenido visible recuperado por OCR como contexto y no busques la pregunta "
                    "como texto literal ni indiques coordenadas salvo que el usuario las pida explícitamente."
                ),
            }]

        return []

    @staticmethod
    def _es_consulta_de_codigo(prompt_usuario: str) -> bool:
        texto = (prompt_usuario or "").lower()
        peticion_visual = any(
            termino in texto
            for termino in (
                "qué ves",
                "que ves",
                "qué hay en pantalla",
                "que hay en pantalla",
                "describe la imagen",
                "describe esto",
            )
        )
        terminos_codigo = (
            "código",
            "codigo",
            "función",
            "funcion",
            "clase",
            "método",
            "metodo",
            "variable",
            "línea",
            "linea",
            "archivo",
            "script",
            "bug",
            "error",
            "qué está haciendo",
            "que esta haciendo",
            "analiza el código",
            "analiza el codigo",
            "explica el código",
            "explica el codigo",
            "dónde está",
            "donde está",
        )
        return not peticion_visual and any(termino in texto for termino in terminos_codigo)

    @staticmethod
    def _extraer_fragmento_codigo(codigo_activo: str, prompt_usuario: str) -> str:
        def normalizar(texto: str) -> str:
            return unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode().lower()

        tokens = {
            token
            for token in re.findall(r"[a-zA-Z_]\w{2,}", normalizar(prompt_usuario))
            if token not in {
                "que", "qué", "hace", "esta", "está", "funcion", "función",
                "codigo", "código", "linea", "línea", "donde", "dónde",
                "sobre", "este", "esta", "para", "del", "las", "los",
            }
        }
        lineas = codigo_activo.splitlines()
        codigo_normalizado = normalizar(codigo_activo)

        try:
            arbol = ast.parse(codigo_activo)
            candidatos = []
            for nodo in ast.walk(arbol):
                if not isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                inicio = nodo.lineno - 1
                final = nodo.end_lineno or nodo.lineno
                bloque = normalizar("\n".join(lineas[inicio:final]))
                nombre = normalizar(nodo.name)
                puntuacion = sum(3 for token in tokens if token in bloque)
                if nombre in tokens:
                    puntuacion += 8
                if puntuacion:
                    candidatos.append((puntuacion, -(final - inicio), inicio, final))

            if candidatos:
                _, _, inicio, final = max(candidatos)
                return "\n".join(lineas[inicio:final])[:12000]
        except (SyntaxError, ValueError):
            pass

        coincidencias = [
            indice
            for indice, linea in enumerate(lineas)
            if any(token in normalizar(linea) for token in tokens)
        ]
        if coincidencias:
            rangos = []
            for indice in coincidencias[:3]:
                rango = (max(0, indice - 6), min(len(lineas), indice + 7))
                if rangos and rango[0] <= rangos[-1][1]:
                    rangos[-1] = (rangos[-1][0], max(rangos[-1][1], rango[1]))
                else:
                    rangos.append(rango)
            return "\n...\n".join(
                "\n".join(lineas[inicio:final]) for inicio, final in rangos
            )[:12000]

        return "\n".join(lineas[:80])[:12000] if codigo_normalizado else ""

    @staticmethod
    def _leer_mapa_ocr(image_path: str) -> str:
        try:
            txt_path = image_path.replace(".png", ".txt")
            if os.path.exists(txt_path):
                with open(txt_path, "r", encoding="utf-8") as archivo:
                    return archivo.read()

            with Image.open(image_path) as imagen:
                return pytesseract.image_to_string(imagen, lang="spa+eng")
        except Exception as exc:
            print(f" > [ROUTER] Error cargando OCR estructurado: {exc}")
            return ""

    @staticmethod
    def _capturar_pantalla_como_fallback() -> Optional[str]:
        try:
            from jarvis.skills.vision_skill import VisionSkill

            return VisionSkill().tomar_captura_pantalla()
        except Exception as exc:
            print(f"[ROUTER WARNING] No se pudo activar el fallback visual: {exc}")
            return None

    def ejecutar_pipeline_cognitivo(
        self, prompt_usuario: str, image_path: Optional[str] = None
    ) -> str:
        """
        Pipeline autónomo con planificador híbrido (determinista si hay visión, 
        evitando fallos de JSON en el arquitecto).
        """
        import os

        codigo_activo = None
        if self._es_consulta_de_codigo(prompt_usuario):
            codigo_activo = obtener_archivo_activo_vscode()
            if codigo_activo:
                fragmento_codigo = self._extraer_fragmento_codigo(
                    codigo_activo, prompt_usuario
                )
                prompt_codigo = (
                    "Analiza este fragmento de código de tu workspace y responde a la pregunta: "
                    f"{prompt_usuario}\n\n{fragmento_codigo}"
                )
                return self.route(ModelRole.CODING, prompt_codigo)
            elif not image_path:
                image_path = self._capturar_pantalla_como_fallback()

        # 1. Validación de recursos físicos y corrupción de imagen (Gatekeeper)
        if image_path:
            if not os.path.exists(image_path):
                return "JARVIS: No se ha podido acceder al archivo de la captura de pantalla."
            
            # Comprobar que la captura no sea un "píxel vacío" o corrupta
            try:
                from PIL import Image
                with Image.open(image_path) as img:
                    width, height = img.size
                    if width < 10 or height < 10:
                        return f"JARVIS: [ERROR VISUAL] La captura generada es inválida o fue bloqueada por el SO ({width}x{height} píxeles). Operación abortada."
            except Exception as e:
                return f"JARVIS: El archivo de imagen generado está corrupto. Error: {e}"

        role_map = {
            "speech": ModelRole.SPEECH,
            "coding": ModelRole.CODING,
            "deep_reasoning": ModelRole.DEEP_REASONING,
            "vision": ModelRole.VISION
        }
        pasos = []
        if image_path:
            pasos = self._build_image_pipeline(prompt_usuario)
            if not pasos:
                pasos = [
                    {
                        "orden": 1,
                        "rol": "deep_reasoning",
                        "usar_mapa_ocr": True,
                        "tarea": (
                            f"Analiza el contenido visible de la pantalla y responde directamente a: "
                            f"'{prompt_usuario}'. Usa el mapa OCR como contexto y ofrece una respuesta útil; "
                            "no busques la pregunta como texto literal ni inventes coordenadas."
                        ),
                    }
                ]

        try:
            contexto_acumulado = f"Petición original del usuario: {prompt_usuario}\n\n"
            respuesta_final = ""
            
            for paso in sorted(pasos, key=lambda x: x.get("orden", 0)):
                orden = paso.get("orden")
                rol_str = paso.get("rol", "deep_reasoning")
                tarea = paso.get("tarea")
                rol_actual = role_map.get(rol_str, ModelRole.DEEP_REASONING)
                
                print(f" > [PASO {orden}] Ejecutando rol [{rol_str}] -> Tarea: {tarea}")
                
                prompt_paso = f"""Actúa como el especialista asignado en este paso del pipeline de JARVIS.
Contexto previo acumulado:
{contexto_acumulado}

Tu tarea específica: {tarea}
"""
                if paso.get("usar_mapa_ocr") and image_path and os.path.exists(image_path):
                    ocr_extraido = self._leer_mapa_ocr(image_path)
                    prompt_paso += (
                        "\n--- MAPA OCR COMPLETO DE LA PANTALLA ---\n"
                        f"{ocr_extraido or '(No disponible)'}\n"
                        "--- FIN DEL MAPA OCR ---\n"
                    )
                    resp_paso = self.route(rol_actual, prompt_paso)
                elif rol_actual == ModelRole.VISION and image_path and os.path.exists(image_path):
                    # --- AQUÍ INYECTAMOS EL OCR ESTRUCTURADO ---
                    ocr_extraido = self._leer_mapa_ocr(image_path)

                    # Cambiamos un poco el prompt para que el LLM sepa qué está leyendo
                    prompt_paso_con_ocr = f"""{prompt_paso}

--- MAPA ESTRUCTURADO DE LA PANTALLA (Coordenadas y Zonas) ---
{ocr_extraido if ocr_extraido else "(No disponible)"}
----------------------------------------------------------------------
"""
                    # -------------------------------------

                    with open(image_path, "rb") as imagen:
                        image_bytes = imagen.read()
                        if self.gemini_api_key:
                            try:
                                resp_paso = self._call_gemini_vision(prompt_paso_con_ocr, image_bytes)
                            except Exception:
                                resp_paso = self._call_vision_ollama_bytes(MODEL_VISION_LOCAL, prompt_paso_con_ocr, image_bytes)
                        else:
                            resp_paso = self._call_vision_ollama_bytes(MODEL_VISION_LOCAL, prompt_paso_con_ocr, image_bytes)
                else:
                    resp_paso = self.route_with_memory(rol_actual, prompt_paso, "", prompt_usuario)
                
                

                contexto_acumulado += f"\n--- Resultado del Paso {orden} ({rol_str}) ---\n{resp_paso}\n"
                respuesta_final += f"\n\n### [Paso {orden} - {rol_str.upper()}]:\n{resp_paso}"
                
            return respuesta_final
            
        except Exception as e:
            print(f"[PIPELINE WARNING] Error crítico en ejecución: {e}")
            return f"JARVIS: No he podido procesar la solicitud debido a una excepción técnica ({e})."
