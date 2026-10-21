from __future__ import annotations

import ast
import re
import traceback
from pathlib import Path
from typing import Tuple

from jarvis.core.config import DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE
from jarvis.core.skill_error_handler import SkillErrorHandler

ALLOWED_IMPORTS = {
    "requests", "json", "math", "datetime", "re", "urllib", 
    "os", "sys", "pathlib", "subprocess", "time", "random", 
    "cv2", "PIL", "pyautogui", "numpy", "psutil", "sqlite3",
    "threading", "asyncio", "typing", "tkinter", "jarvis"
}
FORBIDDEN_FUNCTIONS = {"eval", "exec", "compile", "open", "__import__"}
FORBIDDEN_OCR_IMPORTS = {
    "pytesseract", "tesseract", "easyocr", "paddleocr", "keras_ocr",
}
FORBIDDEN_OPENCV_GUI_FUNCTIONS = {
    "imshow", "namedWindow", "destroyWindow", "destroyAllWindows",
    "waitKey", "waitKeyEx", "createTrackbar", "selectROI",
    "selectROIs", "displayOverlay", "displayStatusBar",
}
REGLA_DE_ORO_ONE_SHOT = (
    "REGLA DE ORO: Todas las skills deben ser de uso único (one-shot). "
    "La función principal debe ejecutarse, realizar su tarea, devolver el resultado "
    "y terminar inmediatamente. ESTÁ ESTRICTAMENTE PROHIBIDO usar bucles infinitos "
    "(como 'while True') o bloqueos continuos ('time.sleep' en bucle). "
    "La skill se enciende, actúa y se apaga. "
    "Si necesitas ejecutar comandos reales de terminal, usa llamadas limpias y explícitas "
    "con subprocess y listas de argumentos, sin shell persistente ni procesos bloqueantes."
)
REGLA_GUI_AUTOCIERRE = (
    "REGLA OBLIGATORIA PARA SCRIPTS CON INTERFAZ GRÁFICA O VENTANAS: Nunca uses un bucle "
    "infinito, un mainloop sin salida o una espera bloqueante indefinida. Programa siempre "
    "el autocierre antes de iniciar el bucle de eventos y deja que el flujo continúe hacia "
    "la captura de pantalla y visión. En Tkinter usa exactamente un temporizador de 2 segundos, "
    "por ejemplo `root.after(2000, root.destroy)` seguido de `root.mainloop()`. En otros "
    "frameworks usa el timeout equivalente de 2000 ms y su método de cierre. No uses "
    "`cv2.waitKey(0)` ni esperas indefinidas. PROHIBIDO usar OpenCV para abrir ventanas "
    "o interfaces: no uses `cv2.imshow`, `cv2.namedWindow` ni APIs GUI equivalentes de cv2. "
    "Para crear ventanas y mostrar texto usa siempre Tkinter, la librería nativa de Python. "
    "Para capturas usa `pyautogui` o `PIL.ImageGrab`. Reserva OpenCV exclusivamente para "
    "procesamiento de matrices de píxeles cuando sea estrictamente necesario."
)
REGLA_VISION_NATIVA = (
    "REGLA OBLIGATORIA PARA ANÁLISIS VISUAL U OCR: Está prohibido importar o ejecutar "
    "motores OCR externos como `pytesseract`, `tesseract`, `easyocr` o `paddleocr`. "
    "Usa exclusivamente el subsistema de visión nativo de JARVIS: delega en "
    "`jarvis.skills.vision_skill.VisionSkill` para capturas/análisis o en el router "
    "nativo con `ModelRole.VISION`. No implementes OCR local ni invoques binarios OCR; "
    "devuelve el resultado del subsistema nativo."
)
ERROR_BUCLE_INFINITO = (
    "[ERROR ARQUITECTÓNICO] Las skills no pueden contener bucles infinitos "
    "(while True). Deben ser de ejecución única. Corrige el código."
)
ERROR_GUI_SIN_AUTOCIERRE = (
    "[ERROR ARQUITECTÓNICO] Una interfaz gráfica no puede iniciar mainloop() sin un "
    "autocierre temporizado de 2000 ms. Programa `root.after(2000, root.destroy)` "
    "o el timeout equivalente antes de mainloop()."
)
ERROR_OPENCV_GUI = (
    "[ERROR ARQUITECTÓNICO] OpenCV no puede abrir ventanas ni interfaces gráficas. "
    "Usa Tkinter para la ventana y pyautogui o PIL.ImageGrab para la captura; reserva "
    "cv2 para procesamiento de matrices de píxeles."
)
ERROR_OCR_EXTERNO = (
    "[ERROR ARQUITECTÓNICO] No se permiten motores OCR externos en una skill. "
    "Usa exclusivamente el subsistema de visión nativo de JARVIS."
)
CONTRATO_SKILL_MANAGER = (
    "CONTRATO OBLIGATORIO DEL CARGADOR: El módulo debe contener exactamente una única "
    "función pública de nivel superior llamada 'ejecutar_skill'. Esa función será el "
    "primer y único callable público que SkillManager registrará. No definas clases "
    "públicas ni otras funciones públicas. Mantén las funciones auxiliares con nombre "
    "privado ('_nombre_auxiliar') y usa imports de módulo ('import modulo'), no "
    "'from modulo import Nombre' que pueda convertirse accidentalmente en el callable "
    "seleccionado. 'ejecutar_skill' debe aceptar únicamente parámetros opcionales con "
    "valores por defecto y devolver directamente el resultado de la operación."
)
DIRECTIVA_WINDOWS = (
    "El sistema operativo anfitrión es Windows (PowerShell/CMD). Todo el código generado "
    "que involucre comandos de consola, subprocesos (subprocess), llamadas a herramientas "
    "externas como nvidia-smi o manejo de rutas debe ser estrictamente compatible con Windows. "
    "Queda totalmente prohibido utilizar sintaxis, comandos o redirecciones exclusivas de Linux "
    "(como 2>/dev/null) a menos que el usuario lo solicite explícitamente."
)
DIRECTIVA_FUSION_EXISTENTE = (
    "DIRECTIVA OBLIGATORIA PARA MODIFICACIONES: Estás modificando una skill existente. "
    "Está terminantemente prohibido eliminar métodos, tablas, funciones o bloques de código "
    "que ya funcionaban. Actúa mediante fusión o reemplazo quirúrgico únicamente de la función "
    "solicitada y conserva intacto el resto de la estructura, incluyendo SQLite, bases de datos, "
    "GPU, comandos externos y manejo de errores. Devuelve el archivo completo resultante, "
    "manteniendo todo el código no relacionado con el cambio."
)

class DynamicSkillBuilder:
    """
    Genera y valida sintácticamente nuevas habilidades para evitar ejecuciones nocivas.
    """
    def __init__(self, skills_dir: Path, model_router: object | None = None):
        self.dynamic_dir = skills_dir / "dynamic"
        self.dynamic_dir.mkdir(parents=True, exist_ok=True)
        self.error_handler = SkillErrorHandler(model_router=model_router)

    def validate_code_safety(self, code_str: str) -> Tuple[bool, str]:
        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return False, f"Sintaxis inválida: {e}"

        tiene_mainloop = False
        tiene_autocierre_gui = False
        nombres_opencv = {"cv2"}

        for node in ast.walk(tree):
            if isinstance(node, ast.While) and isinstance(node.test, ast.Constant):
                es_uno = node.test.value is True or (
                    isinstance(node.test.value, int)
                    and not isinstance(node.test.value, bool)
                    and node.test.value == 1
                )
                if es_uno:
                    return False, ERROR_BUCLE_INFINITO

            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                objeto = node.func.value
                if (
                    isinstance(objeto, ast.Name)
                    and objeto.id in nombres_opencv
                    and node.func.attr in FORBIDDEN_OPENCV_GUI_FUNCTIONS
                ):
                    return False, ERROR_OPENCV_GUI
                if node.func.attr == "mainloop":
                    tiene_mainloop = True
                elif node.func.attr == "after" and node.args:
                    demora = node.args[0]
                    if isinstance(demora, ast.Constant) and demora.value == 2000:
                        tiene_autocierre_gui = True

            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in FORBIDDEN_FUNCTIONS:
                    return False, f"Función prohibida: '{node.func.id}'"

            if isinstance(node, ast.Import):
                for alias in node.names:
                    base = alias.name.split('.')[0]
                    if base in FORBIDDEN_OCR_IMPORTS:
                        return False, ERROR_OCR_EXTERNO
                    if base not in ALLOWED_IMPORTS:
                        return False, f"Módulo no permitido: '{alias.name}'"
                    if base == "cv2":
                        nombres_opencv.add(alias.asname or "cv2")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base = node.module.split('.')[0]
                    if base in FORBIDDEN_OCR_IMPORTS:
                        return False, ERROR_OCR_EXTERNO
                    if base not in ALLOWED_IMPORTS:
                        return False, f"Módulo no permitido: '{node.module}'"

        if tiene_mainloop and not tiene_autocierre_gui:
            return False, ERROR_GUI_SIN_AUTOCIERRE

        return True, "Código seguro."

    def audit_and_test_skill(self, code_str: str) -> Tuple[bool, str]:
        return False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        """Comprueba la estructura y la carga en memoria de una skill generada."""
        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return False, f"Sintaxis inválida durante la auditoría: {e}"

        funciones = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if not funciones:
            return False, "La skill no contiene ninguna función definida."

        namespace = {}
        try:
            exec(compile(tree, "<skill_audit>", "exec"), namespace, namespace)
        except Exception as e:
            return False, f"Error al cargar la skill en memoria: {e}"

        funciones_cargadas = [
            node.name
            for node in funciones
            if callable(namespace.get(node.name))
        ]
        if not funciones_cargadas:
            return False, "La skill declara funciones, pero ninguna se cargó correctamente."

        return True, f"Skill cargada en memoria con {len(funciones_cargadas)} función(es)."

    def create_skill_file(self, skill_name: str, code_str: str) -> Tuple[bool, str]:
        return False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        is_safe, msg = self.validate_code_safety(code_str)
        if not is_safe:
            return False, f"Seguridad: {msg}"

        # <--- AQUÍ: Aseguramos e instalamos dependencias antes de escribir el archivo
        self._ensure_dependencies(code_str)

        file_path = self.dynamic_dir / f"{skill_name}.py"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code_str)
            return True, str(file_path)
        except Exception as e:
            return False, f"Error al escribir archivo: {e}"

        
    def _ensure_dependencies(self, code_str: str):
        return False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        """Instala automáticamente paquetes externos permitidos si no están presentes."""
        try:
            tree = ast.parse(code_str)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
            
            pypi_mapping = {
                'cv2': 'opencv-python',
                'PIL': 'Pillow',
                'psutil': 'psutil',
            }
            import subprocess
            import sys
            
            for mod in imports:
                pkg = pypi_mapping.get(mod, mod)
                try:
                    __import__(mod)
                except ImportError:
                    print(f" > [BUILDER] Instalando dependencia requerida: {pkg}...")
                    python_path = str(sys.executable)
                    subprocess.run(
                        [python_path, "-m", "pip", "install", str(pkg)], 
                        check=True
                    )
        except Exception as e:
            print(f"[WARN] No se pudieron verificar/instalar dependencias: {e}")        

    @staticmethod
    def _extraer_codigo(codigo_generado: str) -> str:
        """Extrae código Python de una respuesta con o sin fences Markdown."""
        codigo_generado = str(codigo_generado or "").strip()
        bloque = re.search(r"```(?:python|py)?\s*(.*?)```", codigo_generado, re.DOTALL | re.IGNORECASE)
        return (bloque.group(1) if bloque else codigo_generado).strip()

    @staticmethod
    def _pedir_modelo(router, rol, prompt: str) -> str:
        """Usa el contrato común del router para las fases de razonamiento y código."""
        return DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        if not hasattr(router, "route"):
            raise AttributeError("El router no expone el método route().")
        return str(router.route(rol, prompt))

    def _diseñar_arquitectura(self, objetivo: str, router) -> str:
        return DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        prompt = f"""
Eres el ingeniero de arquitectura de JARVIS. Diseña una skill para este objetivo:
{objetivo}

No escribas código final. Devuelve un diseño técnico conciso que especifique:
- librerías permitidas y dependencias necesarias;
- funciones o clases y sus responsabilidades;
- manejo de errores, timeouts y fallos de red;
- configuración persistente o variables de entorno necesarias;
- contrato de entrada y salida para que SkillManager pueda cargar una función pública.
Prioriza una implementación segura y comprobable localmente.

{CONTRATO_SKILL_MANAGER}
{DIRECTIVA_WINDOWS}
{REGLA_DE_ORO_ONE_SHOT}
{REGLA_GUI_AUTOCIERRE}
""".strip()
        print("[FASE 1/4] Diseñando la arquitectura con deep_reasoning...")
        from jarvis.core.model_router import ModelRole

        return self._pedir_modelo(router, ModelRole.DEEP_REASONING, prompt)

    def _generar_codigo(
        self,
        objetivo: str,
        arquitectura: str,
        router,
        existing_skill_name: str | None = None,
    ) -> str:
        return DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        directiva_fusion = (
            f"\nNombre de la skill existente: {existing_skill_name}\n"
            f"{DIRECTIVA_FUSION_EXISTENTE}\n"
            if existing_skill_name
            else ""
        )
        prompt = f"""
Eres el programador de skills de JARVIS. Implementa una skill Python para este objetivo:
{objetivo}
{directiva_fusion}

Diseño arquitectónico aprobado:
--- DISEÑO ---
{arquitectura}
--- FIN DEL DISEÑO ---

Devuelve únicamente el código Python completo dentro de un bloque ```python```, sin explicación.
Debe definir al menos una función pública, evitar eval/exec/open y manejar errores de red sin
ocultar excepciones importantes. Usa solo librerías permitidas por el validador.
Cumple exactamente este contrato de carga:
{CONTRATO_SKILL_MANAGER}
{DIRECTIVA_WINDOWS}
Para comandos reales de terminal, usa subprocess con una lista de argumentos explícita y limpia;
no uses shell persistente ni dejes procesos bloqueados.

{REGLA_DE_ORO_ONE_SHOT}
{REGLA_GUI_AUTOCIERRE}
""".strip()
        print("[FASE 2/4] Generando código con coding...")
        from jarvis.core.model_router import ModelRole

        return self._extraer_codigo(self._pedir_modelo(router, ModelRole.CODING, prompt))

    def _corregir_codigo(
        self,
        objetivo: str,
        codigo: str,
        error: str,
        router,
        existing_skill_name: str | None = None,
    ) -> str:
        return DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        directiva_fusion = (
            f"\nLa skill existente que debes conservar y modificar es: {existing_skill_name}\n"
            f"{DIRECTIVA_FUSION_EXISTENTE}\n"
            if existing_skill_name
            else ""
        )
        prompt = f"""
El código de una skill para este objetivo ha fallado durante las pruebas locales:
{objetivo}
{directiva_fusion}

--- CÓDIGO FALLIDO ---
{codigo}
--- TRACEBACK / ERROR ---
{error}
--- FIN DEL ERROR ---

Analiza el fallo, corrige el código y devuelve la versión final completa dentro de un bloque
```python```. Conserva el objetivo, define al menos una función pública y no añadas eval, exec u open.
Devuelve únicamente el código corregido, sin explicación.
El código corregido debe cumplir exactamente este contrato de carga:
{CONTRATO_SKILL_MANAGER}
{DIRECTIVA_WINDOWS}
Para comandos reales de terminal, usa subprocess con una lista de argumentos explícita y limpia;
no uses shell persistente ni dejes procesos bloqueados.

{REGLA_DE_ORO_ONE_SHOT}
{REGLA_GUI_AUTOCIERRE}
""".strip()
        print("[CODER] Enviando el traceback para auto-corrección...")
        from jarvis.core.model_router import ModelRole

        return self._extraer_codigo(self._pedir_modelo(router, ModelRole.CODING, prompt))

    def reparar_skill_en_runtime(
        self,
        skill_name: str,
        error: str,
        router,
        skill_manager,
        max_intentos: int = 3,
    ) -> bool:
        handler = SkillErrorHandler(model_router=router)
        decision = handler.triage(
            error,
            phase="reparación_runtime",
            skill_name=skill_name,
        )
        print(f"[RUNTIME HEALER] {decision.executive_summary}")
        return False

        """Corrige una skill existente tras un fallo y la recarga sin cambiar su nombre."""
        file_path = self.dynamic_dir / f"{skill_name}.py"
        try:
            codigo_generado = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[RUNTIME HEALER] No se pudo leer {file_path}: {exc}")
            return False

        for intento in range(1, max_intentos + 1):
            print(f"[RUNTIME HEALER] Reparando {skill_name} (Intento {intento}/{max_intentos})...")
            try:
                codigo_generado = self._corregir_codigo(
                    f"reparar la skill existente '{skill_name}' tras un fallo en ejecución",
                    codigo_generado,
                    error,
                    router,
                    skill_name,
                )
            except Exception as exc:
                print(f"[RUNTIME HEALER] Falló la llamada al coder: {exc}")
                return False

            seguro, mensaje_seguridad = self.validate_code_safety(codigo_generado)
            if not seguro:
                error = mensaje_seguridad
                print(f"[RUNTIME HEALER] Corrección rechazada: {mensaje_seguridad}")
                continue

            self._ensure_dependencies(codigo_generado)
            sandbox_ok, informe_sandbox = self._probar_en_sandbox(codigo_generado)
            if not sandbox_ok:
                error = informe_sandbox
                print(f"[RUNTIME HEALER] La corrección aún falla: {informe_sandbox}")
                continue

            auditada, informe_auditoria = self.audit_and_test_skill(codigo_generado)
            if not auditada:
                error = informe_auditoria
                print(f"[RUNTIME HEALER] Auditoría fallida: {informe_auditoria}")
                continue

            exito, ruta = self.create_skill_file(skill_name, codigo_generado)
            if not exito:
                print(f"[RUNTIME HEALER] No se pudo sobrescribir la skill: {ruta}")
                return False

            descripcion = f"Habilidad autogenerada y reparada: {skill_name}"
            if not skill_manager.load_skill_from_file(skill_name, str(ruta), descripcion):
                print("[RUNTIME HEALER] El archivo se corrigió, pero no se pudo recargar.")
                return False

            print(f"[RUNTIME HEALER] Skill '{skill_name}' corregida y recargada.")
            return True

        print(f"[RUNTIME HEALER] Límite de {max_intentos} intentos alcanzado.")
        return False

    def _probar_en_sandbox(self, codigo_generado: str) -> Tuple[bool, str]:
        return False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE

        """Compila, importa y ejecuta la definición de la skill en un namespace nuevo."""
        try:
            compile(codigo_generado, "<skill_sandbox>", "exec")
            exec(codigo_generado, {})
            return True, "Sandbox ejecutado correctamente."
        except Exception:
            return False, traceback.format_exc()

            
    def generate_and_load_skill(
        self,
        objetivo: str,
        router,
        skill_manager,
        simulacion: bool,
        existing_skill_name: str | None = None,
    ) -> str:
        try:
            return DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE
        except Exception as exc:
            handler = SkillErrorHandler(model_router=router)
            decision = handler.triage(
                exc,
                phase="creación",
                user_request=objetivo,
                skill_name=existing_skill_name,
            )
            return decision.executive_summary

        """Genera, prueba, corrige y despliega una skill mediante varios agentes."""
        print(f"\n[JARVIS] Iniciando factoría multi-agente para: {objetivo}")
        
        if simulacion:
            print("[SIMULACIÓN] 1. Diseñaría la arquitectura con deep_reasoning.")
            print("[SIMULACIÓN] 2. Generaría el código con coding.")
            print("[SIMULACIÓN] 3. Ejecutaría hasta 5 pruebas con auto-corrección.")
            print("[SIMULACIÓN] 4. Pediría confirmación (s/n) antes de guardar.")
            return

        try:
            arquitectura = self._diseñar_arquitectura(objetivo, router)
            codigo_generado = self._generar_codigo(
                objetivo, arquitectura, router, existing_skill_name
            )
        except Exception as e:
            print(f"\n[ERROR] Falló la fase de diseño o programación: {e}")
            return

        max_intentos = 5
        codigo_aprobado = None
        for intento in range(1, max_intentos + 1):
            print(f"\n[TESTER] Probando skill (Intento {intento}/{max_intentos})...")
            seguro, mensaje_seguridad = self.validate_code_safety(codigo_generado)
            if seguro:
                self._ensure_dependencies(codigo_generado)
                sandbox_ok, informe_sandbox = self._probar_en_sandbox(codigo_generado)
            else:
                sandbox_ok, informe_sandbox = False, f"[SEGURIDAD] {mensaje_seguridad}"

            if sandbox_ok:
                auditada, informe_auditoria = self.audit_and_test_skill(codigo_generado)
                if auditada:
                    codigo_aprobado = codigo_generado
                    print(f"[AUDITORÍA OK] {informe_auditoria}")
                    break
                informe_sandbox = informe_auditoria

            print(f"[TESTER] Fallo detectado: {informe_sandbox}")
            if intento == max_intentos:
                print("[TESTER] Se alcanzó el límite de 5 intentos. Skill rechazada.")
                return

            print(f"[TESTER] Fallo detectado. Reprogramando (Intento {intento + 1}/{max_intentos})...")
            try:
                codigo_generado = self._corregir_codigo(
                    objetivo,
                    codigo_generado,
                    informe_sandbox,
                    router,
                    existing_skill_name,
                )
            except Exception as e:
                print(f"[ERROR] Falló la auto-corrección: {e}")
                return

        if codigo_aprobado is None:
            print("[AUDITORÍA FALLIDA] No se obtuvo una skill válida.")
            return

        codigo_generado = codigo_aprobado

        confirmacion = input("\n[JARVIS] ¿Autorizas la integración de esta skill? (s/n): ")
        if confirmacion.lower() == 's':
            if existing_skill_name:
                nombre = existing_skill_name.strip().replace(" ", "_")
                print(f"[JARVIS] Actualizando automáticamente la skill existente: {nombre}")
            else:
                nombre = input("Nombre de la skill (ej. consultar_clima): ").strip().replace(" ", "_")
            exito, ruta = self.create_skill_file(nombre, codigo_generado)
            if exito:
                print(f"[JARVIS] Habilidad guardada con éxito en {ruta}.")
                descripcion = f"Habilidad autogenerada: {objetivo}"
                if skill_manager.load_skill_from_file(nombre, str(ruta), descripcion):
                     print(f"[JARVIS] ¡Habilidad '{nombre}' cargada en caliente y lista para usarse ahora mismo!")
                else:
                     print(f"[WARN] Habilidad guardada pero falló la carga en caliente. Requiere reiniciar.")
            else:
                print(f"[ERROR] No se pudo crear el archivo: {ruta}")
        else:
            print("[JARVIS] Operación abortada.")
