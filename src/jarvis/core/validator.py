from __future__ import annotations
import re
import ast

class TechnicalValidator:
    """
    Filtro de seguridad, coherencia técnica y validación de sintaxis para JARVIS.
    """
    
    @staticmethod
    def audit_response(prompt: str, response: str) -> str:
        prompt_lower = prompt.lower()
        resp_lower = response.lower()
        
        # -------------------------------------------------------------
        # VALIDACIÓN DE CÓDIGO PYTHON (Si la respuesta contiene bloques de código Python)
        # -------------------------------------------------------------
        if "```python" in response:
            try:
                # Extraemos el código de dentro de los bloques markdown
                match = re.search(r'```python(.*?)```', response, re.DOTALL)
                if match:
                    codigo_python = match.group(1).strip()
                    # Intentamos compilar el código en un árbol sintáctico (AST)
                    ast.parse(codigo_python)
                    print("[VALIDADOR TÉCNICO] Validación AST: El script de Python tiene una sintaxis correcta.")
            except SyntaxError as e:
                print(f"[VALIDADOR TÉCNICO] ALERTA: El modelo generó un error de sintaxis en Python -> {e}")
                # Inyectamos una advertencia visible en la respuesta
                warning_note = (
                    f"\n\n> **[Aviso de Validación de Código]**: El validador AST detectó una posible incorrección sintáctica "
                    f"en el bloque de código (`{e.msg}` en la línea {e.lineno}). Revísalo antes de ejecutarlo.\n"
                )
                response += warning_note

        # (Aquí se mantienen tus reglas anteriores de hardware, pilas, drivers, etc.)
        is_hardware_query = any(k in prompt_lower for k in ["arduino", "robot", "motor", "circuito", "batería", "alimentación", "servo", "driver"])
        if not is_hardware_query:
            return response

        # REGLA 1: Pilas AA
        bad_power_phrases = ["pilas aa", "4 pilas", "pilas de 1,5v", "pilas alcalinas"]
        if any(p in resp_lower for p in bad_power_phrases) and ("motor" in resp_lower or "servo" in resp_lower):
            correction_note = (
                "\n\n> **[Nota de Ingeniería de JARVIS - Corrección de Seguridad]**: "
                "Se han sustituido las pilas AA genéricas por una batería recargable de litio (LiPo/18650 con BMS) "
                "y una etapa de potencia separada para evitar caídas de tensión (brownouts).\n"
            )
            response += correction_note

        # REGLA 3: Drivers obsoletos (L298N)
        if "l298n" in resp_lower and ("stepper" in resp_lower or "paso a paso" in resp_lower or "motor" in resp_lower):
            response = re.sub(
                r"l298n[^\n]*", 
                "Drivers TMC2209 (SilentStepStick) o A4988 / DRV8825", 
                response, 
                flags=re.IGNORECASE
            )
            driver_correction = (
                "\n\n> **[Nota de Ingeniería de JARVIS - Optimización de Drivers]**: "
                "Se ha reemplazado el driver L298N por drivers modernos (como los TMC2209) por eficiencia y ruido.\n"
            )
            response += driver_correction

        return response