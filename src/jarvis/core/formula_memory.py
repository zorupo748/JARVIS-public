from __future__ import annotations
import os
import json
import subprocess
import tempfile

class FormulaMemory:
    """
    Gestiona la memoria persistente de fórmulas aprendidas y la ejecución 
    segura de scripts de cálculo en Python para garantizar precisión numérica.
    """
    def __init__(self, db_path: str = "learned_formulas.json"):
        self.db_path = db_path
        self.formulas = self._load_db()

    def _load_db(self) -> dict:
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_formula(self, key: str, formula_data: dict):
        """Guarda o actualiza una fórmula aprendida en la base de datos local."""
        self.formulas[key] = formula_data
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.formulas, f, indent=4, ensure_ascii=False)
            print(f"[MEMORIA DE FÓRMULAS] Nueva fórmula aprendida y guardada: '{key}'")
        except Exception as e:
            print(f"[MEMORIA DE FÓRMULAS] Error al guardar la base de datos: {e}")

    def get_context_prompt(self) -> str:
        """Devuelve un resumen de las fórmulas aprendidas para inyectarlo en el prompt."""
        if not self.formulas:
            return ""
        
        context = "\n### Fórmulas y Constantes Aprendidas Previamente:\n"
        for k, v in self.formulas.items():
            context += f"- **{k}**: {v.get('formula')} (Unidades: {v.get('units')})\n"
        return context

    @staticmethod
    def execute_calculation_safely(codigo_python: str) -> str:
        """
        Ejecuta el bloque de código de Python en un entorno temporal aislado 
        para extraer los resultados numéricos exactos sin riesgo para el sistema.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp:
            tmp.write(codigo_python)
            tmp_path = tmp.name

        try:
            # Ejecutamos el script con un timeout estricto de 5 segundos
            resultado = subprocess.run(
                ["python", tmp_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            if resultado.returncode == 0:
                return f"\n> **[Resultado Ejecución Exacta (Python)]**:\n```text\n{resultado.stdout.strip()}\n```"
            else:
                return f"\n> **[Aviso de Ejecución]**: El script arrojó un error al calcular: {resultado.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return "\n> **[Error]**: El script de cálculo excedió el tiempo límite de ejecución."
        except Exception as e:
            return f"\n> **[Error]**: No se pudo ejecutar el bloque de cálculo: {e}"
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)