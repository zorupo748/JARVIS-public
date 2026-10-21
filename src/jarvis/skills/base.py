import importlib.util
import os
from typing import Callable, Dict, Any
from jarvis.core.config import DYNAMIC_SKILL_EXTERNAL_LOAD_DISABLED_MESSAGE

class SkillManager:
    """
    Registro y orquestador central de habilidades de JARVIS.
    Permite registrar herramientas, generar un catálogo para los LLMs 
    y cargar nuevas skills en caliente (Hot Reload).
    """
    def __init__(self):
        self._skills: Dict[str, Dict[str, Any]] = {}

    def register_skill(self, name: str, description: str, func: Callable):
        """Registra una función ejecutable dentro del catálogo de JARVIS."""
        self._skills[name] = {
            "description": description,
            "func": func
        }

    def execute(self, name: str, **kwargs) -> Any:
        """Ejecuta una habilidad por su identificador."""
        if name not in self._skills:
            raise ValueError(f"Skill '{name}' no encontrada.")
        return self._skills[name]["func"](**kwargs)

    def get_catalog(self) -> str:
        """Devuelve el catálogo formateado para inyectar en los prompts."""
        if not self._skills:
            return "HABILIDADES DISPONIBLES:\n(Ninguna registrada)"

        skills_list = [f"- {name}: {data['description']}" for name, data in self._skills.items()]
        return "HABILIDADES DISPONIBLES:\n" + "\n".join(skills_list) + "\n"

    def load_skill_from_file(self, nombre_skill: str, ruta_archivo: str, descripcion: str = "") -> bool:
        """
        Carga una habilidad dinámicamente desde un archivo .py en tiempo de ejecución.
        """
        print(f"[SKILL] {DYNAMIC_SKILL_EXTERNAL_LOAD_DISABLED_MESSAGE}")
        return False

        if not os.path.exists(ruta_archivo):
            print(f"[ERROR] El archivo {ruta_archivo} no existe.")
            return False

        try:
            # Importación dinámica del módulo
            spec = importlib.util.spec_from_file_location(nombre_skill, ruta_archivo)
            if spec is None or spec.loader is None:
                return False
                
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            
            # Buscar la primera función pública del módulo (ignorar imports y variables privadas)
            funciones_publicas = [attr for attr in dir(mod) if callable(getattr(mod, attr)) and not attr.startswith("_")]
            
            if not funciones_publicas:
                print(f"[ERROR] No se encontraron funciones llamables en {ruta_archivo}")
                return False
                
            func_name = funciones_publicas[0]
            func_to_register = getattr(mod, func_name)
            
            # Registrar la skill en el catálogo activo
            self.register_skill(nombre_skill, descripcion, func_to_register)
            return True
            
        except Exception as e:
            print(f"[ERROR] Fallo al cargar en caliente la skill {nombre_skill}: {e}")
            return False