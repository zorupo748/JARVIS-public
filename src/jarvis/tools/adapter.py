"""Registry adapter to fulfill the ToolRegistry protocol expected by JarvisAgent."""

from __future__ import annotations

from typing import Any, Dict, List
from jarvis.tools.registry import ToolRegistry as BaseRegistry


class AgentRegistryAdapter:
    """Adapta ToolRegistry a la interfaz Protocol del agente."""

    def get(self, name: str) -> Any:
        return BaseRegistry.get(name)

    def get_tool(self, name: str) -> Any:
        return BaseRegistry.get(name)

    def specifications(self) -> List[Dict[str, Any]]:
        """Extrae las especificaciones soportando todos los formatos de JARVIS."""
        specs = []
        seen_names = set()
        for tool_class in BaseRegistry.all():
            try:
                instance = tool_class()
                spec_dict: Dict[str, Any] | None = None

                # 1. Formato nuevo (usado en las herramientas de sistema/web)
                if hasattr(instance, "spec"):
                    spec_obj = instance.spec
                    if isinstance(spec_obj, dict):
                        spec_dict = spec_obj
                    elif hasattr(spec_obj, "__dict__"):
                        spec_dict = vars(spec_obj)  # Convierte el objeto ToolSpec a diccionario
                    else:
                        spec_dict = dict(vars(spec_obj))

                # 2. Formato original (método specification definido en registry.py)
                elif hasattr(instance, "specification"):
                    spec_dict = instance.specification()

                if spec_dict:
                    name = spec_dict.get("name")
                    if not name or name not in seen_names:
                        if name:
                            seen_names.add(name)
                        specs.append(spec_dict)

            except Exception as e:
                import logging
                logging.warning(f"No se pudo cargar la especificación de {tool_class.__name__}: {e}")

        return specs

    def all(self) -> Any:
        # Tu registry.py devuelve una lista en all(), lo cual es perfecto.
        return BaseRegistry.all()


__all__ = ["AgentRegistryAdapter"]