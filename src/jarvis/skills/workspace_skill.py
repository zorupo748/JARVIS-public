import os
from pathlib import Path


def obtener_archivo_activo_vscode():
    """Devuelve el contenido del archivo activo en la ventana de VS Code."""
    try:
        import pygetwindow as gw

        ventana = gw.getActiveWindow()
        titulo = getattr(ventana, "title", "") if ventana else ""
        titulo = titulo.strip()
        titulo_lower = titulo.lower()

        if not titulo or (
            "visual studio code" not in titulo_lower and "jarvis" not in titulo_lower
        ):
            return None

        partes = [parte.strip() for parte in titulo.split(" - ")]
        nombre_archivo = partes[0] if partes else ""
        if not nombre_archivo or nombre_archivo.lower() in {
            "visual studio code",
            "welcome",
            "untitled",
        }:
            return None

        raiz_workspace = Path(__file__).resolve().parents[3]
        candidatos = [raiz_workspace / nombre_archivo]
        candidatos.extend(
            ruta
            for ruta in raiz_workspace.rglob(nombre_archivo)
            if ".venv" not in ruta.parts and "__pycache__" not in ruta.parts
        )

        archivo_path = next(
            (ruta for ruta in candidatos if ruta.is_file()),
            None,
        )
        if archivo_path is None:
            return None

        print(f" > [WORKSPACE] Archivo activo detectado en VS Code: {archivo_path.name}")
        ruta_relativa = archivo_path.relative_to(raiz_workspace)
        contenido = WorkspaceSkill(str(raiz_workspace)).leer_archivo(str(ruta_relativa))
        return contenido if not contenido.startswith("Error") else None
    except Exception:
        return None

class WorkspaceSkill:
    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir).resolve()

    def leer_archivo(self, ruta_relativa: str) -> str:
        """
        Lee el contenido completo de un archivo del repositorio de forma segura.
        """
        try:
            # Limpiar ruta por si viene con slashes invertidos o espacios extra
            ruta_limpia = ruta_relativa.strip().strip('"\'')
            archivo_path = (self.root_dir / ruta_limpia).resolve()

            # Validación de seguridad: evitar path traversal (salir del root)
            if not str(archivo_path).startswith(str(self.root_dir)):
                return "Error: Acceso denegado fuera del workspace."

            if not archivo_path.exists() or not archivo_path.is_file():
                return f"Error: El archivo '{ruta_relativa}' no existe en el workspace."

            with open(archivo_path, "r", encoding="utf-8") as f:
                contenido = f.read()

            print(f" > [WORKSPACE] Archivo leído correctamente: {archivo_path.name} ({len(contenido)} caracteres)")
            return contenido

        except Exception as e:
            return f"Error crítico al leer el archivo: {e}"

    def listar_archivos(self, extension: str = ".py") -> list:
        """
        Lista todos los archivos del workspace que coincidan con una extensión.
        """
        try:
            archivos = [str(p.relative_to(self.root_dir)) for p in self.root_dir.rglob(f"*{extension}") if ".venv" not in p.parts and "__pycache__" not in p.parts]
            return archivos
        except Exception as e:
            print(f" > [ERROR WORKSPACE LISTAR]: {e}")
            return []