import requests
from typing import Dict, Any, Optional, List

class KlipperPrinterSkill:
    """
    Controlador para la Elegoo Neptune 4 Pro mediante la API de Moonraker/Fluidd.
    """
    def __init__(self, host: str = "http://192.168.1.145"):
        self.host = host.rstrip('/')

    def get_status(self) -> Dict[str, Any]:
        """Obtiene temperaturas, archivo en curso, estado y avance de impresión."""
        try:
            url = f"{self.host}/printer/objects/query?heater_bed&extruder&print_stats"
            res = requests.get(url, timeout=4)
            if res.status_code == 200:
                data = res.json().get('result', {}).get('status', {})
                bed_temp = data.get('heater_bed', {}).get('temperature', 0)
                ext_temp = data.get('extruder', {}).get('temperature', 0)
                state = data.get('print_stats', {}).get('state', 'offline')
                filename = data.get('print_stats', {}).get('filename', '')
                progress = data.get('print_stats', {}).get('progress', 0) * 100

                return {
                    "online": True,
                    "state": state,
                    "bed_temp": round(bed_temp, 1),
                    "extruder_temp": round(ext_temp, 1),
                    "filename": filename,
                    "progress": f"{round(progress, 1)}%"
                }
            return {"online": False, "error": f"HTTP {res.status_code}"}
        except Exception as e:
            return {"online": False, "error": str(e)}

    def list_files(self) -> List[str]:
        """Lista archivos .gcode cargados en Fluidd."""
        try:
            res = requests.get(f"{self.host}/server/files/list?root=gcodes", timeout=3)
            if res.status_code == 200:
                files = res.json().get('result', [])
                return [f['path'] for f in files if f['path'].endswith(('.gcode', '.bgcode'))]
            return []
        except Exception as e:
            return [f"Error al listar: {e}"]

    def start_print(self, filename: str) -> str:
        """Inicia la impresión de un archivo de la lista."""
        try:
            res = requests.post(
                f"{self.host}/printer/print/start",
                json={"filename": filename},
                timeout=4
            )
            return f"Impresión de '{filename}' iniciada." if res.status_code == 200 else f"Error: {res.text}"
        except Exception as e:
            return f"Error de envío: {e}"

    def emergency_stop(self) -> str:
        """Parada de emergencia M112."""
        try:
            res = requests.post(f"{self.host}/printer/emergency_stop", timeout=3)
            return "Parada de emergencia ejecutada." if res.status_code == 200 else "Fallo en M112."
        except Exception as e:
            return f"Error: {e}"

    def upload_and_print_local_file(self, file_path: str) -> str:
        """Sube un archivo G-code local al almacenamiento de Klipper, lo inicia y calcula datos útiles."""
        import os
        
        file_path = file_path.strip('"').strip("'").replace("/", os.sep)
        
        if not os.path.exists(file_path):
            return f"El archivo local '{file_path}' no existe en tu disco duro. Verifica la ruta."
        
        if not file_path.endswith(".gcode"):
            return "El archivo seleccionado no es un .gcode válido."

        url = f"{self.host}/server/files/upload"
        filename = os.path.basename(file_path)
        
        try:
            # Intentamos estimar el tiempo de impresión leyendo metadatos básicos del G-code (ej: capas o tiempo si el slicer lo deja escrito)
            tiempo_estimado = "unos minutos"
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                head = f.read(5000) # Leemos las primeras líneas donde los slicers suelen dejar el tiempo total o metadatos
                if "estimated printing time" in head.lower() or "TIME:" in head:
                    for line in head.splitlines():
                        if "time" in line.lower() or "duration" in line.lower():
                            tiempo_estimado = line.split(":")[-1].strip()
                            break

            with open(file_path, "rb") as f:
                files = {"file": (filename, f)}
                data = {"print": "true"}
                response = requests.post(url, files=files, data=data, timeout=60)
                
            if response.status_code in [200, 201]:
                return f"El archivo '{filename}' se ha subido con éxito a la Elegoo y la impresión ha comenzado. El tiempo estimado de impresión es de {tiempo_estimado}."
            else:
                return f"Error al subir el archivo a Klipper: {response.text}"
        except Exception as e:
            return f"Excepción crítica durante la subida del G-code: {e}"