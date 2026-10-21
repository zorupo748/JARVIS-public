import os
import time
import psutil
import sqlite3
import subprocess

class Monitor:
    def __init__(self):
        self._instance = os.path.dirname(os.path.abspath(__file__))
        self._db_path = os.path.join(self._instance, 'recursos.db')
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        
        self._resource_table = 'resources'
        self._resource_fields = [
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'fecha_hora TEXT',
            'cpu REAL',
            'ram REAL',
            'gpu_temperature TEXT',
            'gpu_vram TEXT'
        ]

    def get_hardware_data(self):
        # Intervalo de 0.1s para evitar el 0.0% inicial de la CPU
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram_usage = psutil.virtual_memory().percent
        gpu_temp, gpu_vram = "N/A", "N/A"
        
        try:
            cmd = ['nvidia-smi', '--query-gpu=temperature.gpu,memory.used', '--format=csv,noheader,nounits']
            nvidia = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output_line = nvidia.stdout.strip().split('\n')[0]
            parts = [p.strip() for p in output_line.split(',')]
            if len(parts) >= 2:
                gpu_temp = f"{parts[0]}°C"
                gpu_vram = f"{parts[1]} MB"
        except Exception as e:
            print(f'Aviso obteniendo datos de GPU: {e}')
            
        return {
            'cpu': cpu_usage,
            'ram': ram_usage,
            'gpu_temperature': gpu_temp,
            'gpu_vram': gpu_vram
        }

    def save_and_get_summary(self):
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        
        fields_str = ', '.join(self._resource_fields)
        cursor.execute(f"CREATE TABLE IF NOT EXISTS {self._resource_table} ({fields_str})")
        
        data = self.get_hardware_data()
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute(f"""
            INSERT INTO {self._resource_table} (fecha_hora, cpu, ram, gpu_temperature, gpu_vram)
            VALUES (?, ?, ?, ?, ?)
        """, (now, data['cpu'], data['ram'], data['gpu_temperature'], data['gpu_vram']))
        
        conn.commit()
        
        cursor.execute(f"SELECT * FROM {self._resource_table} ORDER BY id DESC LIMIT 3")
        rows = cursor.fetchall()
        
        summary = []
        for row in rows:
            summary.append({
                'id': row[0],
                'fecha_hora': row[1],
                'cpu': f"{row[2]}%",
                'ram': f"{row[3]}%",
                'gpu_temperature': row[4],
                'gpu_vram': row[5]
            })
            
        conn.close()
        return summary

def run(*args, **kwargs):
    """Punto de entrada estándar para JARVIS."""
    monitor = Monitor()
    resumen = monitor.save_and_get_summary()
    return f"Lectura de hardware completada con éxito. Últimos registros:\n{resumen}"