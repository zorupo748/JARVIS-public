import json
import os
import sqlite3
from datetime import datetime

class MemoryManager:
    def __init__(self, storage_path="memory/jarvis_memory.json"):
        self.storage_path = storage_path
        self.sqlite_path = os.path.splitext(storage_path)[0] + ".db"
        self.data = {"facts": [], "learned_skills": []}
        self.session_history = []
        self.load()
        self._init_reminders_db()

    def _init_reminders_db(self):
        os.makedirs(os.path.dirname(self.sqlite_path) or ".", exist_ok=True)
        connection = sqlite3.connect(self.sqlite_path)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reminders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mensaje TEXT NOT NULL,
                    timestamp_objetivo TEXT NOT NULL,
                    completado INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def add_reminder(self, mensaje: str, timestamp_objetivo: datetime) -> int:
        connection = sqlite3.connect(self.sqlite_path)
        try:
            cursor = connection.execute(
                "INSERT INTO reminders (mensaje, timestamp_objetivo) VALUES (?, ?)",
                (mensaje.strip(), timestamp_objetivo.isoformat()),
            )
            connection.commit()
            if cursor.lastrowid is None:
                raise RuntimeError("No se pudo obtener el identificador del recordatorio.")
            return int(cursor.lastrowid)
        finally:
            connection.close()

    def get_due_reminders(self, now: datetime | None = None) -> list[dict]:
        now = now or datetime.now()
        connection = sqlite3.connect(self.sqlite_path)
        try:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, mensaje, timestamp_objetivo, completado
                FROM reminders
                WHERE completado = 0 AND timestamp_objetivo <= ?
                ORDER BY timestamp_objetivo
                """,
                (now.isoformat(),),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def complete_reminder(self, reminder_id: int) -> None:
        connection = sqlite3.connect(self.sqlite_path)
        try:
            connection.execute(
                "UPDATE reminders SET completado = 1 WHERE id = ?",
                (reminder_id,),
            )
            connection.commit()
        finally:
            connection.close()

    def load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                pass
        if not isinstance(self.data, dict):
            self.data = {"facts": [], "learned_skills": []}
        if not isinstance(self.data.get("facts"), list):
            self.data["facts"] = []
        if not isinstance(self.data.get("learned_skills"), list):
            self.data["learned_skills"] = []

    def save(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=4)

    def add_fact(self, fact: str) -> str:
        cleaned = fact.strip(" ,:.-")
        if not cleaned:
            return "No hay contenido válido para guardar."
        if not isinstance(self.data.get("facts"), list):
            self.data["facts"] = []
            
        if cleaned not in self.data["facts"]:
            self.data["facts"].append(cleaned)
            self.save()
            return f"He guardado en mi memoria permanente: '{cleaned}'"
        return "Ese hecho ya estaba registrado en mi memoria."

    def add_interaction(self, role: str, content: str):
        self.session_history.append({"role": role, "content": content})
        if len(self.session_history) > 10:
            self.session_history.pop(0)

    def get_session_context(self) -> str:
        return "\n".join([f"{item['role'].capitalize()}: {item['content']}" for item in self.session_history])