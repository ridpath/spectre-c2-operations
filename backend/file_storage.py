import os
import shutil
from pathlib import Path
from typing import BinaryIO, Optional
from datetime import datetime, timezone
from uuid import UUID, uuid4
from config import get_settings

settings = get_settings()


class FileStorageService:
    def __init__(self):
        self._ensure_directories()
    
    def _ensure_directories(self):
        Path(settings.IQ_RECORDINGS_PATH).mkdir(parents=True, exist_ok=True)
        Path(settings.EVIDENCE_FILES_PATH).mkdir(parents=True, exist_ok=True)
        Path(settings.REPORTS_PATH).mkdir(parents=True, exist_ok=True)
    
    def save_iq_recording(
        self,
        file: BinaryIO,
        filename: str,
        satellite_name: Optional[str] = None,
        norad_id: Optional[int] = None
    ) -> tuple[str, str, int]:
        recording_id = uuid4()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        safe_filename = f"{timestamp}_{recording_id}_{filename}"
        file_path = os.path.join(settings.IQ_RECORDINGS_PATH, safe_filename)
        
        file_size = 0
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file, buffer)
            file_size = os.path.getsize(file_path)
        
        return safe_filename, file_path, file_size
    
    def save_evidence_file(
        self,
        file: BinaryIO,
        filename: str,
        mission_id: UUID
    ) -> tuple[str, str, int]:
        mission_dir = os.path.join(settings.EVIDENCE_FILES_PATH, str(mission_id))
        Path(mission_dir).mkdir(parents=True, exist_ok=True)
        
        evidence_id = uuid4()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{evidence_id}_{filename}"
        file_path = os.path.join(mission_dir, safe_filename)
        
        file_size = 0
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file, buffer)
            file_size = os.path.getsize(file_path)
        
        return safe_filename, file_path, file_size
    
    def save_report(
        self,
        content: str,
        mission_id: UUID,
        format: str = "markdown"
    ) -> tuple[str, str]:
        mission_dir = os.path.join(settings.REPORTS_PATH, str(mission_id))
        Path(mission_dir).mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        extension = {"markdown": "md", "json": "json", "html": "html"}.get(format, "txt")
        filename = f"report_{timestamp}.{extension}"
        file_path = os.path.join(mission_dir, filename)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        return filename, file_path
    
    def get_file(self, file_path: str) -> Optional[BinaryIO]:
        if not os.path.exists(file_path):
            return None
        return open(file_path, "rb")
    
    def delete_file(self, file_path: str) -> bool:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception:
            return False
    
    def get_file_size(self, file_path: str) -> int:
        if os.path.exists(file_path):
            return os.path.getsize(file_path)
        return 0


file_storage = FileStorageService()
