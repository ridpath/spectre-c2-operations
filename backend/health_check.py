from typing import Dict, Any
from datetime import datetime, timezone
from database import SessionLocal
from config import get_settings
import subprocess

settings = get_settings()


class HealthChecker:
    def __init__(self):
        self.checks: Dict[str, Any] = {}
        
    def check_database(self) -> Dict[str, Any]:
        try:
            db = SessionLocal()
            db.execute("SELECT 1")
            db.close()
            return {
                "status": "healthy",
                "message": "Database connection successful",
                "url": settings.DATABASE_URL.split('@')[1] if '@' in settings.DATABASE_URL else "configured"
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Database error: {str(e)}",
                "url": "unavailable"
            }
    
    def check_sdr_hardware(self) -> Dict[str, Any]:
        if not settings.ENABLE_SDR_HARDWARE:
            return {
                "status": "disabled",
                "message": "SDR hardware is disabled in configuration",
                "devices": []
            }
        
        try:
            from sdr_hardware import sdr_manager
            devices = sdr_manager.detect_devices()
            
            return {
                "status": "healthy" if devices and devices[0].get("available") else "no_devices",
                "message": f"Found {len(devices)} SDR device(s)",
                "devices": devices
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"SDR check failed: {str(e)}",
                "devices": []
            }
    
    def check_hamlib(self) -> Dict[str, Any]:
        if not settings.ENABLE_HAMLIB:
            return {
                "status": "disabled",
                "message": "Hamlib is disabled in configuration"
            }
        
        try:
            from hamlib_control import hamlib_rotator
            connected = hamlib_rotator.connect()
            
            if connected:
                position = hamlib_rotator.get_position()
                hamlib_rotator.disconnect()
                
                return {
                    "status": "healthy",
                    "message": f"Connected to rotctld at {settings.ROTCTLD_HOST}:{settings.ROTCTLD_PORT}",
                    "position": {
                        "azimuth": position.azimuth if position else 0,
                        "elevation": position.elevation if position else 0
                    } if position else None
                }
            else:
                return {
                    "status": "unavailable",
                    "message": f"Cannot connect to rotctld at {settings.ROTCTLD_HOST}:{settings.ROTCTLD_PORT}"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Hamlib check failed: {str(e)}"
            }
    
    def check_gnu_radio(self) -> Dict[str, Any]:
        if not settings.ENABLE_GNU_RADIO:
            return {
                "status": "disabled",
                "message": "GNU Radio is disabled in configuration"
            }
        
        try:
            result = subprocess.run(
                ["python3", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return {
                    "status": "healthy",
                    "message": "GNU Radio environment available",
                    "python_version": result.stdout.strip()
                }
            else:
                return {
                    "status": "unavailable",
                    "message": "Python3 not found"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"GNU Radio check failed: {str(e)}"
            }
    
    def check_nvd_api(self) -> Dict[str, Any]:
        try:
            from nvd_scanner import nvd_scanner
            
            return {
                "status": "healthy",
                "message": "NVD scanner initialized",
                "cache_size": len(nvd_scanner.cache),
                "api_key": "configured" if nvd_scanner.api_key else "not_configured"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"NVD check failed: {str(e)}"
            }
    
    def check_file_storage(self) -> Dict[str, Any]:
        import os
        
        try:
            paths = [
                settings.IQ_RECORDINGS_PATH,
                settings.EVIDENCE_FILES_PATH,
                settings.REPORTS_PATH
            ]
            
            all_exist = all(os.path.exists(p) for p in paths)
            
            if all_exist:
                return {
                    "status": "healthy",
                    "message": "All storage directories exist",
                    "paths": {
                        "iq_recordings": settings.IQ_RECORDINGS_PATH,
                        "evidence": settings.EVIDENCE_FILES_PATH,
                        "reports": settings.REPORTS_PATH
                    }
                }
            else:
                return {
                    "status": "degraded",
                    "message": "Some storage directories missing (will be created on demand)",
                    "paths": {p: os.path.exists(p) for p in paths}
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"File storage check failed: {str(e)}"
            }
    
    def run_all_checks(self) -> Dict[str, Any]:
        checks = {
            "database": self.check_database(),
            "sdr_hardware": self.check_sdr_hardware(),
            "hamlib": self.check_hamlib(),
            "gnu_radio": self.check_gnu_radio(),
            "nvd_api": self.check_nvd_api(),
            "file_storage": self.check_file_storage()
        }
        
        overall_status = "healthy"
        
        for check_name, check_result in checks.items():
            if check_result["status"] in ["unhealthy", "error"]:
                overall_status = "unhealthy"
                break
            elif check_result["status"] == "unavailable" and overall_status == "healthy":
                overall_status = "degraded"
        
        return {
            "overall_status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": checks,
            "version": settings.APP_VERSION,
            "app_name": settings.APP_NAME
        }


health_checker = HealthChecker()
