import json
from typing import Dict, Any, List
from datetime import datetime, timezone
from database import SessionLocal
from models import Mission, Evidence, Vulnerability, Report, Playbook, CommandTemplate
import uuid


class DataExporter:
    def __init__(self):
        pass
        
    def export_mission(self, mission_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        
        try:
            mission = db.query(Mission).filter(Mission.id == uuid.UUID(mission_id)).first()
            
            if not mission:
                return {"error": "Mission not found"}
            
            evidence_items = db.query(Evidence).filter(
                Evidence.mission_id == mission.id
            ).all()
            
            reports = db.query(Report).filter(
                Report.mission_id == mission.id
            ).all()
            
            mission_data = {
                "id": str(mission.id),
                "name": mission.name,
                "target_satellite": mission.target_satellite,
                "target_norad_id": mission.target_norad_id,
                "objective": mission.objective,
                "status": mission.status.value,
                "authorization": mission.authorization,
                "attack_chain": mission.attack_chain,
                "next_pass": mission.next_pass,
                "created_at": mission.created_at.isoformat(),
                "started_at": mission.started_at.isoformat() if mission.started_at else None,
                "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
                "evidence": [
                    {
                        "id": str(e.id),
                        "timestamp": e.timestamp.isoformat(),
                        "category": e.category,
                        "description": e.description,
                        "data": e.data,
                        "metadata": e.evidence_metadata,
                        "tags": e.tags,
                        "satellite_name": e.satellite_name,
                        "frequency": e.frequency,
                        "signal_strength": e.signal_strength
                    }
                    for e in evidence_items
                ],
                "reports": [
                    {
                        "id": str(r.id),
                        "format": r.format,
                        "generated_at": r.generated_at.isoformat()
                    }
                    for r in reports
                ]
            }
            
            return mission_data
            
        finally:
            db.close()
    
    def export_all_missions(self) -> List[Dict[str, Any]]:
        db = SessionLocal()
        
        try:
            missions = db.query(Mission).all()
            
            return [
                self.export_mission(str(m.id))
                for m in missions
            ]
            
        finally:
            db.close()
    
    def export_vulnerabilities(self) -> List[Dict[str, Any]]:
        db = SessionLocal()
        
        try:
            vulns = db.query(Vulnerability).all()
            
            return [
                {
                    "id": str(v.id),
                    "cve": v.cve,
                    "satellite_name": v.satellite_name,
                    "norad_id": v.norad_id,
                    "subsystem": v.subsystem,
                    "description": v.description,
                    "exploit_available": v.exploit_available,
                    "exploit_command": v.exploit_command,
                    "mitigation": v.mitigation,
                    "references": v.references,
                    "severity": v.severity.value,
                    "discovered_date": v.discovered_date.isoformat() if v.discovered_date else None,
                    "patch_available": v.patch_available,
                    "cvss_score": v.cvss_score
                }
                for v in vulns
            ]
            
        finally:
            db.close()
    
    def export_playbooks(self) -> List[Dict[str, Any]]:
        db = SessionLocal()
        
        try:
            playbooks = db.query(Playbook).all()
            
            return [
                {
                    "id": str(p.id),
                    "name": p.name,
                    "description": p.description,
                    "objective": p.objective,
                    "difficulty": p.difficulty,
                    "duration": p.duration,
                    "steps": p.steps,
                    "required_tools": p.required_tools,
                    "required_hardware": p.required_hardware,
                    "legal_warnings": p.legal_warnings
                }
                for p in playbooks
            ]
            
        finally:
            db.close()
    
    def export_all_data(self) -> Dict[str, Any]:
        return {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "2.0.0",
            "missions": self.export_all_missions(),
            "vulnerabilities": self.export_vulnerabilities(),
            "playbooks": self.export_playbooks()
        }
    
    def save_to_file(self, filename: str, data: Dict[str, Any]):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


class DataImporter:
    def __init__(self):
        pass
        
    def import_vulnerabilities(self, vulns_data: List[Dict[str, Any]]):
        db = SessionLocal()
        
        try:
            imported_count = 0
            
            for vuln_data in vulns_data:
                existing = db.query(Vulnerability).filter(
                    Vulnerability.cve == vuln_data.get("cve")
                ).first()
                
                if not existing:
                    vuln = Vulnerability(
                        id=uuid.uuid4(),
                        cve=vuln_data.get("cve"),
                        satellite_name=vuln_data.get("satellite_name"),
                        norad_id=vuln_data.get("norad_id"),
                        subsystem=vuln_data.get("subsystem"),
                        description=vuln_data.get("description"),
                        exploit_available=vuln_data.get("exploit_available", False),
                        exploit_command=vuln_data.get("exploit_command"),
                        mitigation=vuln_data.get("mitigation"),
                        references=vuln_data.get("references", []),
                        severity=vuln_data.get("severity", "medium"),
                        patch_available=vuln_data.get("patch_available", False),
                        cvss_score=vuln_data.get("cvss_score", 0.0)
                    )
                    
                    db.add(vuln)
                    imported_count += 1
            
            db.commit()
            
            return {"imported": imported_count}
            
        finally:
            db.close()
    
    def import_playbooks(self, playbooks_data: List[Dict[str, Any]]):
        db = SessionLocal()
        
        try:
            imported_count = 0
            
            for playbook_data in playbooks_data:
                existing = db.query(Playbook).filter(
                    Playbook.name == playbook_data.get("name")
                ).first()
                
                if not existing:
                    playbook = Playbook(
                        id=uuid.uuid4(),
                        name=playbook_data.get("name"),
                        description=playbook_data.get("description"),
                        objective=playbook_data.get("objective"),
                        difficulty=playbook_data.get("difficulty"),
                        duration=playbook_data.get("duration"),
                        steps=playbook_data.get("steps", []),
                        required_tools=playbook_data.get("required_tools", []),
                        required_hardware=playbook_data.get("required_hardware", []),
                        legal_warnings=playbook_data.get("legal_warnings", [])
                    )
                    
                    db.add(playbook)
                    imported_count += 1
            
            db.commit()
            
            return {"imported": imported_count}
            
        finally:
            db.close()
    
    def load_from_file(self, filename: str) -> Dict[str, Any]:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)


data_exporter = DataExporter()
data_importer = DataImporter()
