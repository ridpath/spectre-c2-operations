from typing import Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy import func
from database import SessionLocal
from models import Mission, Evidence, Vulnerability, Report, User, IQRecording, AuditLog, MissionStatus


class StatisticsCollector:
    def __init__(self):
        pass
        
    def get_mission_statistics(self, db) -> Dict[str, Any]:
        total_missions = db.query(Mission).count()
        
        active_missions = db.query(Mission).filter(
            Mission.status == MissionStatus.ACTIVE
        ).count()
        
        completed_missions = db.query(Mission).filter(
            Mission.status == MissionStatus.COMPLETED
        ).count()
        
        recent_missions = db.query(Mission).filter(
            Mission.created_at >= datetime.now(timezone.utc) - timedelta(days=7)
        ).count()
        
        missions_by_status = {}
        for status in MissionStatus:
            count = db.query(Mission).filter(Mission.status == status).count()
            missions_by_status[status.value] = count
        
        return {
            "total": total_missions,
            "active": active_missions,
            "completed": completed_missions,
            "recent_7_days": recent_missions,
            "by_status": missions_by_status
        }
    
    def get_evidence_statistics(self, db) -> Dict[str, Any]:
        total_evidence = db.query(Evidence).count()
        
        evidence_by_category = db.query(
            Evidence.category,
            func.count(Evidence.id)
        ).group_by(Evidence.category).all()
        
        total_file_size = db.query(
            func.sum(Evidence.file_size)
        ).scalar() or 0
        
        recent_evidence = db.query(Evidence).filter(
            Evidence.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
        ).count()
        
        return {
            "total": total_evidence,
            "recent_7_days": recent_evidence,
            "by_category": {cat: count for cat, count in evidence_by_category},
            "total_file_size_bytes": total_file_size,
            "total_file_size_mb": round(total_file_size / (1024 * 1024), 2)
        }
    
    def get_vulnerability_statistics(self, db) -> Dict[str, Any]:
        total_vulns = db.query(Vulnerability).count()
        
        exploitable_vulns = db.query(Vulnerability).filter(
            Vulnerability.exploit_available == True
        ).count()
        
        vulns_by_severity = db.query(
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).group_by(Vulnerability.severity).all()
        
        critical_vulns = db.query(Vulnerability).filter(
            Vulnerability.cvss_score >= 9.0
        ).count()
        
        return {
            "total": total_vulns,
            "exploitable": exploitable_vulns,
            "critical_cvss": critical_vulns,
            "by_severity": {sev.value: count for sev, count in vulns_by_severity}
        }
    
    def get_iq_recording_statistics(self, db) -> Dict[str, Any]:
        total_recordings = db.query(IQRecording).count()
        
        total_size = db.query(
            func.sum(IQRecording.file_size)
        ).scalar() or 0
        
        recent_recordings = db.query(IQRecording).filter(
            IQRecording.recorded_at >= datetime.now(timezone.utc) - timedelta(days=7)
        ).count()
        
        recordings_by_satellite = db.query(
            IQRecording.satellite_name,
            func.count(IQRecording.id)
        ).group_by(IQRecording.satellite_name).all()
        
        return {
            "total": total_recordings,
            "recent_7_days": recent_recordings,
            "total_file_size_bytes": total_size,
            "total_file_size_gb": round(total_size / (1024 * 1024 * 1024), 2),
            "by_satellite": {sat: count for sat, count in recordings_by_satellite if sat}
        }
    
    def get_user_statistics(self, db) -> Dict[str, Any]:
        total_users = db.query(User).count()
        
        active_users = db.query(User).filter(User.is_active == True).count()
        
        users_by_role = db.query(
            User.role,
            func.count(User.id)
        ).group_by(User.role).all()
        
        recent_logins = db.query(User).filter(
            User.last_login >= datetime.now(timezone.utc) - timedelta(days=7)
        ).count()
        
        return {
            "total": total_users,
            "active": active_users,
            "recent_logins_7_days": recent_logins,
            "by_role": {role.value: count for role, count in users_by_role}
        }
    
    def get_audit_statistics(self, db) -> Dict[str, Any]:
        total_events = db.query(AuditLog).count()
        
        recent_events = db.query(AuditLog).filter(
            AuditLog.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
        ).count()
        
        events_by_action = db.query(
            AuditLog.action,
            func.count(AuditLog.id)
        ).group_by(AuditLog.action).limit(10).all()
        
        return {
            "total": total_events,
            "recent_7_days": recent_events,
            "top_actions": {action: count for action, count in events_by_action}
        }
    
    def get_report_statistics(self, db) -> Dict[str, Any]:
        total_reports = db.query(Report).count()
        
        recent_reports = db.query(Report).filter(
            Report.generated_at >= datetime.now(timezone.utc) - timedelta(days=7)
        ).count()
        
        reports_by_format = db.query(
            Report.format,
            func.count(Report.id)
        ).group_by(Report.format).all()
        
        return {
            "total": total_reports,
            "recent_7_days": recent_reports,
            "by_format": {fmt: count for fmt, count in reports_by_format}
        }
    
    def get_all_statistics(self) -> Dict[str, Any]:
        db = SessionLocal()
        
        try:
            stats = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "missions": self.get_mission_statistics(db),
                "evidence": self.get_evidence_statistics(db),
                "vulnerabilities": self.get_vulnerability_statistics(db),
                "iq_recordings": self.get_iq_recording_statistics(db),
                "users": self.get_user_statistics(db),
                "audit_logs": self.get_audit_statistics(db),
                "reports": self.get_report_statistics(db)
            }
            
            return stats
            
        finally:
            db.close()


stats_collector = StatisticsCollector()
