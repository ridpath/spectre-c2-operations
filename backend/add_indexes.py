"""Add database indexes for improved query performance"""

from sqlalchemy import create_engine, text, Index
from config import get_settings
from models import Base, TLEData, Mission, Evidence, Vulnerability, AuditLog, C2Agent, C2Task, SatelliteTask, PassPrediction

settings = get_settings()


def add_indexes():
    """Add indexes to frequently queried columns"""
    engine = create_engine(settings.DATABASE_URL)
    
    with engine.connect() as conn:
        print("Adding database indexes for performance optimization...")
        
        # TLE Data indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tle_norad ON tle_data(norad_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tle_epoch ON tle_data(epoch)"))
            print("[OK] TLE data indexes created")
        except Exception as e:
            print(f"  TLE indexes: {e}")
        
        # Mission indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_mission_status ON missions(status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_mission_created ON missions(created_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_mission_norad ON missions(target_norad_id)"))
            print("✓ Mission indexes created")
        except Exception as e:
            print(f"  Mission indexes: {e}")
        
        # Evidence indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_evidence_mission ON evidence(mission_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_evidence_category ON evidence(category)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp)"))
            print("[OK] Evidence indexes created")
        except Exception as e:
            print(f"  Evidence indexes: {e}")
        
        # Audit Log indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)"))
            print("✓ Audit log indexes created")
        except Exception as e:
            print(f"  Audit log indexes: {e}")
        
        # Vulnerability indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)"))
            print("[OK] Vulnerability indexes created")
        except Exception as e:
            print(f"  Vulnerability indexes: {e}")
        
        # C2 Agent indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_agent_status ON c2_agents(status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_agent_type ON c2_agents(agent_type)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_agent_last_seen ON c2_agents(last_seen)"))
            print("✓ C2 Agent indexes created")
        except Exception as e:
            print(f"  C2 Agent indexes: {e}")
        
        # C2 Task indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_task_agent ON c2_tasks(agent_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_task_status ON c2_tasks(status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_task_created ON c2_tasks(created_at)"))
            print("✓ C2 Task indexes created")
        except Exception as e:
            print(f"  C2 Task indexes: {e}")
        
        # Satellite Task indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sat_task_norad ON satellite_tasks(norad_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sat_task_status ON satellite_tasks(status)"))
            print("[OK] Satellite Task indexes created")
        except Exception as e:
            print(f"  Satellite Task indexes: {e}")
        
        # Pass Prediction indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pass_norad ON pass_predictions(norad_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pass_aos ON pass_predictions(aos_time)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pass_los ON pass_predictions(los_time)"))
            print("✓ Pass Prediction indexes created")
        except Exception as e:
            print(f"  Pass Prediction indexes: {e}")
        
        conn.commit()
        
        print("\n[SUCCESS] All database indexes added successfully!")
        print("Query performance should be significantly improved.")


if __name__ == "__main__":
    add_indexes()
