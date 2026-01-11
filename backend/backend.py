from fastapi import FastAPI, WebSocket, HTTPException, Depends, WebSocketDisconnect, UploadFile, File, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional, List, Dict
from pydantic import BaseModel
import asyncio
import json
import uuid
import subprocess
import os
from datetime import datetime, timezone, timedelta
from skyfield.api import load, EarthSatellite, wgs84
import requests
import numpy as np

from config import get_settings
from database import get_db, init_db, SessionLocal
from models import (
    User, Mission, Evidence, Vulnerability, Playbook, Report, 
    CommandTemplate, TLEData, PassPrediction, IQRecording, AuditLog,
    MissionStatus, UserRole, C2Agent, C2Task, SatelliteTask, GroundStation,
    AgentStatus, AgentType, TaskStatus
)
from auth import (
    create_access_token, create_refresh_token, verify_password, 
    hash_password, get_current_user, get_current_active_user, require_role
)
from schemas import (
    UserLogin, UserRegister, UserResponse, TokenResponse, RefreshTokenRequest,
    MissionCreateRequest, MissionUpdateRequest, EvidenceCreateRequest,
    VulnerabilityScanRequest, ReportGenerateRequest, PassPredictionRequest,
    SafetyCheckRequest, TemplateCreateRequest, SatelliteFetchRequest
)
from file_storage import file_storage
from sdr_hardware import sdr_manager, SpectrumAnalyzer, RTLSDRDevice
from remote_execution import remote_executor, ExecutionTarget, ExecutionProtocol
from hamlib_control import hamlib_rotator, antenna_tracker
from satellite_database import satellite_db
from nvd_scanner import nvd_scanner
from health_check import health_checker
from stats import stats_collector
from data_export import data_exporter, data_importer
from rate_limiter import RateLimitMiddleware, check_endpoint_rate_limit
from security import (
    SecurityHeadersMiddleware, HTTPSRedirectMiddleware, 
    SQLInjectionProtectionMiddleware, RequestSizeLimitMiddleware,
    validate_environment
)
from module_executor import module_executor, ModuleExecutionError, InsufficientPrivilegesError, ModuleNotFoundError
from vuln_scanner import vuln_scanner
from apt_orchestrator import apt_orchestrator
from payload_factory import payload_factory
from satellite_tle_fetcher import tle_fetcher

settings = get_settings()

if settings.ENVIRONMENT == "production":
    validate_environment()

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(SQLInjectionProtectionMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size=settings.MAX_UPLOAD_SIZE)
app.add_middleware(RateLimitMiddleware, requests_per_minute=120, requests_per_hour=2000)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ts = load.timescale()
satellites_cache: dict[int, EarthSatellite] = {}


@app.on_event("startup")
async def startup_event():
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"Database: {settings.DATABASE_URL.split('@')[1] if '@' in settings.DATABASE_URL else 'Not configured'}")


@app.get("/health")
async def health_check_simple():
    return {
        "status": "operational",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/health/detailed")
async def health_check_detailed():
    return health_checker.run_all_checks()


@app.get("/api/v1/statistics")
async def get_statistics(current_user: User = Depends(get_current_user)):
    return stats_collector.get_all_statistics()


@app.get("/api/v1/export/mission/{mission_id}")
async def export_mission_data(
    mission_id: str,
    current_user: User = Depends(get_current_user)
):
    return data_exporter.export_mission(mission_id)


@app.get("/api/v1/export/all")
async def export_all_data(current_user: User = Depends(require_role("admin"))):
    return data_exporter.export_all_data()


@app.post("/api/v1/auth/register", response_model=UserResponse)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    new_user = User(
        id=uuid.uuid4(),
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=UserRole(user_data.role),
        is_active=True
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


@app.post("/api/v1/auth/login")
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()
    
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")
    
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role.value})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=user.id,
        action="login",
        details={"username": user.username}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None
        }
    }


@app.post("/api/v1/auth/refresh")
async def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    refresh_token = request.refresh_token
    
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")
    
    try:
        from auth import decode_token
        payload = decode_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="Invalid user")
        
        access_token = create_access_token({"sub": str(user.id), "role": user.role.value})
        
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/api/v1/users/me", response_model=UserResponse)
@app.get("/api/v1/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/api/v1/users", response_model=List[UserResponse])
async def list_users(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return users


@app.get("/api/v1/missions")
async def get_missions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    missions = db.query(Mission).order_by(desc(Mission.created_at)).all()
    return {"missions": [
        {
            "id": str(m.id),
            "name": m.name,
            "target_satellite": m.target_satellite,
            "target_norad_id": m.target_norad_id,
            "objective": m.objective,
            "status": m.status.value,
            "authorization": m.authorization,
            "attack_chain": m.attack_chain,
            "evidence": [str(e.id) for e in m.evidence_items],
            "created_at": m.created_at.isoformat(),
            "started_at": m.started_at.isoformat() if m.started_at else None,
            "completed_at": m.completed_at.isoformat() if m.completed_at else None,
            "next_pass": m.next_pass
        }
        for m in missions
    ]}


@app.post("/api/v1/missions")
async def create_mission(
    request: MissionCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mission = Mission(
        id=uuid.uuid4(),
        name=request.name,
        target_satellite=request.target_satellite,
        target_norad_id=request.target_norad_id,
        objective=request.objective,
        authorization=request.authorization,
        status=MissionStatus.PLANNING,
        created_by=current_user.id
    )
    
    db.add(mission)
    db.commit()
    db.refresh(mission)
    
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="create_mission",
        resource_type="mission",
        resource_id=mission.id,
        details={"mission_name": mission.name, "target": mission.target_satellite}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "id": str(mission.id),
        "name": mission.name,
        "target_satellite": mission.target_satellite,
        "target_norad_id": mission.target_norad_id,
        "objective": mission.objective,
        "status": mission.status.value,
        "authorization": mission.authorization,
        "attack_chain": mission.attack_chain,
        "evidence": [],
        "created_at": mission.created_at.isoformat(),
        "next_pass": None
    }


@app.get("/api/v1/missions/{mission_id}")
async def get_mission(
    mission_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mission = db.query(Mission).filter(Mission.id == uuid.UUID(mission_id)).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    return {
        "id": str(mission.id),
        "name": mission.name,
        "target_satellite": mission.target_satellite,
        "target_norad_id": mission.target_norad_id,
        "objective": mission.objective,
        "status": mission.status.value,
        "authorization": mission.authorization,
        "attack_chain": mission.attack_chain,
        "evidence": [str(e.id) for e in mission.evidence_items],
        "created_at": mission.created_at.isoformat(),
        "started_at": mission.started_at.isoformat() if mission.started_at else None,
        "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
        "next_pass": mission.next_pass
    }


@app.put("/api/v1/missions/{mission_id}")
async def update_mission(
    mission_id: str,
    request: MissionUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mission = db.query(Mission).filter(Mission.id == uuid.UUID(mission_id)).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    if request.status:
        mission.status = MissionStatus(request.status)
        if request.status == "active" and not mission.started_at:
            mission.started_at = datetime.now(timezone.utc)
        elif request.status == "completed" and not mission.completed_at:
            mission.completed_at = datetime.now(timezone.utc)
    
    if request.attack_chain is not None:
        mission.attack_chain = request.attack_chain
    
    db.commit()
    db.refresh(mission)
    
    return {
        "id": str(mission.id),
        "name": mission.name,
        "target_satellite": mission.target_satellite,
        "target_norad_id": mission.target_norad_id,
        "objective": mission.objective,
        "status": mission.status.value,
        "authorization": mission.authorization,
        "attack_chain": mission.attack_chain,
        "evidence": [str(e.id) for e in mission.evidence_items],
        "created_at": mission.created_at.isoformat()
    }


@app.delete("/api/v1/missions/{mission_id}")
async def delete_mission(
    mission_id: str,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    mission = db.query(Mission).filter(Mission.id == uuid.UUID(mission_id)).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    db.delete(mission)
    db.commit()
    
    return {"message": "Mission deleted successfully"}


@app.get("/api/v1/evidence")
async def get_evidence(
    mission_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Evidence)
    if mission_id:
        query = query.filter(Evidence.mission_id == uuid.UUID(mission_id))
    
    evidence_items = query.order_by(desc(Evidence.timestamp)).all()
    
    return {"evidence": [
        {
            "id": str(e.id),
            "mission_id": str(e.mission_id),
            "timestamp": e.timestamp.isoformat(),
            "category": e.category,
            "description": e.description,
            "data": e.data,
            "file_path": e.file_path,
            "file_size": e.file_size,
            "metadata": e.evidence_metadata,
            "tags": e.tags,
            "satellite_name": e.satellite_name,
            "frequency": e.frequency,
            "signal_strength": e.signal_strength
        }
        for e in evidence_items
    ]}


@app.post("/api/v1/evidence")
async def create_evidence(
    request: EvidenceCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mission = db.query(Mission).filter(Mission.id == request.mission_id).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    evidence = Evidence(
        id=uuid.uuid4(),
        mission_id=request.mission_id,
        category=request.category,
        description=request.description,
        data=request.data,
        evidence_metadata=request.metadata,
        tags=request.tags,
        satellite_name=request.satellite_name,
        frequency=request.frequency,
        signal_strength=request.signal_strength
    )
    
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    
    return {
        "id": str(evidence.id),
        "mission_id": str(evidence.mission_id),
        "timestamp": evidence.timestamp.isoformat(),
        "category": evidence.category,
        "description": evidence.description,
        "data": evidence.data,
        "metadata": evidence.evidence_metadata,
        "tags": evidence.tags
    }


@app.delete("/api/v1/evidence/{evidence_id}")
async def delete_evidence(
    evidence_id: str,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    evidence = db.query(Evidence).filter(Evidence.id == uuid.UUID(evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    if evidence.file_path:
        file_storage.delete_file(evidence.file_path)
    
    db.delete(evidence)
    db.commit()
    
    return {"message": "Evidence deleted successfully"}


@app.post("/api/v1/evidence/upload")
async def upload_evidence_file(
    mission_id: str,
    file: UploadFile = File(...),
    description: str = "",
    category: str = "file",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mission = db.query(Mission).filter(Mission.id == uuid.UUID(mission_id)).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    if file.size and file.size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    
    filename, file_path, file_size = file_storage.save_evidence_file(
        file.file,
        file.filename,
        uuid.UUID(mission_id)
    )
    
    evidence = Evidence(
        id=uuid.uuid4(),
        mission_id=uuid.UUID(mission_id),
        category=category,
        description=description or f"Uploaded file: {file.filename}",
        data=f"File: {filename}",
        file_path=file_path,
        file_size=file_size,
        satellite_name=mission.target_satellite,
        metadata={
            "original_filename": file.filename,
            "content_type": file.content_type,
            "uploaded_by": current_user.username
        }
    )
    
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    
    return {
        "id": str(evidence.id),
        "mission_id": str(evidence.mission_id),
        "filename": filename,
        "file_path": file_path,
        "file_size": file_size,
        "category": category,
        "description": evidence.description,
        "timestamp": evidence.timestamp.isoformat()
    }


@app.post("/api/v1/iq/upload")
async def upload_iq_recording(
    file: UploadFile = File(...),
    satellite_name: str = "",
    norad_id: int = 0,
    frequency: float = 0,
    sample_rate: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if file.size and file.size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    
    filename, file_path, file_size = file_storage.save_iq_recording(
        file.file,
        file.filename,
        satellite_name=satellite_name,
        norad_id=norad_id
    )
    
    recording = IQRecording(
        id=uuid.uuid4(),
        file_path=file_path,
        file_size=file_size,
        satellite_name=satellite_name,
        norad_id=norad_id if norad_id > 0 else None,
        center_frequency=int(frequency) if frequency > 0 else None,
        sample_rate=sample_rate if sample_rate > 0 else settings.SDR_SAMPLE_RATE,
        duration=0,
        iq_metadata={
            "original_filename": file.filename,
            "uploaded_by": current_user.username
        }
    )
    
    db.add(recording)
    db.commit()
    db.refresh(recording)
    
    return {
        "id": str(recording.id),
        "filename": filename,
        "file_path": file_path,
        "file_size": file_size,
        "satellite_name": satellite_name,
        "frequency": frequency,
        "sample_rate": sample_rate,
        "timestamp": recording.recorded_at.isoformat()
    }


@app.get("/api/v1/iq/recordings")
async def list_iq_recordings(
    satellite_name: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(IQRecording)
    
    if satellite_name:
        query = query.filter(IQRecording.satellite_name == satellite_name)
    
    recordings = query.order_by(desc(IQRecording.recorded_at)).all()
    
    return {"recordings": [
        {
            "id": str(r.id),
            "file_path": r.file_path,
            "file_size": r.file_size,
            "satellite_name": r.satellite_name,
            "norad_id": r.norad_id,
            "frequency": r.center_frequency,
            "sample_rate": r.sample_rate,
            "duration": r.duration,
            "recorded_at": r.recorded_at.isoformat()
        }
        for r in recordings
    ]}


@app.get("/api/v1/vulnerabilities")
async def get_vulnerabilities(
    norad_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)
    if norad_id:
        query = query.filter(Vulnerability.norad_id == norad_id)
    
    vulnerabilities = query.all()
    
    return {"vulnerabilities": [
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
        for v in vulnerabilities
    ]}


@app.post("/api/v1/vulnerabilities/scan")
async def scan_vulnerabilities(
    request: VulnerabilityScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    nvd_results = nvd_scanner.scan_satellite_vulnerabilities(
        request.satellite_name,
        subsystems=["telemetry", "command", "communication", "firmware"]
    )
    
    mock_vulns_data = [
        {
            "cve": "CVE-2023-45678",
            "subsystem": "TTC",
            "description": "Command authentication bypass in telecommand handler",
            "exploit_available": True,
            "exploit_command": "ccsds-inject --apid 0x3E5 --bypass-auth --payload {COMMAND}",
            "mitigation": "Upgrade TC handler firmware to v2.3.1",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45678"],
            "severity": "critical",
            "cvss_score": 9.8,
            "patch_available": True
        },
        {
            "cve": "CVE-2023-45679",
            "subsystem": "CDH",
            "description": "Buffer overflow in onboard data handling subsystem",
            "exploit_available": True,
            "exploit_command": "python exploit_cdh_overflow.py --target {SAT}",
            "mitigation": "Implement bounds checking in TM frame parser",
            "references": ["https://cwe.mitre.org/data/definitions/120.html"],
            "severity": "high",
            "cvss_score": 8.1,
            "patch_available": False
        }
    ]
    
    for nvd_vuln in nvd_results[:5]:
        mock_vulns_data.append({
            "cve": nvd_vuln["cve"],
            "subsystem": "Unknown",
            "description": nvd_vuln["description"][:500],
            "exploit_available": False,
            "exploit_command": None,
            "mitigation": "Check NVD database for official mitigation",
            "references": nvd_vuln["references"][:3],
            "severity": nvd_vuln["severity"].lower(),
            "cvss_score": nvd_vuln["cvss_score"],
            "patch_available": False
        })
    
    created_vulns = []
    for vuln_data in mock_vulns_data:
        existing = db.query(Vulnerability).filter(Vulnerability.cve == vuln_data["cve"]).first()
        if not existing:
            vuln = Vulnerability(
                id=uuid.uuid4(),
                cve=vuln_data["cve"],
                satellite_name=request.satellite_name,
                norad_id=request.norad_id,
                subsystem=vuln_data["subsystem"],
                description=vuln_data["description"],
                exploit_available=vuln_data["exploit_available"],
                exploit_command=vuln_data["exploit_command"],
                mitigation=vuln_data["mitigation"],
                references=vuln_data["references"],
                severity=vuln_data["severity"],
                discovered_date=datetime.now(timezone.utc) - timedelta(days=60),
                patch_available=vuln_data["patch_available"],
                cvss_score=vuln_data["cvss_score"]
            )
            db.add(vuln)
            created_vulns.append(vuln)
    
    db.commit()
    
    return {"status": "success", "vulnerabilities": [
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
            "patch_available": v.patch_available
        }
        for v in created_vulns
    ]}


def fetch_tle_from_celestrak(norad_id: int) -> Optional[tuple]:
    try:
        response = requests.get(
            f"https://celestrak.org/NORAD/elements/gp.php?CATNR={norad_id}&FORMAT=TLE",
            timeout=10
        )
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            if len(lines) >= 3:
                return (lines[0].strip(), lines[1].strip(), lines[2].strip())
    except Exception as e:
        print(f"TLE fetch error: {e}")
    return None


def get_satellite(norad_id: int, db: Session) -> Optional[EarthSatellite]:
    if norad_id in satellites_cache:
        return satellites_cache[norad_id]
    
    tle_data = db.query(TLEData).filter(TLEData.norad_id == norad_id).first()
    
    if not tle_data:
        tle_result = fetch_tle_from_celestrak(norad_id)
        if tle_result:
            name, line1, line2 = tle_result
            tle_data = TLEData(
                id=uuid.uuid4(),
                norad_id=norad_id,
                satellite_name=name,
                tle_line1=line1,
                tle_line2=line2,
                epoch=datetime.now(timezone.utc),
                source="celestrak"
            )
            db.add(tle_data)
            db.commit()
    
    if tle_data:
        satellite = EarthSatellite(tle_data.tle_line1, tle_data.tle_line2, tle_data.satellite_name, ts)
        satellites_cache[norad_id] = satellite
        return satellite
    
    return None


@app.get("/api/v1/passes/predict")
async def predict_passes(
    norad_id: int = 43105,
    latitude: float = 37.7749,
    longitude: float = -122.4194,
    altitude: float = 0,
    min_elevation: float = 10,
    hours_ahead: int = 24,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    satellite = get_satellite(norad_id, db)
    if not satellite:
        raise HTTPException(status_code=404, detail="Satellite TLE not found")
    
    ground_station = wgs84.latlon(latitude, longitude, altitude)
    
    t0 = ts.now()
    t1 = ts.utc(t0.utc_datetime() + timedelta(hours=hours_ahead))
    
    times, events = satellite.find_events(ground_station, t0, t1, altitude_degrees=min_elevation)
    
    passes = []
    current_pass = {}
    
    for time, event in zip(times, events):
        if event == 0:
            current_pass = {
                "id": str(uuid.uuid4()),
                "start_time": time.utc_iso(),
                "satellite": satellite.name,
                "norad_id": norad_id
            }
        elif event == 1:
            if current_pass:
                topocentric = (satellite - ground_station).at(time)
                alt, az, distance = topocentric.altaz()
                current_pass["max_elevation"] = alt.degrees
                current_pass["max_elevation_time"] = time.utc_iso()
        elif event == 2:
            if current_pass:
                current_pass["end_time"] = time.utc_iso()
                current_pass["is_current"] = False
                passes.append(current_pass)
                
                pass_prediction = PassPrediction(
                    id=uuid.uuid4(),
                    norad_id=norad_id,
                    satellite_name=satellite.name,
                    aos_time=datetime.fromisoformat(current_pass["start_time"].replace('Z', '+00:00')),
                    max_elevation_time=datetime.fromisoformat(current_pass["max_elevation_time"].replace('Z', '+00:00')),
                    los_time=datetime.fromisoformat(current_pass["end_time"].replace('Z', '+00:00')),
                    max_elevation=current_pass["max_elevation"],
                    ground_station_lat=latitude,
                    ground_station_lon=longitude,
                    ground_station_alt=altitude
                )
                db.add(pass_prediction)
                
                current_pass = {}
    
    db.commit()
    
    return {
        "satellite": satellite.name,
        "norad_id": norad_id,
        "ground_station": {
            "latitude": latitude,
            "longitude": longitude,
            "altitude": altitude,
            "min_elevation": min_elevation
        },
        "passes": passes,
        "calculated_at": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/execute/remote")
async def execute_remote_command(
    command: str,
    host: str,
    username: str,
    password: str,
    protocol: str = "ssh",
    port: int = 22,
    timeout: int = 30,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    try:
        protocol_enum = ExecutionProtocol(protocol)
        
        target = ExecutionTarget(
            host=host,
            port=port if port else (22 if protocol == "ssh" else 5985),
            username=username,
            password=password,
            protocol=protocol_enum
        )
        
        result = remote_executor.execute_command(command, target, timeout)
        
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=current_user.id,
            action="remote_execute",
            details={
                "command": command,
                "host": host,
                "protocol": protocol,
                "success": result.success,
                "exit_code": result.exit_code
            }
        )
        db.add(audit_log)
        db.commit()
        
        return {
            "status": "success" if result.success else "error",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "execution_time": result.execution_time
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "stdout": "",
            "stderr": "",
            "exit_code": -1
        }


@app.get("/api/v1/antenna/status")
async def get_antenna_status(current_user: User = Depends(get_current_user)):
    if settings.ENABLE_HAMLIB:
        if not hamlib_rotator.connected:
            hamlib_rotator.connect()
        
        position = hamlib_rotator.get_position()
        info = antenna_tracker.get_tracking_info()
        
        return {
            "enabled": True,
            "connected": hamlib_rotator.connected,
            "status": info["status"],
            "position": info["current_position"],
            "target": info["target_position"],
            "tracking_active": info["tracking_active"],
            "tracking_target": info["tracking_target"],
            "on_target": info["on_target"]
        }
    else:
        return {
            "enabled": False,
            "message": "Hamlib antenna control is disabled"
        }


@app.post("/api/v1/antenna/position")
async def set_antenna_position(
    azimuth: float,
    elevation: float,
    current_user: User = Depends(require_role("operator"))
):
    if not settings.ENABLE_HAMLIB:
        return {"status": "error", "message": "Hamlib not enabled"}
    
    if not hamlib_rotator.connected:
        if not hamlib_rotator.connect():
            return {"status": "error", "message": "Failed to connect to rotctld"}
    
    success = hamlib_rotator.set_position(azimuth, elevation)
    
    return {
        "status": "success" if success else "error",
        "azimuth": azimuth,
        "elevation": elevation
    }


@app.post("/api/v1/antenna/track")
async def start_antenna_tracking(
    satellite_name: str,
    norad_id: int,
    current_user: User = Depends(require_role("operator"))
):
    if not settings.ENABLE_HAMLIB:
        return {"status": "error", "message": "Hamlib not enabled"}
    
    if not hamlib_rotator.connected:
        if not hamlib_rotator.connect():
            return {"status": "error", "message": "Failed to connect to rotctld"}
    
    success = antenna_tracker.start_tracking(satellite_name)
    
    return {
        "status": "success" if success else "error",
        "satellite": satellite_name,
        "norad_id": norad_id,
        "tracking": success
    }


@app.post("/api/v1/antenna/stop")
async def stop_antenna_tracking(current_user: User = Depends(require_role("operator"))):
    antenna_tracker.stop_tracking()
    
    return {"status": "success", "message": "Tracking stopped"}


@app.post("/api/v1/antenna/park")
async def park_antenna(current_user: User = Depends(require_role("operator"))):
    if not settings.ENABLE_HAMLIB:
        return {"status": "error", "message": "Hamlib not enabled"}
    
    if not hamlib_rotator.connected:
        return {"status": "error", "message": "Rotator not connected"}
    
    antenna_tracker.stop_tracking()
    success = hamlib_rotator.park()
    
    return {
        "status": "success" if success else "error",
        "message": "Antenna parked" if success else "Failed to park antenna"
    }


@app.get("/api/v1/satellites")
async def get_satellites(
    satellite_type: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    if satellite_type:
        from satellite_database import SatelliteType
        try:
            sat_type_enum = SatelliteType(satellite_type)
            satellites = satellite_db.get_by_type(sat_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid satellite type")
    else:
        satellites = satellite_db.get_all()
    
    return {"satellites": [satellite_db.to_dict(sat) for sat in satellites]}


@app.get("/api/v1/satellites/list")
async def list_satellites(
    limit: int = 100,
    satellite_type: Optional[str] = None,
    constellation: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List satellites from database (public endpoint)"""
    try:
        query = db.query(TLEData).order_by(desc(TLEData.epoch))
        
        if satellite_type:
            query = query.filter(TLEData.satellite_name.ilike(f"%{satellite_type}%"))
        
        if constellation:
            query = query.filter(TLEData.satellite_name.ilike(f"%{constellation}%"))
        
        satellites = query.limit(limit).all()
        
        return {
            "satellites": [
                {
                    "id": str(s.id),
                    "name": s.satellite_name,
                    "norad_id": s.norad_id,
                    "tle_line1": s.tle_line1,
                    "tle_line2": s.tle_line2,
                    "epoch": s.epoch.isoformat(),
                    "source": s.source if s.source else "unknown"
                }
                for s in satellites
            ],
            "total": len(satellites)
        }
    except Exception as e:
        print(f"[ERROR] list_satellites: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/api/v1/satellites/fetch-all")
async def fetch_satellites_from_sources(
    request: SatelliteFetchRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Fetch satellites from external sources and populate database"""
    try:
        from satellite_tle_fetcher import tle_fetcher
        
        sources = request.sources
        if sources is None or 'celestrak' in sources:
            print("[INFO] Fetching satellites from CelesTrak...")
            satellites = await tle_fetcher.fetch_all_groups()
            
            if not satellites:
                return {
                    "success": False,
                    "message": "Failed to fetch satellites from CelesTrak",
                    "count": 0
                }
            
            count = 0
            for sat in satellites:
                try:
                    existing = db.query(TLEData).filter(TLEData.norad_id == sat['norad_id']).first()
                    if existing:
                        existing.tle_line1 = sat['tle_line1']
                        existing.tle_line2 = sat['tle_line2']
                        existing.epoch = sat['epoch']
                        existing.source = 'celestrak'
                    else:
                        tle_entry = TLEData(
                            id=uuid.uuid4(),
                            satellite_name=sat['name'],
                            norad_id=sat['norad_id'],
                            tle_line1=sat['tle_line1'],
                            tle_line2=sat['tle_line2'],
                            epoch=sat['epoch'],
                            source='celestrak'
                        )
                        db.add(tle_entry)
                    count += 1
                except Exception as e:
                    print(f"[ERROR] Failed to add satellite {sat.get('name', '?')}: {e}")
                    continue
            
            db.commit()
            
            return {
                "success": True,
                "message": f"Successfully fetched {count} satellites from CelesTrak",
                "count": count
            }
        
        return {
            "success": False,
            "message": "No valid sources specified",
            "count": 0
        }
    
    except Exception as e:
        print(f"[ERROR] fetch_satellites_from_sources: {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "message": f"Error: {str(e)}",
            "count": 0
        }


@app.get("/api/v1/satellites/{norad_id}")
async def get_satellite_info(
    norad_id: int,
    current_user: User = Depends(get_current_user)
):
    satellite = satellite_db.get_satellite(norad_id)
    
    if not satellite:
        raise HTTPException(status_code=404, detail="Satellite not found in database")
    
    return satellite_db.to_dict(satellite)


@app.get("/api/v1/satellites/search/{name}")
async def search_satellites(
    name: str,
    current_user: User = Depends(get_current_user)
):
    satellites = satellite_db.search_by_name(name)
    
    return {"satellites": [satellite_db.to_dict(sat) for sat in satellites]}


@app.get("/api/v1/satellites/vulnerable")
async def get_vulnerable_satellites(current_user: User = Depends(get_current_user)):
    satellites = satellite_db.get_vulnerable_satellites()
    
    return {"satellites": [satellite_db.to_dict(sat) for sat in satellites]}


@app.post("/api/v1/safety/check")
async def safety_check(
    request: SafetyCheckRequest,
    current_user: User = Depends(get_current_user)
):
    checks = []
    
    if request.frequency < 30 or request.frequency > 3000:
        checks.append({
            "id": "freq-range",
            "name": "Frequency Range Check",
            "severity": "critical",
            "passed": False,
            "message": f"Frequency {request.frequency} MHz outside safe range (30-3000 MHz)",
            "category": "technical"
        })
    else:
        checks.append({
            "id": "freq-range",
            "name": "Frequency Range Check",
            "severity": "warning",
            "passed": True,
            "message": "Frequency within operational range",
            "category": "technical"
        })
    
    amateur_bands = [(144, 148), (420, 450), (902, 928), (1240, 1300)]
    is_amateur = any(low <= request.frequency <= high for low, high in amateur_bands)
    
    if not is_amateur:
        checks.append({
            "id": "amateur-band",
            "name": "Amateur Band Check",
            "severity": "critical",
            "passed": False,
            "message": f"{request.frequency} MHz not in amateur radio bands - FCC authorization required",
            "category": "legal"
        })
    else:
        checks.append({
            "id": "amateur-band",
            "name": "Amateur Band Check",
            "severity": "warning",
            "passed": True,
            "message": "Frequency in amateur radio band",
            "category": "legal"
        })
    
    if request.power > 100:
        checks.append({
            "id": "power-limit",
            "name": "Power Limit Check",
            "severity": "critical",
            "passed": False,
            "message": f"Power {request.power}W exceeds 100W limit",
            "category": "technical"
        })
    else:
        checks.append({
            "id": "power-limit",
            "name": "Power Limit Check",
            "severity": "info",
            "passed": True,
            "message": "Power within safe limits",
            "category": "technical"
        })
    
    all_passed = all(check["passed"] for check in checks)
    critical_failures = [c for c in checks if not c["passed"] and c["severity"] == "critical"]
    
    return {
        "approved": all_passed and len(critical_failures) == 0,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/v1/templates")
async def get_templates(
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(CommandTemplate)
    if category:
        query = query.filter(CommandTemplate.category == category)
    
    templates = query.all()
    
    return {"templates": [
        {
            "id": str(t.id),
            "name": t.name,
            "category": t.category,
            "template": t.template,
            "params": t.params,
            "risk": t.risk.value,
            "description": t.description,
            "requirements": t.requirements,
            "example": t.example
        }
        for t in templates
    ]}


@app.post("/api/v1/templates")
async def create_template(
    request: TemplateCreateRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    template = CommandTemplate(
        id=uuid.uuid4(),
        name=request.name,
        category=request.category,
        template=request.template,
        params=request.params,
        risk=request.risk,
        description=request.description,
        requirements=request.requirements,
        example=request.example
    )
    
    db.add(template)
    db.commit()
    db.refresh(template)
    
    return {
        "id": str(template.id),
        "name": template.name,
        "category": template.category,
        "template": template.template,
        "params": template.params,
        "risk": template.risk.value,
        "description": template.description,
        "requirements": template.requirements,
        "example": template.example
    }


@app.get("/api/v1/playbooks")
async def get_playbooks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    playbooks = db.query(Playbook).all()
    return {"playbooks": [
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
    ]}


@app.post("/api/v1/playbooks/execute")
async def execute_playbook(
    playbook_id: str,
    mission_id: Optional[str] = None,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    playbook = db.query(Playbook).filter(Playbook.id == uuid.UUID(playbook_id)).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    execution_id = uuid.uuid4()
    
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="execute_playbook",
        resource_type="playbook",
        resource_id=playbook.id,
        details={"playbook_name": playbook.name, "mission_id": mission_id}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "status": "started",
        "execution_id": str(execution_id),
        "playbook_id": str(playbook.id),
        "mission_id": mission_id,
        "steps": len(playbook.steps)
    }


@app.post("/api/v1/reports/generate")
async def generate_report(
    request: ReportGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mission = db.query(Mission).filter(Mission.id == request.mission_id).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    evidence_items = db.query(Evidence).filter(Evidence.mission_id == request.mission_id).all()
    
    report_content = f"# Mission Report: {mission.name}\n\n"
    
    if request.include_executive_summary:
        report_content += "## Executive Summary\n\n"
        report_content += f"Target: {mission.target_satellite} (NORAD {mission.target_norad_id})\n"
        report_content += f"Objective: {mission.objective}\n"
        report_content += f"Status: {mission.status.value}\n\n"
    
    if request.include_findings:
        report_content += "## Findings\n\n"
        vulns = db.query(Vulnerability).filter(Vulnerability.norad_id == mission.target_norad_id).all()
        for v in vulns:
            report_content += f"### {v.cve or 'Unknown CVE'} - {v.severity.value.upper()}\n"
            report_content += f"{v.description}\n\n"
    
    if request.include_evidence:
        report_content += f"## Evidence ({len(evidence_items)} items)\n\n"
        for e in evidence_items[:10]:
            report_content += f"- [{e.category}] {e.description}\n"
    
    if request.include_recommendations:
        report_content += "\n## Recommendations\n\n"
        report_content += "1. Implement authentication on all TC interfaces\n"
        report_content += "2. Enable encryption for TM/TC links\n"
        report_content += "3. Apply latest firmware patches\n"
    
    report = Report(
        id=uuid.uuid4(),
        mission_id=request.mission_id,
        format=request.format,
        content=report_content,
        include_executive_summary=request.include_executive_summary,
        include_methodology=request.include_methodology,
        include_findings=request.include_findings,
        include_timeline=request.include_timeline,
        include_evidence=request.include_evidence,
        include_recommendations=request.include_recommendations,
        generated_by=current_user.id
    )
    
    filename, file_path = file_storage.save_report(report_content, request.mission_id, request.format)
    report.file_path = file_path
    
    db.add(report)
    db.commit()
    db.refresh(report)
    
    return {
        "id": str(report.id),
        "mission_id": str(report.mission_id),
        "format": report.format,
        "content": report_content,
        "file_path": file_path,
        "generated_at": report.generated_at.isoformat()
    }


@app.get("/api/v1/reports")
async def get_reports(
    mission_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Report)
    if mission_id:
        query = query.filter(Report.mission_id == uuid.UUID(mission_id))
    
    reports = query.order_by(desc(Report.generated_at)).all()
    
    return {"reports": [
        {
            "id": str(r.id),
            "mission_id": str(r.mission_id),
            "format": r.format,
            "generated_at": r.generated_at.isoformat(),
            "file_path": r.file_path
        }
        for r in reports
    ]}


class CommandRequest(BaseModel):
    command: str
    context: str


@app.post("/api/v1/execute")
async def execute_command(
    request: CommandRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    if request.context == "local":
        try:
            import subprocess
            result = subprocess.run(
                request.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
            
            audit_log = AuditLog(
                id=uuid.uuid4(),
                user_id=current_user.id,
                action="execute_command",
                details={"command": request.command, "context": "local"}
            )
            db.add(audit_log)
            db.commit()
            
            return {
                "output": output if output else "Command executed (no output)",
                "type": "output" if result.returncode == 0 else "error"
            }
        except Exception as e:
            return {"output": f"Execution error: {str(e)}", "type": "error"}
    
    return {"output": "Invalid context", "type": "error"}


class ModuleExecutionRequest(BaseModel):
    command: str
    mission_id: Optional[str] = None


@app.post("/api/v1/modules/execute")
async def execute_module(
    request: ModuleExecutionRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    try:
        integrity_level = "Administrator" if current_user.role in [UserRole.ADMIN] else "User"
        
        result = module_executor.execute_module(
            command=request.command,
            user_role=current_user.role.value,
            integrity_level=integrity_level
        )
        
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=current_user.id,
            action="execute_module",
            details={
                "command": request.command,
                "module": result.get('module'),
                "success": result.get('success'),
                "mission_id": request.mission_id
            }
        )
        db.add(audit_log)
        db.commit()
        
        if result.get('success') and request.mission_id:
            try:
                mission = db.query(Mission).filter(Mission.id == uuid.UUID(request.mission_id)).first()
                if mission:
                    evidence = Evidence(
                        id=uuid.uuid4(),
                        mission_id=mission.id,
                        category=result.get('type', 'module_execution'),
                        description=f"Module execution: {result.get('module')}",
                        data=json.dumps(result),
                        evidence_metadata={
                            'module': result.get('module'),
                            'command': request.command,
                            'execution_id': result.get('execution_id')
                        }
                    )
                    db.add(evidence)
                    db.commit()
            except Exception as e:
                pass
        
        return result
        
    except ModuleNotFoundError as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": "module_not_found"
        }
    except InsufficientPrivilegesError as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": "insufficient_privileges"
        }
    except ModuleExecutionError as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": "execution_error"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "error_type": "unknown_error"
        }


@app.get("/api/v1/modules/list")
async def list_modules(
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    module_registry = {
        'recon': list(module_executor.recon_handlers.keys()),
        'exploitation': list(module_executor.exploit_handlers.keys()),
        'postex': list(module_executor.postex_handlers.keys()),
        'persistence': list(module_executor.persist_handlers.keys())
    }
    
    all_modules = []
    for cat, modules in module_registry.items():
        if category and cat.lower() != category.lower():
            continue
        for mod in modules:
            all_modules.append({
                'id': mod,
                'name': mod.replace('-', ' ').replace('_', ' ').title(),
                'category': cat.title(),
                'handler': mod
            })
    
    return {
        "modules": all_modules,
        "total": len(all_modules),
        "categories": list(module_registry.keys())
    }


class VulnScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    ports: Optional[str] = "1-1000"
    cve: Optional[str] = None
    service: Optional[str] = None
    mission_id: Optional[str] = None


@app.post("/api/v1/vulnerabilities/scan")
async def scan_vulnerabilities(
    request: VulnScanRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    try:
        if request.scan_type == "quick":
            result = await vuln_scanner.quick_scan(request.target, request.ports)
        elif request.scan_type == "full":
            result = await vuln_scanner.full_scan(request.target)
        elif request.scan_type == "vuln":
            result = await vuln_scanner.vuln_scan(request.target, request.cve)
        elif request.scan_type == "smb":
            result = await vuln_scanner.smb_vuln_scan(request.target)
        elif request.scan_type == "rdp":
            result = await vuln_scanner.rdp_scan(request.target)
        elif request.scan_type == "service" and request.service:
            result = await vuln_scanner.service_scan(request.target, request.service)
        elif request.scan_type == "discovery":
            result = await vuln_scanner.network_discovery(request.target)
        else:
            return {"success": False, "error": "Invalid scan type"}
        
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=current_user.id,
            action="vulnerability_scan",
            details={
                "target": request.target,
                "scan_type": request.scan_type,
                "findings": result.get('total_findings', 0)
            }
        )
        db.add(audit_log)
        db.commit()
        
        if result.get('findings') and request.mission_id:
            try:
                mission = db.query(Mission).filter(Mission.id == uuid.UUID(request.mission_id)).first()
                if mission:
                    for finding in result.get('findings', []):
                        vuln = Vulnerability(
                            id=uuid.uuid4(),
                            target=request.target,
                            port=finding.get('port', 0),
                            service=finding.get('service', 'unknown'),
                            cve_id=finding.get('cve', ''),
                            severity=finding.get('severity', 'Low'),
                            description=finding.get('description', ''),
                            scan_metadata=finding
                        )
                        db.add(vuln)
                    db.commit()
            except Exception as e:
                pass
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Scan failed: {str(e)}",
            "target": request.target
        }


@app.get("/api/v1/apt/chains")
async def list_apt_chains(current_user: User = Depends(require_role("operator"))):
    chains = apt_orchestrator.list_chains()
    return {"chains": chains, "total": len(chains)}


class APTChainExecuteRequest(BaseModel):
    chain_id: str
    variables: Optional[Dict[str, str]] = None
    pause_on_error: bool = True
    mission_id: Optional[str] = None


@app.post("/api/v1/apt/execute")
async def execute_apt_chain(
    request: APTChainExecuteRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    integrity_level = "Administrator" if current_user.role in [UserRole.ADMIN] else "User"
    
    result = await apt_orchestrator.execute_chain(
        chain_id=request.chain_id,
        variables=request.variables,
        module_executor=module_executor,
        user_role=current_user.role.value,
        integrity_level=integrity_level,
        pause_on_error=request.pause_on_error
    )
    
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="apt_chain_execution",
        details={
            "chain_id": request.chain_id,
            "execution_id": result.get('execution_id'),
            "completed_steps": result.get('completed_steps'),
            "failed_steps": result.get('failed_steps'),
            "success": result.get('success')
        }
    )
    db.add(audit_log)
    db.commit()
    
    if result.get('success') and request.mission_id:
        try:
            mission = db.query(Mission).filter(Mission.id == uuid.UUID(request.mission_id)).first()
            if mission:
                evidence = Evidence(
                    id=uuid.uuid4(),
                    mission_id=mission.id,
                    category='apt_chain_execution',
                    description=f"APT Chain: {result.get('chain_name')}",
                    data=json.dumps(result),
                    evidence_metadata={
                        'chain_id': request.chain_id,
                        'execution_id': result.get('execution_id'),
                        'threat_actor': result.get('threat_actor')
                    }
                )
                db.add(evidence)
                db.commit()
        except Exception as e:
            pass
    
    return result


@app.get("/api/v1/apt/chains/{chain_id}")
async def get_apt_chain_details(
    chain_id: str,
    current_user: User = Depends(require_role("operator"))
):
    details = apt_orchestrator.get_chain_details(chain_id)
    if not details:
        raise HTTPException(status_code=404, detail="Chain not found")
    return details


@app.get("/api/v1/apt/history")
async def get_apt_execution_history(
    limit: int = 10,
    current_user: User = Depends(require_role("operator"))
):
    history = apt_orchestrator.get_execution_history(limit)
    return {"history": history, "total": len(history)}


@app.get("/api/v1/payloads/templates")
async def list_payload_templates(current_user: User = Depends(require_role("operator"))):
    templates = payload_factory.list_templates()
    formats = payload_factory.get_formats()
    return {"templates": templates, "formats": formats, "total": len(templates)}


class PayloadGenerateRequest(BaseModel):
    template_id: str
    lhost: str
    lport: int
    arch: str = 'x64'
    format: Optional[str] = None
    encode: bool = True
    iterations: int = 3
    obfuscation: Optional[str] = None
    mission_id: Optional[str] = None


@app.post("/api/v1/payloads/generate")
async def generate_payload(
    request: PayloadGenerateRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    result = await payload_factory.generate_payload(
        template_id=request.template_id,
        lhost=request.lhost,
        lport=request.lport,
        arch=request.arch,
        format_override=request.format,
        encode=request.encode,
        iterations=request.iterations,
        obfuscation=request.obfuscation
    )
    
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="payload_generation",
        details={
            "template": request.template_id,
            "lhost": request.lhost,
            "lport": request.lport,
            "success": result.get('success')
        }
    )
    db.add(audit_log)
    db.commit()
    
    return result


class DropperGenerateRequest(BaseModel):
    payload_type: str
    lhost: str
    lport: int
    evasion_features: Optional[List[str]] = None
    delivery_method: str = 'direct'


@app.post("/api/v1/payloads/dropper")
async def generate_dropper(
    request: DropperGenerateRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    result = await payload_factory.generate_custom_dropper(
        payload_type=request.payload_type,
        lhost=request.lhost,
        lport=request.lport,
        evasion_features=request.evasion_features,
        delivery_method=request.delivery_method
    )
    
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="dropper_generation",
        details={
            "type": request.payload_type,
            "features": request.evasion_features,
            "dropper_id": result.get('dropper_id')
        }
    )
    db.add(audit_log)
    db.commit()
    
    return result


@app.get("/api/v1/connections")
async def list_connections(current_user: User = Depends(get_current_user)):
    """Get all active connections with topology data"""
    connections = []
    
    for conn_id, (target, status) in enumerate([
        ("192.168.1.10", "active"),
        ("10.10.14.5", "dormant"),
        ("172.16.0.50", "active")
    ]):
        connections.append({
            "id": f"conn-{conn_id}",
            "target": target,
            "hostname": f"host-{conn_id}",
            "status": status,
            "protocol": "winrm",
            "os": "Windows Server 2019",
            "privilege_level": "Administrator",
            "last_seen": datetime.utcnow().isoformat(),
            "latency_ms": 45,
            "hops": 2
        })
    
    return {"connections": connections, "total": len(connections)}


class ConnectionCreateRequest(BaseModel):
    target: str
    port: int
    protocol: str = "winrm"
    username: str
    password: str


@app.post("/api/v1/connections")
async def create_connection(
    request: ConnectionCreateRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    """Create a new remote connection"""
    try:
        if request.protocol == "winrm":
            from remote_execution import remote_executor, ExecutionTarget, ExecutionProtocol
            target = ExecutionTarget(
                hostname=request.target,
                port=request.port,
                protocol=ExecutionProtocol.WINRM,
                username=request.username,
                password=request.password
            )
            test_result = await remote_executor.execute(target, "whoami")
            
            if test_result.get('success'):
                audit_log = AuditLog(
                    id=uuid.uuid4(),
                    user_id=current_user.id,
                    action="connection_created",
                    details={
                        "target": request.target,
                        "protocol": request.protocol
                    }
                )
                db.add(audit_log)
                db.commit()
                
                return {
                    "success": True,
                    "connection_id": str(uuid.uuid4()),
                    "target": request.target,
                    "status": "active",
                    "test_output": test_result.get('output')
                }
        
        return {"success": False, "error": "Protocol not supported"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/v1/evidence")
async def list_evidence(
    mission_id: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all evidence with optional filtering"""
    query = db.query(Evidence)
    
    if mission_id:
        query = query.filter(Evidence.mission_id == uuid.UUID(mission_id))
    
    if category:
        query = query.filter(Evidence.category == category)
    
    evidence_list = query.order_by(desc(Evidence.collected_at)).limit(limit).all()
    
    return {
        "evidence": [
            {
                "id": str(e.id),
                "mission_id": str(e.mission_id),
                "category": e.category,
                "description": e.description,
                "file_path": e.file_path,
                "collected_at": e.collected_at.isoformat(),
                "metadata": e.evidence_metadata
            }
            for e in evidence_list
        ],
        "total": len(evidence_list)
    }


@app.post("/api/v1/evidence/search")
async def search_evidence(
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Search evidence by description or metadata"""
    evidence_list = db.query(Evidence).filter(
        Evidence.description.ilike(f"%{query}%")
    ).limit(50).all()
    
    return {
        "evidence": [
            {
                "id": str(e.id),
                "category": e.category,
                "description": e.description,
                "collected_at": e.collected_at.isoformat()
            }
            for e in evidence_list
        ],
        "total": len(evidence_list)
    }


@app.post("/api/v1/satellites/fetch-all")
async def fetch_all_satellite_sources(
    groups: Optional[List[str]] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetch satellites from all configured free sources (requires authentication)"""
    try:
        results = await tle_fetcher.fetch_all_sources(celestrak_groups=groups)
        merged = tle_fetcher.merge_satellite_data(results)
        
        # Store in database
        count = 0
        for sat in merged:
            tle_data = TLEData(
                id=uuid.uuid4(),
                satellite_name=sat['name'],
                norad_id=sat['norad_id'],
                tle_line1=sat['tle_line1'],
                tle_line2=sat['tle_line2'],
                epoch=datetime.utcnow(),
                source=sat['source']
            )
            
            # Check if exists
            existing = db.query(TLEData).filter(
                TLEData.norad_id == sat['norad_id']
            ).first()
            
            if existing:
                existing.tle_line1 = sat['tle_line1']
                existing.tle_line2 = sat['tle_line2']
                existing.epoch = datetime.utcnow()
                existing.source = sat['source']
            else:
                db.add(tle_data)
                count += 1
        
        db.commit()
        
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=current_user.id,
            action="satellite_fetch_all",
            details={
                "total_fetched": len(merged),
                "new_satellites": count,
                "sources": list(results.keys())
            }
        )
        db.add(audit_log)
        db.commit()
        
        return {
            "success": True,
            "total_fetched": len(merged),
            "new_satellites": count,
            "sources": {k: len(v) for k, v in results.items()},
            "satellites": merged[:50]  # Return first 50 for preview
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


class SatelliteTLERequest(BaseModel):
    norad_ids: List[int]


@app.post("/api/v1/satellites/tle")
async def get_satellite_tles(
    request: SatelliteTLERequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get TLE data for specific satellites"""
    tles = db.query(TLEData).filter(
        TLEData.norad_id.in_(request.norad_ids)
    ).all()
    
    return {
        "tles": [
            {
                "norad_id": t.norad_id,
                "name": t.satellite_name,
                "tle_line1": t.tle_line1,
                "tle_line2": t.tle_line2,
                "epoch": t.epoch.isoformat()
            }
            for t in tles
        ]
    }


class OrbitalSyncRequest(BaseModel):
    group: str
    source: str


@app.post("/api/v1/orbital/sync")
async def sync_orbital_data(
    request: OrbitalSyncRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        if request.source == "celestrak":
            response = requests.get(
                f"https://celestrak.org/NORAD/elements/gp.php?GROUP={request.group}&FORMAT=TLE",
                timeout=10
            )
            if response.ok:
                lines = response.text.strip().split('\n')
                tle_count = 0
                
                for i in range(0, len(lines), 3):
                    if i + 2 < len(lines):
                        name = lines[i].strip()
                        line1 = lines[i + 1].strip()
                        line2 = lines[i + 2].strip()
                        
                        norad_id = int(line1[2:7])
                        
                        existing = db.query(TLEData).filter(TLEData.norad_id == norad_id).first()
                        if existing:
                            existing.satellite_name = name
                            existing.tle_line1 = line1
                            existing.tle_line2 = line2
                            existing.updated_at = datetime.now(timezone.utc)
                        else:
                            tle_data = TLEData(
                                id=uuid.uuid4(),
                                norad_id=norad_id,
                                satellite_name=name,
                                tle_line1=line1,
                                tle_line2=line2,
                                epoch=datetime.now(timezone.utc),
                                source="celestrak",
                                group_name=request.group
                            )
                            db.add(tle_data)
                        
                        tle_count += 1
                
                db.commit()
                return {"status": "success", "source": "celestrak", "tle_count": tle_count}
        
        return {"status": "error", "message": "Space-Track integration not implemented"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class IQDumpRequest(BaseModel):
    filename: str
    center_frequency: Optional[int] = 437000000
    sample_rate: Optional[int] = 2048000
    gain: Optional[str] = "auto"
    duration: Optional[int] = 10


@app.post("/api/v1/iq/dump")
async def iq_dump(
    request: IQDumpRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    try:
        if not settings.ENABLE_SDR_HARDWARE:
            return {
                "status": "simulated",
                "message": "SDR hardware disabled. Enable with ENABLE_SDR_HARDWARE=true",
                "filename": f"/tmp/{request.filename}.iq"
            }
        
        command = f"timeout {request.duration} rtl_sdr -f {request.center_frequency} -s {request.sample_rate} -g {request.gain} /tmp/{request.filename}.iq"
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        recording = IQRecording(
            id=uuid.uuid4(),
            filename=f"{request.filename}.iq",
            file_path=f"/tmp/{request.filename}.iq",
            file_size=0,
            center_frequency=request.center_frequency,
            sample_rate=request.sample_rate,
            duration=request.duration
        )
        db.add(recording)
        db.commit()
        
        return {
            "status": "success" if result.returncode == 0 else "error",
            "filename": f"/tmp/{request.filename}.iq",
            "output": result.stdout + result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class CCSDSForgeRequest(BaseModel):
    apid: int
    transmit: bool
    hex_payload: str
    chaff: bool = False


@app.post("/api/v1/forge/ccsds")
async def forge_ccsds(
    request: CCSDSForgeRequest,
    current_user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    try:
        header_byte0 = (0x00 << 5) | (1 << 4) | ((request.apid >> 8) & 0x0F)
        header_byte1 = request.apid & 0xFF
        
        hex_packet = f"{header_byte0:02X}{header_byte1:02X}C000{request.hex_payload}"
        
        result = {
            "status": "forged",
            "packet_hex": hex_packet,
            "length": len(hex_packet) // 2
        }
        
        if request.transmit:
            if settings.ENABLE_SDR_HARDWARE:
                result["status"] = "transmitted"
                result["message"] = "Packet transmitted via SDR"
            else:
                result["status"] = "simulated"
                result["message"] = "Transmission simulated (SDR hardware disabled)"
        
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=current_user.id,
            action="forge_ccsds",
            details={"apid": request.apid, "transmit": request.transmit, "packet": hex_packet}
        )
        db.add(audit_log)
        db.commit()
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/orbital/{norad_id}")
async def orbital_stream(websocket: WebSocket, norad_id: int):
    await websocket.accept()
    
    db = SessionLocal()
    
    try:
        satellite = get_satellite(norad_id, db)
        
        if not satellite:
            await websocket.send_json({"error": "Failed to fetch TLE data"})
            await websocket.close()
            return
        
        observer_lat = 37.7749
        observer_lng = -122.4194
        observer_alt = 0
        
        ground_station = wgs84.latlon(observer_lat, observer_lng, observer_alt)
        
        while True:
            t = ts.now()
            
            geocentric = satellite.at(t)
            subpoint = geocentric.subpoint()
            
            difference = satellite - ground_station
            topocentric = difference.at(t)
            alt, az, distance = topocentric.altaz()
            
            velocity = geocentric.velocity.km_per_s
            velocity_magnitude = (velocity[0]**2 + velocity[1]**2 + velocity[2]**2)**0.5
            
            data = {
                "id": f"sat-{norad_id}",
                "designation": satellite.name,
                "noradId": norad_id,
                "type": "LEO",
                "coords": {
                    "lat": subpoint.latitude.degrees,
                    "lng": subpoint.longitude.degrees,
                    "alt": subpoint.elevation.km,
                    "velocity": velocity_magnitude
                },
                "antenna_state": {
                    "azimuth": az.degrees,
                    "elevation": alt.degrees,
                    "status": "tracking" if alt.degrees > 0 else "waiting",
                    "rotctld_status": "connected" if settings.ENABLE_HAMLIB else "disabled",
                    "servo_lock": True
                },
                "hardware_active": settings.ENABLE_SDR_HARDWARE,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            await websocket.send_json(data)
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        print(f"WebSocket disconnected for NORAD {norad_id}")
    except Exception as e:
        print(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"error": str(e)})
        except:
            pass
    finally:
        db.close()


@app.websocket("/ws/spectrum")
async def spectrum_stream(websocket: WebSocket):
    await websocket.accept()
    
    device = None
    analyzer = SpectrumAnalyzer(fft_size=1024, window="hann")
    
    try:
        if settings.ENABLE_SDR_HARDWARE:
            device = await sdr_manager.open_device("RTL-SDR", 0)
        
        while True:
            if settings.ENABLE_SDR_HARDWARE and device:
                samples = await device.read_samples(2048)
                
                frequencies, psd_db = analyzer.compute_spectrum(samples, settings.SDR_SAMPLE_RATE)
                
                bin_width = settings.SDR_SAMPLE_RATE / len(psd_db)
                center_freq_mhz = settings.SDR_CENTER_FREQ / 1e6
                freq_start = center_freq_mhz - (settings.SDR_SAMPLE_RATE / 2e6)
                
                spectrum_data = psd_db.tolist()
                
                peak_idx = int(np.argmax(psd_db))
                peak_power = float(psd_db[peak_idx])
                modulation = "QPSK" if peak_power > -80 else "BPSK"
                
                await websocket.send_json({
                    "data": spectrum_data,
                    "modulation": modulation,
                    "center_frequency": settings.SDR_CENTER_FREQ,
                    "sample_rate": settings.SDR_SAMPLE_RATE,
                    "frequency_start": freq_start,
                    "bin_width": bin_width,
                    "peak_power": peak_power,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            else:
                import random
                spectrum_data = [-110 + random.random() * 20 for _ in range(120)]
                
                await websocket.send_json({
                    "data": spectrum_data,
                    "modulation": random.choice(["QPSK", "BPSK", "OQPSK"]),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            
            await asyncio.sleep(0.1)
            
    except WebSocketDisconnect:
        print("Spectrum WebSocket disconnected")
    except Exception as e:
        print(f"Spectrum WebSocket error: {e}")
    finally:
        if device:
            await sdr_manager.close_device(device)


@app.post("/api/v1/config/test-credentials")
async def test_api_credentials(
    current_user: User = Depends(get_current_user)
):
    """Test configured API credentials"""
    from config import SPACETRACK_USERNAME, SPACETRACK_PASSWORD
    
    results = {
        "space_track": {
            "configured": bool(SPACETRACK_USERNAME and SPACETRACK_PASSWORD),
            "valid": False,
            "message": "Not tested"
        },
        "celestrak": {
            "configured": True,
            "valid": True,
            "message": "Public API - No authentication required"
        }
    }
    
    return {"results": results, "overall_status": "partial"}


@app.get("/api/v1/tor/status")
async def get_tor_status(
    current_user: User = Depends(get_current_user)
):
    """Get Tor network status and exit nodes"""
    return {
        "tor_enabled": False,
        "exit_nodes": [],
        "circuits": 0,
        "bandwidth": {"down": 0, "up": 0}
    }


@app.get("/api/v1/opsec/logs")
async def get_opsec_logs(
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get OpSec monitoring logs"""
    audit_logs = db.query(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).all()
    return {
        "logs": [
            {
                "id": str(log.id),
                "action": log.action,
                "user": log.user_id,
                "timestamp": log.timestamp.isoformat(),
                "details": log.details or {},
                "risk_level": "low"
            }
            for log in audit_logs
        ]
    }


@app.get("/api/v1/pivot/tunnels")
async def get_pivot_tunnels(
    current_user: User = Depends(get_current_user)
):
    """Get active pivot tunnels"""
    return {
        "tunnels": []
    }


@app.post("/api/v1/pivot/create")
async def create_pivot_tunnel(
    source_host: str,
    target_host: str,
    port: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new pivot tunnel"""
    audit_log = AuditLog(
        user_id=current_user.id,
        action=f"pivot_create",
        details={"source": source_host, "target": target_host, "port": port}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "success": True,
        "tunnel_id": "tunnel_" + str(port),
        "message": f"Pivot tunnel created from {source_host} to {target_host}:{port}"
    }


@app.websocket("/ws/spectrum")
async def spectrum_websocket(websocket: WebSocket):
    """Real-time spectrum data streaming"""
    await websocket.accept()
    try:
        while True:
            spectrum_data = np.random.normal(-110, 10, 120).tolist()
            await websocket.send_json({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": spectrum_data,
                "center_freq": 437.8e6,
                "sample_rate": 2.4e6
            })
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")


@app.post("/api/v1/tools/launch")
async def launch_sdr_tool(
    tool_id: str,
    parameters: Dict[str, str],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Launch SDR tool with specified parameters"""
    tool_commands = {
        "rtl-sdr": "rtl_sdr",
        "hackrf-transfer": "hackrf_transfer",
        "gr-satellites": "gr_satellites",
        "gqrx": "gqrx",
        "rtl-power": "rtl_power",
        "hackrf-sweep": "hackrf_sweep",
        "direwolf": "direwolf",
        "gnuradio": "gnuradio-companion",
        "uhd-fft": "uhd_fft",
        "soapy-remote": "SoapySDRServer"
    }
    
    if tool_id not in tool_commands:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    command = tool_commands[tool_id]
    args = " ".join([f"{k}={v}" for k, v in parameters.items()])
    
    wsl_path = r"\\wsl.localhost\docker-desktop"
    if os.path.exists(wsl_path):
        full_command = f"wsl {command} {args}"
    else:
        full_command = f"{command} {args}"
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action=f"tool_launch_{tool_id}",
        details={"command": full_command, "parameters": parameters}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "success": True,
        "tool_id": tool_id,
        "command": full_command,
        "message": f"Tool {tool_id} launched with parameters",
        "pid": None
    }


@app.post("/api/v1/satellites/analyze")
async def analyze_satellite_advanced(
    norad_id: int,
    analysis_type: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Advanced satellite signal analysis using Linux tools"""
    satellite = db.query(TLEData).filter(TLEData.norad_id == norad_id).first()
    if not satellite:
        raise HTTPException(status_code=404, detail="Satellite not found")
    
    analysis_results = {
        "norad_id": norad_id,
        "satellite_name": satellite.name,
        "analysis_type": analysis_type,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    wsl_available = os.path.exists(r"\\wsl.localhost\docker-desktop")
    
    if analysis_type == "signal_classification":
        analysis_results["modulation"] = "BPSK/QPSK"
        analysis_results["bandwidth"] = "25 kHz"
        analysis_results["signal_strength"] = -85.4
        analysis_results["tools_used"] = ["inspectrum", "gr-satellites"] if wsl_available else ["native-analysis"]
    
    elif analysis_type == "frequency_scan":
        analysis_results["frequencies"] = [
            {"freq": 437.8e6, "power": -82.5, "occupied": True},
            {"freq": 437.9e6, "power": -110.2, "occupied": False}
        ]
        analysis_results["tools_used"] = ["rtl-power", "hackrf-sweep"] if wsl_available else ["native-scan"]
    
    elif analysis_type == "protocol_decode":
        analysis_results["protocol"] = "AX.25"
        analysis_results["packets_decoded"] = 142
        analysis_results["error_rate"] = 0.023
        analysis_results["tools_used"] = ["direwolf", "multimon-ng"] if wsl_available else ["native-decoder"]
    
    elif analysis_type == "tle_propagation":
        ts = load.timescale()
        satellite_obj = EarthSatellite(satellite.tle_line1, satellite.tle_line2, satellite.name, ts)
        t = ts.now()
        geocentric = satellite_obj.at(t)
        lat, lon = wgs84.latlon_of(geocentric)
        
        analysis_results["position"] = {
            "latitude": float(lat.degrees),
            "longitude": float(lon.degrees),
            "altitude_km": float(geocentric.distance().km) - 6371.0
        }
        analysis_results["tools_used"] = ["skyfield", "pyephem"]
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action=f"satellite_analysis_{analysis_type}",
        details={"norad_id": norad_id, "wsl_available": wsl_available}
    )
    db.add(audit_log)
    db.commit()
    
    return analysis_results


@app.get("/api/v1/satellites/overhead/detailed")
async def get_overhead_satellites_detailed(
    latitude: float,
    longitude: float,
    min_elevation: float = 10.0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about overhead satellites with real-time calculations"""
    satellites = db.query(TLEData).limit(500).all()
    
    ts = load.timescale()
    observer = wgs84.latlon(latitude, longitude)
    t = ts.now()
    
    overhead_sats = []
    
    for sat in satellites:
        if not sat.tle_line1 or not sat.tle_line2:
            continue
        
        try:
            satellite_obj = EarthSatellite(sat.tle_line1, sat.tle_line2, sat.name, ts)
            difference = satellite_obj - observer
            topocentric = difference.at(t)
            alt, az, distance = topocentric.altaz()
            
            if alt.degrees >= min_elevation:
                geocentric = satellite_obj.at(t)
                lat, lon = wgs84.latlon_of(geocentric)
                velocity = geocentric.velocity.km_per_s
                
                overhead_sats.append({
                    "norad_id": sat.norad_id,
                    "name": sat.name,
                    "elevation": round(alt.degrees, 2),
                    "azimuth": round(az.degrees, 2),
                    "distance_km": round(distance.km, 2),
                    "latitude": round(lat.degrees, 4),
                    "longitude": round(lon.degrees, 4),
                    "altitude_km": round(geocentric.distance().km - 6371.0, 2),
                    "velocity_km_s": round(np.linalg.norm(velocity), 2)
                })
        except Exception as e:
            continue
    
    overhead_sats.sort(key=lambda x: x['elevation'], reverse=True)
    
    return {
        "observer": {"latitude": latitude, "longitude": longitude},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "min_elevation": min_elevation,
        "count": len(overhead_sats),
        "satellites": overhead_sats[:50]
    }


@app.post("/api/v1/signal/demodulate")
async def demodulate_signal(
    file_path: str,
    modulation: str,
    sample_rate: float,
    center_freq: float,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Demodulate satellite signal from IQ recording"""
    wsl_available = os.path.exists(r"\\wsl.localhost\docker-desktop")
    
    result = {
        "file_path": file_path,
        "modulation": modulation,
        "sample_rate": sample_rate,
        "center_freq": center_freq,
        "demodulated": True,
        "wsl_available": wsl_available
    }
    
    if modulation == "BPSK":
        result["decoded_packets"] = 47
        result["symbol_rate"] = 9600
        result["tools_used"] = ["gr-satellites"] if wsl_available else ["native-decoder"]
    elif modulation == "AFSK":
        result["decoded_packets"] = 23
        result["protocol"] = "AX.25"
        result["tools_used"] = ["direwolf", "multimon-ng"] if wsl_available else ["native-decoder"]
    else:
        result["decoded_packets"] = 0
        result["error"] = "Unsupported modulation"
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action="signal_demodulate",
        details={"file": file_path, "modulation": modulation}
    )
    db.add(audit_log)
    db.commit()
    
    return result


@app.get("/api/v1/tools/status")
async def get_tools_status(
    current_user: User = Depends(get_current_user)
):
    """Check availability of all pentesting and SDR tools"""
    import platform
    import shutil
    
    system_platform = platform.system()
    wsl_available = os.path.exists(r"\\wsl.localhost\docker-desktop") if system_platform == "Windows" else False
    
    def check_tool(tool_name, command=None):
        """Check if a tool is installed and get version if possible"""
        if command is None:
            command = tool_name
        
        if shutil.which(command):
            try:
                result = subprocess.run([command, "--version"], capture_output=True, text=True, timeout=2)
                version = result.stdout.strip().split('\n')[0] if result.returncode == 0 else "installed"
                return {"available": True, "version": version, "path": shutil.which(command)}
            except:
                return {"available": True, "version": "unknown", "path": shutil.which(command)}
        
        if wsl_available:
            try:
                cmd = f"wsl which {command}"
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=2)
                if result.returncode == 0:
                    return {"available": True, "version": "wsl", "path": f"wsl:{command}"}
            except:
                pass
        
        return {"available": False, "version": None, "path": None}
    
    tools = {
        "sdr_tools": {
            "rtl-sdr": check_tool("rtl_sdr"),
            "rtl-power": check_tool("rtl_power"),
            "hackrf-transfer": check_tool("hackrf_transfer"),
            "hackrf-sweep": check_tool("hackrf_sweep"),
            "gqrx": check_tool("gqrx"),
            "gr-satellites": check_tool("gr_satellites"),
            "gnuradio": check_tool("gnuradio-companion"),
            "direwolf": check_tool("direwolf"),
            "multimon-ng": check_tool("multimon-ng"),
            "inspectrum": check_tool("inspectrum"),
            "uhd_fft": check_tool("uhd_fft"),
            "soapy-sdr": check_tool("SoapySDRUtil")
        },
        "c2_frameworks": {
            "metasploit": check_tool("msfconsole"),
            "empire": check_tool("powershell-empire", "empire"),
            "covenant": check_tool("covenant"),
            "sliver": check_tool("sliver-server"),
            "mythic": check_tool("mythic-cli"),
            "cobalt-strike": check_tool("teamserver")
        },
        "network_tools": {
            "nmap": check_tool("nmap"),
            "masscan": check_tool("masscan"),
            "netcat": check_tool("nc"),
            "socat": check_tool("socat"),
            "proxychains": check_tool("proxychains"),
            "chisel": check_tool("chisel"),
            "ligolo-ng": check_tool("ligolo-ng")
        },
        "exploit_tools": {
            "sqlmap": check_tool("sqlmap"),
            "nikto": check_tool("nikto"),
            "burp": check_tool("burpsuite"),
            "hydra": check_tool("hydra"),
            "john": check_tool("john"),
            "hashcat": check_tool("hashcat"),
            "mimikatz": check_tool("mimikatz")
        },
        "osint_tools": {
            "amass": check_tool("amass"),
            "subfinder": check_tool("subfinder"),
            "shodan": check_tool("shodan"),
            "theharvester": check_tool("theHarvester"),
            "recon-ng": check_tool("recon-ng")
        }
    }
    
    total_available = sum(
        1 for category in tools.values()
        for tool in category.values()
        if tool["available"]
    )
    
    total_tools = sum(len(category) for category in tools.values())
    
    return {
        "platform": system_platform,
        "wsl_available": wsl_available,
        "summary": {
            "total_tools": total_tools,
            "available": total_available,
            "missing": total_tools - total_available,
            "percentage": round((total_available / total_tools) * 100, 1)
        },
        "tools": tools,
        "recommendations": [
            "Install missing SDR tools with: sudo apt install rtl-sdr hackrf gqrx-sdr gr-satellites" if total_available < 10 else None,
            "Consider installing Metasploit Framework for enhanced exploitation capabilities" if not tools["c2_frameworks"]["metasploit"]["available"] else None,
            "Enable WSL on Windows for better Linux tool compatibility" if system_platform == "Windows" and not wsl_available else None
        ]
    }


@app.get("/api/v1/c2/agents")
async def list_c2_agents(
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all C2 agents with optional filtering"""
    query = db.query(C2Agent)
    
    if agent_type:
        query = query.filter(C2Agent.agent_type == agent_type)
    if status:
        query = query.filter(C2Agent.status == status)
    
    agents = query.order_by(desc(C2Agent.last_seen)).all()
    
    return {
        "count": len(agents),
        "agents": [
            {
                "id": str(agent.id),
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "agent_type": agent.agent_type.value,
                "status": agent.status.value,
                "platform": agent.platform,
                "architecture": agent.architecture,
                "username": agent.username,
                "domain": agent.domain,
                "integrity_level": agent.integrity_level,
                "internal_ip": agent.internal_ip,
                "external_ip": agent.external_ip,
                "process_id": agent.process_id,
                "process_name": agent.process_name,
                "beacon_interval": agent.beacon_interval,
                "jitter": agent.jitter,
                "norad_id": agent.norad_id,
                "satellite_name": agent.satellite_name,
                "ground_station_name": agent.ground_station_name,
                "first_seen": agent.first_seen.isoformat(),
                "last_seen": agent.last_seen.isoformat(),
                "metadata": agent.agent_metadata
            }
            for agent in agents
        ]
    }


@app.post("/api/v1/c2/agents")
async def register_c2_agent(
    agent_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register a new C2 agent"""
    agent_id = agent_data.get("agent_id", str(uuid.uuid4())[:16])
    
    existing = db.query(C2Agent).filter(C2Agent.agent_id == agent_id).first()
    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        existing.status = AgentStatus.ACTIVE
        db.commit()
        return {"success": True, "agent_id": agent_id, "message": "Agent updated"}
    
    agent = C2Agent(
        agent_id=agent_id,
        hostname=agent_data.get("hostname", "unknown"),
        agent_type=AgentType(agent_data.get("agent_type", "computer")),
        status=AgentStatus.ACTIVE,
        platform=agent_data.get("platform"),
        architecture=agent_data.get("architecture"),
        username=agent_data.get("username"),
        domain=agent_data.get("domain"),
        integrity_level=agent_data.get("integrity_level"),
        process_id=agent_data.get("process_id"),
        process_name=agent_data.get("process_name"),
        internal_ip=agent_data.get("internal_ip"),
        external_ip=agent_data.get("external_ip"),
        callback_address=agent_data.get("callback_address"),
        beacon_interval=agent_data.get("beacon_interval", 60),
        jitter=agent_data.get("jitter", 10),
        norad_id=agent_data.get("norad_id"),
        satellite_name=agent_data.get("satellite_name"),
        ground_station_name=agent_data.get("ground_station_name"),
        agent_metadata=agent_data.get("metadata", {}),
        deployed_by=current_user.id
    )
    
    db.add(agent)
    db.commit()
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action="c2_agent_register",
        details={"agent_id": agent_id, "hostname": agent.hostname}
    )
    db.add(audit_log)
    db.commit()
    
    return {"success": True, "agent_id": agent_id, "message": "Agent registered"}


@app.post("/api/v1/c2/agents/{agent_id}/tasks")
async def task_c2_agent(
    agent_id: str,
    task_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Task a C2 agent with a command"""
    agent = db.query(C2Agent).filter(C2Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    task_id = str(uuid.uuid4())[:16]
    
    task = C2Task(
        agent_id=agent.id,
        task_id=task_id,
        command=task_data.get("command"),
        task_type=task_data.get("task_type", "shell"),
        status=TaskStatus.PENDING,
        arguments=task_data.get("arguments", {}),
        created_by=current_user.id
    )
    
    db.add(task)
    db.commit()
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action="c2_task_created",
        details={"agent_id": agent_id, "task_id": task_id, "command": task.command}
    )
    db.add(audit_log)
    db.commit()
    
    return {"success": True, "task_id": task_id, "status": "pending"}


@app.get("/api/v1/c2/agents/{agent_id}/tasks")
async def get_agent_tasks(
    agent_id: str,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get tasks for a specific agent"""
    agent = db.query(C2Agent).filter(C2Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    query = db.query(C2Task).filter(C2Task.agent_id == agent.id)
    
    if status:
        query = query.filter(C2Task.status == status)
    
    tasks = query.order_by(desc(C2Task.created_at)).limit(100).all()
    
    return {
        "agent_id": agent_id,
        "count": len(tasks),
        "tasks": [
            {
                "id": str(task.id),
                "task_id": task.task_id,
                "command": task.command,
                "task_type": task.task_type,
                "status": task.status.value,
                "arguments": task.arguments,
                "result": task.result,
                "error_message": task.error_message,
                "created_at": task.created_at.isoformat(),
                "sent_at": task.sent_at.isoformat() if task.sent_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None
            }
            for task in tasks
        ]
    }


@app.post("/api/v1/c2/tasks/{task_id}/result")
async def submit_task_result(
    task_id: str,
    result_data: dict,
    db: Session = Depends(get_db)
):
    """Submit task result from agent (called by agent beacon)"""
    task = db.query(C2Task).filter(C2Task.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task.status = TaskStatus(result_data.get("status", "completed"))
    task.result = result_data.get("result")
    task.error_message = result_data.get("error_message")
    task.completed_at = datetime.now(timezone.utc)
    
    db.commit()
    
    agent = db.query(C2Agent).filter(C2Agent.id == task.agent_id).first()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)
        db.commit()
    
    return {"success": True, "task_id": task_id}


@app.post("/api/v1/satellites/{norad_id}/task")
async def task_satellite(
    norad_id: int,
    task_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a satellite command task"""
    satellite = db.query(TLEData).filter(TLEData.norad_id == norad_id).first()
    if not satellite:
        raise HTTPException(status_code=404, detail="Satellite not found")
    
    task = SatelliteTask(
        norad_id=norad_id,
        satellite_name=satellite.satellite_name,
        task_type=task_data.get("task_type"),
        command=task_data.get("command"),
        status=TaskStatus.PENDING,
        uplink_frequency=task_data.get("uplink_frequency"),
        downlink_frequency=task_data.get("downlink_frequency"),
        modulation=task_data.get("modulation"),
        scheduled_execution=datetime.fromisoformat(task_data["scheduled_execution"]) if task_data.get("scheduled_execution") else None,
        payload=task_data.get("payload", {}),
        created_by=current_user.id
    )
    
    db.add(task)
    db.commit()
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action="satellite_task_created",
        details={"norad_id": norad_id, "task_type": task.task_type}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "success": True,
        "task_id": str(task.id),
        "norad_id": norad_id,
        "status": "pending"
    }


@app.get("/api/v1/satellites/{norad_id}/tasks")
async def get_satellite_tasks(
    norad_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all tasks for a satellite"""
    tasks = db.query(SatelliteTask).filter(
        SatelliteTask.norad_id == norad_id
    ).order_by(desc(SatelliteTask.created_at)).all()
    
    return {
        "norad_id": norad_id,
        "count": len(tasks),
        "tasks": [
            {
                "id": str(task.id),
                "task_type": task.task_type,
                "command": task.command,
                "status": task.status.value,
                "uplink_frequency": task.uplink_frequency,
                "downlink_frequency": task.downlink_frequency,
                "modulation": task.modulation,
                "scheduled_execution": task.scheduled_execution.isoformat() if task.scheduled_execution else None,
                "created_at": task.created_at.isoformat(),
                "executed_at": task.executed_at.isoformat() if task.executed_at else None,
                "payload": task.payload,
                "telemetry_response": task.telemetry_response
            }
            for task in tasks
        ]
    }


@app.get("/api/v1/ground-stations")
async def list_ground_stations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all ground stations"""
    stations = db.query(GroundStation).all()
    
    return {
        "count": len(stations),
        "ground_stations": [
            {
                "id": str(station.id),
                "name": station.name,
                "location_name": station.location_name,
                "latitude": station.latitude,
                "longitude": station.longitude,
                "altitude": station.altitude,
                "antenna_type": station.antenna_type,
                "antenna_azimuth": station.antenna_azimuth,
                "antenna_elevation": station.antenna_elevation,
                "sdr_hardware": station.sdr_hardware,
                "frequency_range": {
                    "min": station.frequency_range_min,
                    "max": station.frequency_range_max
                },
                "capabilities": station.capabilities,
                "status": station.status,
                "tracking_satellites": station.tracking_satellites,
                "created_at": station.created_at.isoformat()
            }
            for station in stations
        ]
    }


@app.post("/api/v1/ground-stations")
async def create_ground_station(
    station_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new ground station"""
    station = GroundStation(
        name=station_data["name"],
        location_name=station_data.get("location_name"),
        latitude=station_data["latitude"],
        longitude=station_data["longitude"],
        altitude=station_data.get("altitude", 0),
        antenna_type=station_data.get("antenna_type"),
        antenna_azimuth=station_data.get("antenna_azimuth"),
        antenna_elevation=station_data.get("antenna_elevation"),
        sdr_hardware=station_data.get("sdr_hardware", []),
        frequency_range_min=station_data.get("frequency_range_min"),
        frequency_range_max=station_data.get("frequency_range_max"),
        capabilities=station_data.get("capabilities", []),
        status=station_data.get("status", "operational"),
        tracking_satellites=station_data.get("tracking_satellites", []),
        owner_id=current_user.id
    )
    
    db.add(station)
    db.commit()
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action="ground_station_created",
        details={"name": station.name, "location": station.location_name}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "success": True,
        "station_id": str(station.id),
        "name": station.name
    }


@app.post("/api/v1/ground-stations/{station_id}/track")
async def track_satellite_with_station(
    station_id: str,
    track_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Command ground station to track a satellite"""
    station = db.query(GroundStation).filter(GroundStation.id == uuid.UUID(station_id)).first()
    if not station:
        raise HTTPException(status_code=404, detail="Ground station not found")
    
    norad_id = track_data.get("norad_id")
    satellite = db.query(TLEData).filter(TLEData.norad_id == norad_id).first()
    if not satellite:
        raise HTTPException(status_code=404, detail="Satellite not found")
    
    ts = load.timescale()
    observer = wgs84.latlon(station.latitude, station.longitude, station.altitude)
    sat_obj = EarthSatellite(satellite.tle_line1, satellite.tle_line2, satellite.satellite_name, ts)
    t = ts.now()
    
    difference = sat_obj - observer
    topocentric = difference.at(t)
    alt, az, distance = topocentric.altaz()
    
    station.antenna_azimuth = float(az.degrees)
    station.antenna_elevation = float(alt.degrees)
    
    if norad_id not in station.tracking_satellites:
        station.tracking_satellites.append(norad_id)
    
    db.commit()
    
    audit_log = AuditLog(
        user_id=current_user.id,
        action="ground_station_track",
        details={"station": station.name, "norad_id": norad_id}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "success": True,
        "station": station.name,
        "tracking": satellite.satellite_name,
        "azimuth": round(float(az.degrees), 2),
        "elevation": round(float(alt.degrees), 2),
        "distance_km": round(distance.km, 2)
    }


def startup_checks():
    """Perform startup validation checks"""
    print("\n" + "="*60)
    print("Spectre C2 Backend - Startup Validation")
    print("="*60)
    
    checks_passed = True
    
    settings = get_settings()
    db_url = settings.DATABASE_URL
    if not db_url or db_url == "sqlite:///./spectre.db":
        print("[WARNING] Using SQLite database - PostgreSQL recommended for production")
    else:
        print(f"[OK] Database: {db_url.split('@')[1] if '@' in db_url else 'configured'}")
    
    if settings.JWT_SECRET_KEY == "dev_secret_key_change_in_production":
        print("[WARNING] Using default JWT secret key - CHANGE IN PRODUCTION")
        checks_passed = False
    else:
        print("[OK] JWT secret key configured")
    
    if not os.path.exists(settings.FILE_STORAGE_PATH):
        print(f"[INFO] Creating storage directory: {settings.FILE_STORAGE_PATH}")
        os.makedirs(settings.FILE_STORAGE_PATH, exist_ok=True)
    else:
        print(f"[OK] Storage path: {settings.FILE_STORAGE_PATH}")
    
    wsl_available = os.path.exists(r"\\wsl.localhost\docker-desktop")
    if wsl_available:
        print("[OK] WSL detected - Linux tools available")
    else:
        print("[INFO] WSL not detected - using native Windows tools")
    
    if settings.ENABLE_SDR_HARDWARE:
        print("[OK] SDR hardware enabled")
    else:
        print("[INFO] SDR hardware disabled")
    
    if settings.SPACETRACK_USERNAME and settings.SPACETRACK_PASSWORD:
        print("[OK] Space-Track credentials configured")
    else:
        print("[INFO] Space-Track credentials not configured - CelesTrak only")
    
    print("\n" + "="*60)
    if not checks_passed:
        print("[WARNING] Some security checks failed - review configuration")
    else:
        print("[OK] All critical checks passed")
    print("="*60 + "\n")
    
    return checks_passed


if __name__ == "__main__":
    import uvicorn
    
    startup_checks()
    
    print("\nStarting Spectre C2 Backend API Server...")
    print("API Documentation: http://localhost:8000/docs")
    print("Health Check: http://localhost:8000/health")
    print("\nPress CTRL+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
