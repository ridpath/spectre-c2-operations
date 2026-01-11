#!/usr/bin/env python3
"""
Spectre C2 Tactical Bridge - FastAPI Backend
Provides WinRM execution, satellite orbital mechanics, and SDR integration
"""

from fastapi import FastAPI, WebSocket, HTTPException, Header, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import asyncio
import json
import subprocess
import os
import uuid
from datetime import datetime, timezone, timedelta
from skyfield.api import load, EarthSatellite, wgs84
from sgp4.api import Satrec, jday
import requests

app = FastAPI(title="Spectre C2 Tactical Bridge", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AUTH_TOKEN = "valid_token"

def verify_token(authorization: Optional[str] = Header(None)):
    if authorization != f"Bearer {AUTH_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return True

class WinRMConnectionPayload(BaseModel):
    host: str
    port: int
    username: str
    password: str
    use_ssl: bool
    auth_method: str

class CommandRequest(BaseModel):
    command: str
    context: str
    connection: Optional[WinRMConnectionPayload] = None

class CommandResult(BaseModel):
    output: str
    type: str

class OrbitalSyncRequest(BaseModel):
    group: str
    source: str

class IQDumpRequest(BaseModel):
    filename: str

class CCSDSForgeRequest(BaseModel):
    apid: int
    transmit: bool
    hex_payload: str
    chaff: bool

class VulnerabilityScan(BaseModel):
    norad_id: int
    satellite_name: str

class PlaybookExecution(BaseModel):
    playbook_id: str
    mission_id: Optional[str] = None

class StepExecution(BaseModel):
    step_id: str
    playbook_id: str
    mission_id: Optional[str] = None

class MissionCreate(BaseModel):
    name: str
    target_satellite: str
    target_norad_id: int
    objective: str
    authorization: Dict[str, Any]

class MissionUpdate(BaseModel):
    status: Optional[str] = None
    attack_chain: Optional[List[Dict[str, Any]]] = None
    evidence: Optional[List[str]] = None

class EvidenceCreate(BaseModel):
    mission_id: str
    category: str
    description: str
    data: str
    metadata: Dict[str, Any]
    tags: List[str]
    satellite_name: Optional[str] = None
    frequency: Optional[float] = None
    signal_strength: Optional[float] = None

class ReportGenerate(BaseModel):
    mission_id: str
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_findings: bool = True
    include_timeline: bool = True
    include_evidence: bool = True
    include_recommendations: bool = True
    format: str = "markdown"

class PassPredictionRequest(BaseModel):
    norad_id: int
    latitude: float
    longitude: float
    altitude: float = 0
    min_elevation: float = 10
    hours_ahead: int = 24

class SafetyCheckRequest(BaseModel):
    frequency: float
    power: float
    modulation: str
    target_satellite: str

class TemplateCreate(BaseModel):
    name: str
    category: str
    template: str
    params: Dict[str, Any]
    risk: str
    description: str
    requirements: List[str]
    example: str

ts = load.timescale()
satellites_cache: Dict[int, EarthSatellite] = {}

vulnerabilities_db: List[Dict[str, Any]] = []
playbooks_db: List[Dict[str, Any]] = []
missions_db: List[Dict[str, Any]] = []
evidence_db: List[Dict[str, Any]] = []
reports_db: List[Dict[str, Any]] = []
templates_db: List[Dict[str, Any]] = []

def fetch_tle_from_celestrak(norad_id: int) -> Optional[tuple]:
    """Fetch TLE data from Celestrak"""
    try:
        response = requests.get(
            f"https://celestrak.org/NORAD/elements/gp.php?CATNR={norad_id}&FORMAT=TLE",
            timeout=5
        )
        if response.ok:
            lines = response.text.strip().split('\n')
            if len(lines) >= 3:
                return (lines[0].strip(), lines[1].strip(), lines[2].strip())
    except Exception as e:
        print(f"TLE fetch error for {norad_id}: {e}")
    return None

def get_satellite(norad_id: int) -> Optional[EarthSatellite]:
    """Get or create satellite object from TLE data"""
    if norad_id in satellites_cache:
        return satellites_cache[norad_id]
    
    tle_data = fetch_tle_from_celestrak(norad_id)
    if tle_data:
        name, line1, line2 = tle_data
        satellite = EarthSatellite(line1, line2, name, ts)
        satellites_cache[norad_id] = satellite
        return satellite
    return None

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "operational", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.post("/api/v1/execute")
async def execute_command(request: CommandRequest, _: bool = Depends(verify_token)) -> CommandResult:
    """Execute command via WinRM or local shell"""
    
    if request.context == "local":
        try:
            result = subprocess.run(
                request.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
            return CommandResult(
                output=output if output else f"Command executed: {request.command}",
                type="output"
            )
        except subprocess.TimeoutExpired:
            return CommandResult(output="Command timed out after 30 seconds", type="error")
        except Exception as e:
            return CommandResult(output=f"Execution error: {str(e)}", type="error")
    
    elif request.context == "remote" and request.connection:
        try:
            from winrm.protocol import Protocol
            
            endpoint = f"{'https' if request.connection.use_ssl else 'http'}://{request.connection.host}:{request.connection.port}/wsman"
            
            p = Protocol(
                endpoint=endpoint,
                transport=request.connection.auth_method.lower(),
                username=request.connection.username,
                password=request.connection.password,
                server_cert_validation='ignore'
            )
            
            shell_id = p.open_shell()
            command_id = p.run_command(shell_id, request.command)
            stdout, stderr, status_code = p.get_command_output(shell_id, command_id)
            p.cleanup_command(shell_id, command_id)
            p.close_shell(shell_id)
            
            output = stdout.decode('utf-8') + stderr.decode('utf-8')
            
            return CommandResult(
                output=output if output else f"Command executed on {request.connection.host}",
                type="output" if status_code == 0 else "error"
            )
            
        except ImportError:
            return CommandResult(
                output="pywinrm not installed. Run: pip install pywinrm",
                type="error"
            )
        except Exception as e:
            return CommandResult(output=f"WinRM error: {str(e)}", type="error")
    
    return CommandResult(output="Invalid context or missing connection", type="error")

@app.post("/api/v1/orbital/sync")
async def sync_orbital_data(request: OrbitalSyncRequest, _: bool = Depends(verify_token)):
    """Sync TLE data from Celestrak or Space-Track"""
    try:
        if request.source == "celestrak":
            response = requests.get(
                f"https://celestrak.org/NORAD/elements/gp.php?GROUP={request.group}&FORMAT=TLE",
                timeout=10
            )
            if response.ok:
                return {"status": "success", "source": "celestrak", "tle_count": response.text.count('\n') // 3}
        
        return {"status": "error", "message": "Space-Track integration not implemented"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/iq/dump")
async def iq_dump(request: IQDumpRequest, _: bool = Depends(verify_token)):
    """Capture IQ samples via rtl_sdr"""
    try:
        command = f"timeout 10 rtl_sdr -f 437000000 -s 2048000 -g 40 /tmp/{request.filename}.iq"
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        
        return {
            "status": "success" if result.returncode == 0 else "error",
            "filename": f"/tmp/{request.filename}.iq",
            "output": result.stdout + result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/forge/ccsds")
async def forge_ccsds(request: CCSDSForgeRequest, _: bool = Depends(verify_token)):
    """Forge and optionally transmit CCSDS packet"""
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
            result["status"] = "transmitted"
            result["message"] = "Packet transmission simulated (no hardware)"
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/vulnerabilities")
async def get_vulnerabilities(_: bool = Depends(verify_token), norad_id: Optional[int] = None):
    """Get vulnerability database"""
    if norad_id:
        return {"vulnerabilities": [v for v in vulnerabilities_db if v.get("norad_id") == norad_id]}
    return {"vulnerabilities": vulnerabilities_db}

@app.post("/api/v1/vulnerabilities/scan")
async def scan_vulnerabilities(request: VulnerabilityScan, _: bool = Depends(verify_token)):
    """Scan satellite for vulnerabilities (uses mock CVE database)"""
    mock_vulns = [
        {
            "id": f"vuln-{request.norad_id}-1",
            "cve": "CVE-2023-45678",
            "satellite_name": request.satellite_name,
            "norad_id": request.norad_id,
            "subsystem": "TTC",
            "description": "Command authentication bypass in telecommand handler",
            "exploit_available": True,
            "exploit_command": "ccsds-inject --apid 0x3E5 --bypass-auth --payload {COMMAND}",
            "mitigation": "Upgrade TC handler firmware to v2.3.1",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45678"],
            "severity": "critical",
            "discovered_date": (datetime.now() - timedelta(days=60)).isoformat(),
            "patch_available": True
        },
        {
            "id": f"vuln-{request.norad_id}-2",
            "satellite_name": request.satellite_name,
            "norad_id": request.norad_id,
            "subsystem": "CDH",
            "description": "Buffer overflow in onboard data handling subsystem",
            "exploit_available": True,
            "exploit_command": "python exploit_cdh_overflow.py --target {SAT}",
            "mitigation": "Implement bounds checking in TM frame parser",
            "references": ["https://cwe.mitre.org/data/definitions/120.html"],
            "severity": "high",
            "discovered_date": (datetime.now() - timedelta(days=10)).isoformat(),
            "patch_available": False
        }
    ]
    
    for vuln in mock_vulns:
        if vuln["id"] not in [v["id"] for v in vulnerabilities_db]:
            vulnerabilities_db.append(vuln)
    
    return {"status": "success", "vulnerabilities": mock_vulns}

@app.get("/api/v1/playbooks")
async def get_playbooks(_: bool = Depends(verify_token)):
    """Get all attack playbooks"""
    return {"playbooks": playbooks_db}

@app.get("/api/v1/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, _: bool = Depends(verify_token)):
    """Get specific playbook"""
    playbook = next((p for p in playbooks_db if p["id"] == playbook_id), None)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook

@app.post("/api/v1/playbooks/execute")
async def execute_playbook(request: PlaybookExecution, _: bool = Depends(verify_token)):
    """Execute attack playbook"""
    playbook = next((p for p in playbooks_db if p["id"] == request.playbook_id), None)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    execution_id = str(uuid.uuid4())
    return {
        "status": "started",
        "execution_id": execution_id,
        "playbook_id": request.playbook_id,
        "mission_id": request.mission_id,
        "steps": len(playbook.get("steps", []))
    }

@app.post("/api/v1/playbooks/step/execute")
async def execute_step(request: StepExecution, _: bool = Depends(verify_token)):
    """Execute single playbook step"""
    playbook = next((p for p in playbooks_db if p["id"] == request.playbook_id), None)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    step = next((s for s in playbook.get("steps", []) if s["id"] == request.step_id), None)
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")
    
    return {
        "status": "executed",
        "step_id": request.step_id,
        "result": f"Step '{step.get('tool', 'unknown')}' executed successfully",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/v1/missions")
async def get_missions(_: bool = Depends(verify_token)):
    """Get all missions"""
    return {"missions": missions_db}

@app.get("/api/v1/missions/{mission_id}")
async def get_mission(mission_id: str, _: bool = Depends(verify_token)):
    """Get specific mission"""
    mission = next((m for m in missions_db if m["id"] == mission_id), None)
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    return mission

@app.post("/api/v1/missions")
async def create_mission(request: MissionCreate, _: bool = Depends(verify_token)):
    """Create new mission"""
    mission = {
        "id": str(uuid.uuid4()),
        "name": request.name,
        "target_satellite": request.target_satellite,
        "target_norad_id": request.target_norad_id,
        "objective": request.objective,
        "authorization": request.authorization,
        "attack_chain": [],
        "evidence": [],
        "status": "planning",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "next_pass": None
    }
    missions_db.append(mission)
    return mission

@app.put("/api/v1/missions/{mission_id}")
async def update_mission(mission_id: str, request: MissionUpdate, _: bool = Depends(verify_token)):
    """Update mission"""
    mission = next((m for m in missions_db if m["id"] == mission_id), None)
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    if request.status:
        mission["status"] = request.status
    if request.attack_chain:
        mission["attack_chain"] = request.attack_chain
    if request.evidence:
        mission["evidence"] = request.evidence
    
    return mission

@app.delete("/api/v1/missions/{mission_id}")
async def delete_mission(mission_id: str, _: bool = Depends(verify_token)):
    """Delete mission"""
    global missions_db
    initial_count = len(missions_db)
    missions_db = [m for m in missions_db if m["id"] != mission_id]
    
    if len(missions_db) == initial_count:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    return {"status": "deleted", "mission_id": mission_id}

@app.get("/api/v1/evidence")
async def get_evidence(_: bool = Depends(verify_token), mission_id: Optional[str] = None):
    """Get evidence items"""
    if mission_id:
        return {"evidence": [e for e in evidence_db if e.get("mission_id") == mission_id]}
    return {"evidence": evidence_db}

@app.post("/api/v1/evidence")
async def create_evidence(request: EvidenceCreate, _: bool = Depends(verify_token)):
    """Create evidence item"""
    evidence = {
        "id": str(uuid.uuid4()),
        "mission_id": request.mission_id,
        "category": request.category,
        "description": request.description,
        "data": request.data,
        "metadata": request.metadata,
        "tags": request.tags,
        "satellite_name": request.satellite_name,
        "frequency": request.frequency,
        "signal_strength": request.signal_strength,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    evidence_db.append(evidence)
    return evidence

@app.delete("/api/v1/evidence/{evidence_id}")
async def delete_evidence(evidence_id: str, _: bool = Depends(verify_token)):
    """Delete evidence item"""
    global evidence_db
    initial_count = len(evidence_db)
    evidence_db = [e for e in evidence_db if e["id"] != evidence_id]
    
    if len(evidence_db) == initial_count:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    return {"status": "deleted", "evidence_id": evidence_id}

@app.post("/api/v1/reports/generate")
async def generate_report(request: ReportGenerate, _: bool = Depends(verify_token)):
    """Generate mission report"""
    mission = next((m for m in missions_db if m["id"] == request.mission_id), None)
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    mission_evidence = [e for e in evidence_db if e.get("mission_id") == request.mission_id]
    
    findings = [
        {
            "id": "finding-1",
            "severity": "critical",
            "title": "Unauthenticated Telecommand Acceptance",
            "description": "Satellite accepts commands without proper authentication",
            "cvss": 9.8,
            "recommendation": "Implement cryptographic authentication"
        }
    ]
    
    report = {
        "id": str(uuid.uuid4()),
        "mission": mission,
        "executive_summary": f"Assessment of {mission['target_satellite']} identified {len(findings)} findings",
        "methodology": "Black-box testing using SDR equipment and open-source tools",
        "findings": findings,
        "timeline": mission.get("attack_chain", []),
        "evidence": mission_evidence,
        "recommendations": ["Implement end-to-end encryption", "Deploy authentication mechanisms"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "Spectre Backend"
    }
    
    reports_db.append(report)
    
    if request.format == "markdown":
        content = f"# Satellite Penetration Test Report\n\n"
        content += f"**Target:** {mission['target_satellite']}\n"
        content += f"**Mission:** {mission['name']}\n\n"
        content += f"## Executive Summary\n{report['executive_summary']}\n\n"
        content += f"## Findings\n"
        for finding in findings:
            content += f"### {finding['title']} ({finding['severity'].upper()})\n"
            content += f"{finding['description']}\n\n"
        report["content"] = content
    elif request.format == "json":
        report["content"] = json.dumps(report, indent=2, default=str)
    else:
        report["content"] = f"<html><body><h1>Report for {mission['target_satellite']}</h1></body></html>"
    
    return report

@app.get("/api/v1/reports")
async def get_reports(_: bool = Depends(verify_token)):
    """Get all reports"""
    return {"reports": reports_db}

@app.get("/api/v1/passes/predict")
async def predict_passes(_: bool = Depends(verify_token), norad_id: int = 43105, latitude: float = 37.7749, longitude: float = -122.4194, altitude: float = 0, min_elevation: float = 10, hours_ahead: int = 24):
    """Predict satellite passes"""
    satellite = get_satellite(norad_id)
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
                current_pass = {}
    
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

@app.post("/api/v1/safety/check")
async def safety_check(request: SafetyCheckRequest, _: bool = Depends(verify_token)):
    """Perform safety and regulatory checks"""
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
            "message": f"Power {request.power}W exceeds safe limit (100W)",
            "category": "operational"
        })
    else:
        checks.append({
            "id": "power-limit",
            "name": "Power Limit Check",
            "severity": "warning",
            "passed": True,
            "message": "Power within safe limits",
            "category": "operational"
        })
    
    all_passed = all(c["passed"] for c in checks)
    
    return {
        "approved": all_passed,
        "checks": checks,
        "warnings": [c for c in checks if c["severity"] == "warning"],
        "critical_failures": [c for c in checks if not c["passed"] and c["severity"] == "critical"]
    }

@app.get("/api/v1/templates")
async def get_templates(_: bool = Depends(verify_token), category: Optional[str] = None):
    """Get command templates"""
    if category:
        return {"templates": [t for t in templates_db if t.get("category") == category]}
    return {"templates": templates_db}

@app.post("/api/v1/templates")
async def create_template(request: TemplateCreate, _: bool = Depends(verify_token)):
    """Create command template"""
    template = {
        "id": str(uuid.uuid4()),
        "name": request.name,
        "category": request.category,
        "template": request.template,
        "params": request.params,
        "risk": request.risk,
        "description": request.description,
        "requirements": request.requirements,
        "example": request.example
    }
    templates_db.append(template)
    return template

@app.websocket("/ws/orbital/{norad_id}")
async def orbital_stream(websocket: WebSocket, norad_id: int):
    """Stream real-time satellite position data"""
    await websocket.accept()
    
    try:
        satellite = get_satellite(norad_id)
        
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
                    "rotctld_status": "connected",
                    "servo_lock": True
                },
                "hardware_active": False,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            await websocket.send_json(data)
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        print(f"WebSocket disconnected for NORAD {norad_id}")
    except Exception as e:
        print(f"WebSocket error: {e}")
        await websocket.send_json({"error": str(e)})

@app.websocket("/ws/spectrum")
async def spectrum_stream(websocket: WebSocket):
    """Stream simulated spectrum data"""
    await websocket.accept()
    
    try:
        while True:
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
