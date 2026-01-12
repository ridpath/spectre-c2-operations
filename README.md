
<!-- Spectre C2, Spectre C2 Operations Center, satellite penetration testing, satellite security assessment platform, space systems security, space cybersecurity, orbital cybersecurity, orbital threat modeling, satellite red team toolkit, space red teaming, adversary simulation for space systems, space domain awareness security, ground segment security testing, ground station security assessment, satellite communications security, satcom security research, RF security assessment, radio frequency threat analysis, spectrum analysis tooling, signal analysis, spectral analysis, signal profiling, signal characterization, signal anomaly detection, non-transmitting RF research tooling, CCSDS security research, CCSDS packet analysis, CCSDS packet crafting, CCSDS packet injection research, CCSDS telemetry security, CCSDS TC/TM security, AX.25 analysis, DVB-S2 analysis, satellite protocol analysis, space protocol fuzzing research, satellite link budget calculation, link budget modeling, Doppler shift calculation, pass prediction, SGP4 propagation, TLE ingestion, CelesTrak TLE, Space-Track integration, N2YO integration, orbital mechanics computation, look angle computation, azimuth elevation range, mission planning timelines, satellite visibility windows, orbital pass scheduling, evidence collection and reporting, forensic artifact capture, audit logging, operator-invoked modules, controlled exploitation research, red team operations platform, penetration test lab tooling, government testbed security tooling, aerospace security research, satellite SOC, space SOC, tactical operations center for space systems, command and control research platform, C2 tasking and telemetry, WinRM agent management, agent task execution, post-exploitation simulation, persistence simulation, credential access simulation, lateral movement simulation, attack chain modeling, vulnerability research platform, security assessment automation, defensive validation, purple team workflows, SIEM-aligned artifacts, operational security research, role-based access control RBAC, JWT authentication, FastAPI backend, Python security tooling, React TypeScript frontend, WebSocket telemetry updates, SQLite WAL development, PostgreSQL production, caching, indexing, rate limiting, input validation, CORS controls, HTTPS deployment guidance, authorized use only, ethical security research, compliance-aware red teaming, RF compliance and licensing constraints, no unauthorized RF transmission, no interference with operational satellite systems, scoped engagement tooling, written authorization required, secure-by-design research platform -->



# Spectre C2 Operations Center

![Status: Alpha](https://img.shields.io/badge/status-alpha_active_research-yellow)
![Use Authorized Research Only](https://img.shields.io/badge/Use-Authorized_Research_Only-blueviolet)
![Domain: Astro-Sec](https://img.shields.io/badge/domain-astro--sec-blue)
![Satellite Security](https://img.shields.io/badge/Domain-Satellite_Security-informational)
![Red Team Research](https://img.shields.io/badge/Focus-Red_Team_Research-critical)
![Security Research](https://img.shields.io/badge/Category-Security_Research-blue)
![Protocols](https://img.shields.io/badge/protocols-WinRM%20%7C%20CCSDS%20%7C%20DVB--S2-purple)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688)
![Python](https://img.shields.io/badge/Backend-Python_3.10%2B-3776AB)
![React](https://img.shields.io/badge/Frontend-React_18-61DAFB)
![TypeScript](https://img.shields.io/badge/Language-TypeScript-3178C6)

---

## Executive Overview

Spectre C2 is a platform for **authorized satellite security research, orbital asset assessment, and adversary simulation**. It unifies traditional command-and-control workflows with orbital mechanics, RF analysis, and space protocol research in a controlled, auditable environment.

**Research Status:** Alpha (active development). Interfaces, modules, and internal behavior are subject to change.

---

## Core Capabilities

- Modular offensive capability engine for controlled red team simulation
- Orbital asset intelligence with real-time SGP4 propagation and pass prediction
- Satellite-aware mission planning aligned to visibility windows and link constraints
- RF and space protocol analysis tooling (non-transmitting by default)
- Deterministic C2 tasking with structured evidence capture

---

## System Architecture

### Backend (Python / FastAPI)
- Asynchronous ASGI runtime
- JWT authentication with RBAC
- SQLite (development) or PostgreSQL (production)
- Rate limiting, input validation, and audit logging

### Frontend (React / TypeScript)
- React 18 with Vite build pipeline
- Typed state hooks for C2, mission, and telemetry state
- WebSocket-based real-time updates

---

## Installation & Setup

### Prerequisites

- Node.js 18+ ([Download](https://nodejs.org/))
- Python 3.10+ ([Download](https://www.python.org/downloads/))
- Git

---

### Quick Start

#### 1. Clone Repository
```bash
git clone <repository-url>
cd spectre-c2
```

#### 2. Backend Setup
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

#### 3. Initialize Database
```bash
# Create database schema
python init_db.py

# Create admin user (username: admin, password: admin123)
python create_test_admin.py

# Apply performance indexes
python add_indexes.py
```

#### 4. Frontend Setup
```bash
cd ..
npm install
npm run build
```

#### 5. Start Services

**Terminal 1 – Backend**
```bash
cd backend
venv\Scripts\activate  # or source venv/bin/activate on Linux/macOS
uvicorn backend:app --reload --port 8000
```

**Terminal 2 – Frontend**
```bash
npm run dev
```

#### 6. Access Application
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

#### 7. Login
```
Username: admin
Password: admin123
```

**IMPORTANT:** Change default credentials immediately in production or shared environments.

---

## Environment Configuration

Create a `.env` file in the `backend/` directory:

```bash
# Database (optional - defaults to SQLite)
DATABASE_URL=sqlite:///./spectre.db

# JWT Security (REQUIRED for production)
JWT_SECRET_KEY=your-secret-key-minimum-32-characters

# External API Keys (optional)
CELESTRAK_API_KEY=your-key
SPACETRACK_USERNAME=your-username
SPACETRACK_PASSWORD=your-password
N2YO_API_KEY=your-key

# Performance Tuning
CACHE_ENABLED=true
CACHE_TTL_SECONDS=300
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40
```

---

## API Documentation

The backend exposes a fully documented REST API.

- OpenAPI / Swagger UI: http://localhost:8000/docs
- Health Check: http://localhost:8000/health
- Detailed Health: http://localhost:8000/health/detailed


---

## Usage Guide

### Initial Login
1. Navigate to http://localhost:3000
2. Enter credentials: `admin` / `admin123`  initial setup creds
3. System authenticates and loads the operator session

### Running Offensive Modules
1. Navigate to **Offensive > Modules**
2. Filter by category (Recon, Exploitation, Post-Ex, Persistence)
3. Insert module commands into the terminal
4. Execute against the active C2 agent within scope

### Satellite Tracking
1. Navigate to **Intel > Orbital**
2. Load satellites from the database
3. Select a satellite for detailed telemetry
4. Use **Satellite > Timeline** for pass predictions

### Mission Planning
1. Navigate to **Satellite > Missions**
2. Create a new mission
3. Select target satellite and objectives
4. Review calculated execution windows

### Evidence Collection
1. Navigate to **Intel > Vault**
2. Review automatically collected artifacts
3. Filter by credentials, screenshots, or files
4. Export evidence for reporting

---



## Legal & Ethical Use

This platform is intended solely for authorized security research, adversary simulation, and educational use. Unauthorized access, RF transmission, or interference with operational satellite systems is prohibited.

---

## License

Research only usage. Commercial deployment or redistribution without explicit authorization is prohibited.

<!--
satellite red team framework, space security testing, orbital cyber operations research,
space C2 research platform, CCSDS penetration testing, orbital threat assessment framework
-->
