# Spectre C2 Operations Center

**Version:** 5.0.0  
**Type:** Satellite Security Assessment & Red Team Operations Platform  
**Status:** Production Ready

---

## Overview

Spectre C2 is a full-stack command and control platform designed for satellite security research, orbital asset assessment, and red team operations. The system combines traditional C2 capabilities with specialized satellite tracking, RF analysis, and orbital mechanics computation.

### Key Features

- **Offensive Module Engine**: 29 pre-built modules across reconnaissance, exploitation, post-exploitation, and persistence
- **Satellite Tracking**: Real-time orbital propagation using SGP4/TLE data from CelesTrak and Space-Track
- **C2 Operations**: WinRM-based agent management with task execution and evidence collection
- **RF Spectrum Analysis**: Real-time spectrum visualization and signal mimicry
- **Mission Planning**: Automated pass prediction and link budget calculation
- **Evidence Management**: Comprehensive artifact collection and reporting

## System Architecture

### Backend (FastAPI/Python)
- **Framework:** FastAPI with async/await support
- **Database:** SQLite (default) or PostgreSQL for production
- **Authentication:** JWT-based with role-based access control (RBAC)
- **Performance:** Connection pooling, in-memory caching, database indexing
- **Security:** Rate limiting, SQL injection protection, HTTPS enforcement

### Frontend (React/TypeScript)
- **Framework:** React 18 with TypeScript
- **State Management:** Custom hooks for C2 operations
- **Build Tool:** Vite for fast development and optimized production builds
- **UI Library:** Tailwind CSS with custom component library
- **Real-time Updates:** WebSocket support for live telemetry

### Database Schema
- **Users & Authentication:** User accounts, roles, audit logs
- **Satellites:** TLE data, orbital parameters, pass predictions
- **Missions:** Mission planning, evidence collection, reporting
- **C2 Operations:** Agents, tasks, listeners, payloads
- **Security:** Vulnerabilities, exploits, attack chains

## Feature Modules

### Capability Engine (Offensive Modules)
29 operational modules across 4 categories:

**Reconnaissance (8 modules)**
- Domain enumeration (AD users, groups, trusts)
- Network and port scanning
- Service enumeration
- BloodHound data collection
- Process and module enumeration
- Orbital asset scanning

**Exploitation (6 modules)**
- EternalBlue (MS17-010)
- Zerologon (CVE-2020-1472)
- PrintNightmare (CVE-2021-1675)
- CCSDS packet injection
- Kerberoasting

**Post-Exploitation (8 modules)**
- Credential harvesting (LSASS, SAM, DCSync)
- Lateral movement (PsExec, WMI)
- Token manipulation
- SMB data exfiltration
- Orbital relay initialization

**Persistence (7 modules)**
- Scheduled tasks
- Registry run keys
- Windows services
- WMI event subscriptions
- Golden ticket generation
- Satellite AOS triggers
- Ground station mimicry

### Satellite Operations

**Orbital Tracking**
- Real-time SGP4 propagation engine
- TLE data from CelesTrak and Space-Track
- Position, velocity, and look angle computation
- Doppler shift calculation

**Mission Planning**
- Pass prediction for satellite visibility windows
- Link budget calculation for RF operations
- Mission timeline visualization
- Evidence collection and reporting

**RF Analysis**
- Spectrum visualization
- Signal profile generation
- Protocol analysis (CCSDS, AX.25, DVB-S2)
- Ground station mimicry

### C2 Operations

**Agent Management**
- WinRM-based agent connectivity
- Task execution and response handling
- File upload/download
- Interactive shell sessions

**Payload Generation**
- Msfvenom integration
- Custom payload templates
- Obfuscation and encoding
- Multi-stage delivery

**Evidence & Reporting**
- Artifact collection and categorization
- Screenshot capture
- Credential harvesting logs
- Automated report generation

---

## Installation and Setup

### Prerequisites

- Node.js 18+ ([Download](https://nodejs.org/))
- Python 3.10+ ([Download](https://www.python.org/downloads/))
- Git

### Quick Start

**1. Clone Repository**
```bash
git clone <repository-url>
cd spectre-c2
```

**2. Backend Setup**
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

**3. Initialize Database**
```bash
# Create database schema
python init_db.py

# Create admin user (username: admin, password: admin123)
python create_test_admin.py

# Apply performance indexes
python add_indexes.py
```

**4. Frontend Setup**
```bash
cd ..
npm install
npm run build
```

**5. Start Services**

**Terminal 1 - Backend:**
```bash
cd backend
venv\Scripts\activate  # or source venv/bin/activate on Linux/macOS
uvicorn backend:app --reload --port 8000
```

**Terminal 2 - Frontend:**
```bash
npm run dev
```

**6. Access Application**
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`

**7. Login**
```
Username: admin
Password: admin123
```

**IMPORTANT:** Change default credentials immediately in production environments.

### Environment Configuration

Create `.env` file in `backend/` directory:

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

## Usage Guide

### Initial Login
1. Navigate to `http://localhost:3000`
2. Enter credentials: `admin` / `admin123`
3. System will authenticate and load operator session

### Running Offensive Modules
1. Navigate to **Offensive > Modules** tab
2. Filter by category (All, Recon, Exploitation, Post-Ex, Persistence)
3. Click module command button to insert into terminal
4. Commands are executed against active C2 agent

### Satellite Tracking
1. Navigate to **Intel > Orbital** tab
2. System loads satellites from database
3. Click satellite for detailed view
4. Use **Satellite > Timeline** for pass predictions

### Mission Planning
1. Navigate to **Satellite > Missions** tab
2. Click **New Mission** button
3. Select target satellite and objectives
4. System calculates optimal execution windows

### Evidence Collection
1. Navigate to **Intel > Vault** tab
2. All mission artifacts automatically collected
3. Filter by category (credentials, screenshots, files)
4. Export evidence for reporting

### Testing Backend
Run comprehensive test suite:
```bash
cd backend
python run_all_tests.py
```

Test individual components:
```bash
# Authentication endpoints
python test_auth_endpoints.py

# Module execution
python test_module_executor.py

# Satellite operations
python test_backend_services.py
```

## Performance Optimization

The system includes production-grade performance features:

**Database Optimization**
- Connection pooling (20 base connections, 40 overflow)
- 25+ indexes on frequently queried columns
- Query result caching with TTL

**Caching Layer**
- In-memory cache for satellites, modules, templates
- Configurable TTL (default 300 seconds)
- Automatic cache invalidation

**Concurrent Request Handling**
- Supports 60+ simultaneous connections
- Async/await throughout backend
- Non-blocking database operations

## Security Considerations

**Production Deployment Checklist**
1. Change default admin password
2. Set strong JWT_SECRET_KEY (32+ characters)
3. Enable HTTPS with valid SSL certificates
4. Configure firewall rules (ports 8000, 3000)
5. Use PostgreSQL instead of SQLite
6. Enable rate limiting and request validation
7. Review CORS origins in backend config
8. Implement IP whitelisting if needed
9. Regular security audits and updates
10. Monitor audit logs for suspicious activity

## Legal and Ethical Use

**IMPORTANT:** This system is designed for authorized security research and red team operations only.

**Requirements for Legal Use:**
- Written authorization from asset owners
- Defined scope of engagement
- Compliance with local laws and regulations
- Proper documentation and reporting
- No unauthorized RF transmissions

**Prohibited Activities:**
- Unauthorized access to computer systems
- Interference with satellite operations
- Unlicensed RF transmission
- Data theft or destruction
- Any activity violating applicable laws

**User Responsibility:**
Operators are solely responsible for ensuring all activities comply with applicable laws, regulations, and authorizations. The developers assume no liability for misuse of this software.

## License

This software is provided for authorized security research and educational purposes only. Commercial use, redistribution, or deployment without proper authorization is prohibited.

## Support and Documentation

- API Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`
- Detailed Health: `http://localhost:8000/health/detailed`

For issues, feature requests, or security concerns, contact the development team through official channels.