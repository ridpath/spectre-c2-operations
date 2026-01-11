from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Enum, BigInteger
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID

JSONB = JSON
from datetime import datetime, timezone
import uuid as uuid_lib
import enum
from database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class MissionStatus(str, enum.Enum):
    PLANNING = "planning"
    WAITING = "waiting"
    ACTIVE = "active"
    COMPLETED = "completed"
    ABORTED = "aborted"


class StepStatus(str, enum.Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(Enum(UserRole), nullable=False, default=UserRole.OPERATOR)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True))
    
    missions = relationship("Mission", back_populates="created_by_user", foreign_keys="Mission.created_by")
    audit_logs = relationship("AuditLog", back_populates="user")


class Mission(Base):
    __tablename__ = "missions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    name = Column(String(255), nullable=False)
    target_satellite = Column(String(255), nullable=False)
    target_norad_id = Column(Integer, nullable=False, index=True)
    objective = Column(String(50), nullable=False)
    status = Column(Enum(MissionStatus), nullable=False, default=MissionStatus.PLANNING)
    
    authorization = Column(JSONB, nullable=False)
    attack_chain = Column(JSONB, default=list)
    next_pass = Column(JSONB)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_by_user = relationship("User", back_populates="missions", foreign_keys=[created_by])
    
    evidence_items = relationship("Evidence", back_populates="mission", cascade="all, delete-orphan")
    attack_steps = relationship("AttackStep", back_populates="mission", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="mission", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    mission_id = Column(UUID(as_uuid=True), ForeignKey("missions.id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    category = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    data = Column(Text)
    file_path = Column(String(1024))
    file_size = Column(BigInteger)
    evidence_metadata = Column(JSONB, default=dict)
    tags = Column(JSONB, default=list)
    
    satellite_name = Column(String(255))
    frequency = Column(Float)
    signal_strength = Column(Float)
    
    mission = relationship("Mission", back_populates="evidence_items")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    cve = Column(String(50), unique=True, index=True)
    satellite_name = Column(String(255), index=True)
    norad_id = Column(Integer, index=True)
    subsystem = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    exploit_available = Column(Boolean, default=False)
    exploit_command = Column(Text)
    mitigation = Column(Text)
    references = Column(JSONB, default=list)
    severity = Column(Enum(Severity), nullable=False)
    discovered_date = Column(DateTime(timezone=True))
    patch_available = Column(Boolean, default=False)
    cvss_score = Column(Float)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))


class Playbook(Base):
    __tablename__ = "playbooks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    objective = Column(String(255))
    difficulty = Column(String(50))
    duration = Column(String(50))
    steps = Column(JSONB, default=list)
    required_tools = Column(JSONB, default=list)
    required_hardware = Column(JSONB, default=list)
    legal_warnings = Column(JSONB, default=list)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))


class AttackStep(Base):
    __tablename__ = "attack_steps"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    mission_id = Column(UUID(as_uuid=True), ForeignKey("missions.id"), nullable=False, index=True)
    phase = Column(String(50), nullable=False)
    tool = Column(String(255), nullable=False)
    command = Column(Text, nullable=False)
    expected_result = Column(Text)
    actual_result = Column(Text)
    status = Column(Enum(StepStatus), nullable=False, default=StepStatus.PENDING)
    
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    mission = relationship("Mission", back_populates="attack_steps")


class Report(Base):
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    mission_id = Column(UUID(as_uuid=True), ForeignKey("missions.id"), nullable=False, index=True)
    format = Column(String(50), nullable=False)
    content = Column(Text, nullable=False)
    file_path = Column(String(1024))
    
    include_executive_summary = Column(Boolean, default=True)
    include_methodology = Column(Boolean, default=True)
    include_findings = Column(Boolean, default=True)
    include_timeline = Column(Boolean, default=True)
    include_evidence = Column(Boolean, default=True)
    include_recommendations = Column(Boolean, default=True)
    
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    mission = relationship("Mission", back_populates="reports")


class CommandTemplate(Base):
    __tablename__ = "command_templates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    category = Column(String(50), nullable=False, index=True)
    template = Column(Text, nullable=False)
    params = Column(JSONB, default=dict)
    risk = Column(Enum(Severity), nullable=False)
    description = Column(Text)
    requirements = Column(JSONB, default=list)
    example = Column(Text)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))


class TLEData(Base):
    __tablename__ = "tle_data"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    norad_id = Column(Integer, nullable=False, unique=True, index=True)
    satellite_name = Column(String(255), nullable=False)
    tle_line1 = Column(String(69), nullable=False)
    tle_line2 = Column(String(69), nullable=False)
    epoch = Column(DateTime(timezone=True), nullable=False)
    
    source = Column(String(50))
    group_name = Column(String(100))
    
    fetched_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))


class PassPrediction(Base):
    __tablename__ = "pass_predictions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    norad_id = Column(Integer, nullable=False, index=True)
    satellite_name = Column(String(255), nullable=False)
    
    aos_time = Column(DateTime(timezone=True), nullable=False, index=True)
    max_elevation_time = Column(DateTime(timezone=True), nullable=False)
    los_time = Column(DateTime(timezone=True), nullable=False)
    max_elevation = Column(Float, nullable=False)
    
    ground_station_lat = Column(Float, nullable=False)
    ground_station_lon = Column(Float, nullable=False)
    ground_station_alt = Column(Float, default=0)
    
    calculated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IQRecording(Base):
    __tablename__ = "iq_recordings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    filename = Column(String(255), nullable=False, unique=True)
    file_path = Column(String(1024), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    
    satellite_name = Column(String(255))
    norad_id = Column(Integer, index=True)
    center_frequency = Column(BigInteger, nullable=False)
    sample_rate = Column(Integer, nullable=False)
    duration = Column(Float)
    
    iq_metadata = Column(JSONB, default=dict)
    
    recorded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    mission_id = Column(UUID(as_uuid=True), ForeignKey("missions.id"))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))
    resource_id = Column(UUID(as_uuid=True))
    details = Column(JSONB, default=dict)
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    
    user = relationship("User", back_populates="audit_logs")


class SatelliteProtocol(Base):
    __tablename__ = "satellite_protocols"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    satellite_name = Column(String(255), nullable=False)
    norad_id = Column(Integer, nullable=False, index=True)
    protocol_type = Column(String(50), nullable=False)
    frequency = Column(Float)
    modulation = Column(String(50))
    baud_rate = Column(Integer)
    
    decoder_module = Column(String(255))
    packet_structure = Column(JSONB)
    telemetry_definitions = Column(JSONB)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))


class AgentStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISCONNECTED = "disconnected"
    COMPROMISED = "compromised"


class AgentType(str, enum.Enum):
    COMPUTER = "computer"
    SATELLITE = "satellite"
    GROUND_STATION = "ground_station"


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class C2Agent(Base):
    __tablename__ = "c2_agents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    agent_id = Column(String(64), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    agent_type = Column(Enum(AgentType), nullable=False, default=AgentType.COMPUTER)
    status = Column(Enum(AgentStatus), nullable=False, default=AgentStatus.ACTIVE)
    
    platform = Column(String(50))
    architecture = Column(String(50))
    username = Column(String(255))
    domain = Column(String(255))
    integrity_level = Column(String(50))
    process_id = Column(Integer)
    process_name = Column(String(255))
    
    internal_ip = Column(String(45))
    external_ip = Column(String(45))
    callback_address = Column(String(255))
    beacon_interval = Column(Integer, default=60)
    jitter = Column(Integer, default=10)
    
    norad_id = Column(Integer, index=True)
    satellite_name = Column(String(255))
    ground_station_name = Column(String(255))
    
    agent_metadata = Column(JSONB, default=dict)
    
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    deployed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    tasks = relationship("C2Task", back_populates="agent", cascade="all, delete-orphan")


class C2Task(Base):
    __tablename__ = "c2_tasks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("c2_agents.id"), nullable=False, index=True)
    task_id = Column(String(64), unique=True, nullable=False, index=True)
    
    command = Column(Text, nullable=False)
    task_type = Column(String(50), nullable=False)
    status = Column(Enum(TaskStatus), nullable=False, default=TaskStatus.PENDING)
    
    arguments = Column(JSONB, default=dict)
    result = Column(Text)
    error_message = Column(Text)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    sent_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    agent = relationship("C2Agent", back_populates="tasks")


class SatelliteTask(Base):
    __tablename__ = "satellite_tasks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    norad_id = Column(Integer, nullable=False, index=True)
    satellite_name = Column(String(255), nullable=False)
    
    task_type = Column(String(50), nullable=False)
    command = Column(Text, nullable=False)
    status = Column(Enum(TaskStatus), nullable=False, default=TaskStatus.PENDING)
    
    uplink_frequency = Column(Float)
    downlink_frequency = Column(Float)
    modulation = Column(String(50))
    
    scheduled_execution = Column(DateTime(timezone=True))
    aos_time = Column(DateTime(timezone=True))
    los_time = Column(DateTime(timezone=True))
    
    payload = Column(JSONB)
    telemetry_response = Column(JSONB)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    executed_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))


class GroundStation(Base):
    __tablename__ = "ground_stations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    location_name = Column(String(255))
    
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    altitude = Column(Float, default=0)
    
    antenna_type = Column(String(100))
    antenna_azimuth = Column(Float)
    antenna_elevation = Column(Float)
    
    sdr_hardware = Column(JSONB, default=list)
    frequency_range_min = Column(Float)
    frequency_range_max = Column(Float)
    
    capabilities = Column(JSONB, default=list)
    status = Column(String(50), default="operational")
    
    tracking_satellites = Column(JSONB, default=list)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))
    
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
