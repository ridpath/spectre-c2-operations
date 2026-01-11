from pydantic import BaseModel, EmailStr, Field, UUID4
from typing import Optional, List, Dict, Any
from datetime import datetime


class UserLogin(BaseModel):
    username: str
    password: str


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    role: Optional[str] = "operator"


class UserResponse(BaseModel):
    id: UUID4
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class MissionCreateRequest(BaseModel):
    name: str
    target_satellite: str
    target_norad_id: int
    objective: str
    authorization: Dict[str, Any]


class MissionUpdateRequest(BaseModel):
    status: Optional[str] = None
    attack_chain: Optional[List[Dict[str, Any]]] = None
    evidence: Optional[List[str]] = None


class EvidenceCreateRequest(BaseModel):
    mission_id: UUID4
    category: str
    description: str
    data: str
    metadata: Dict[str, Any] = {}
    tags: List[str] = []
    satellite_name: Optional[str] = None
    frequency: Optional[float] = None
    signal_strength: Optional[float] = None


class VulnerabilityScanRequest(BaseModel):
    norad_id: int
    satellite_name: str


class ReportGenerateRequest(BaseModel):
    mission_id: UUID4
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


class TemplateCreateRequest(BaseModel):
    name: str
    category: str
    template: str
    params: Dict[str, Any]
    risk: str
    description: str
    requirements: List[str]
    example: str


class PlaybookExecutionRequest(BaseModel):
    playbook_id: UUID4
    mission_id: Optional[UUID4] = None


class StepExecutionRequest(BaseModel):
    step_id: UUID4
    playbook_id: UUID4
    mission_id: Optional[UUID4] = None
