
export enum AuthMethod {
  BASIC = 'Basic',
  NTLM = 'NTLM',
  KERBEROS = 'Kerberos',
  CERTIFICATE = 'Certificate'
}

export type ModuleCategory = 'Initial Access' | 'Recon' | 'Exploitation' | 'Post-Ex' | 'Persistence' | 'Evasion' | 'Exfiltration' | 'Deception' | 'Vector Testing' | 'Orbital SIGINT';

// --- CELESTIAL BREACH PROTOCOL TYPES ---

/**
 * CCSDSPacket: Represents a standard Consultative Committee for Space Data Systems packet.
 */
export interface CCSDSPacket {
  version: number;
  type: 'TC' | 'TM';
  secondaryHeader: boolean;
  apid: number; 
  sequenceFlags: number;
  sequenceCount: number;
  dataLength: number;
  payload: string; // Hex-encoded string
  crc: string; // Hex-encoded 16-bit CRC
}

/**
 * SatelliteSubsystem: Hardware monitoring for LEO/GEO assets.
 */
export interface SatelliteSubsystem {
  id: string;
  name: string;
  status: 'nominal' | 'degraded' | 'critical' | 'fuzzed' | 'offline';
  load: number; // 0-100 percentage
  telemetry: Record<string, string | number>;
  isSpoofed?: boolean;
}

/**
 * RFProfile: Spectrum footprint data.
 */
export interface RFProfile {
  id: string;
  name: string; 
  frequency: string;
  bandwidth: string;
  modulation: string;
  noiseFloor: number;
  iqSignature: string; 
  isGroundStationMimic?: boolean;
}

export interface TLEData {
  line1: string;
  line2: string;
  epoch: string;
}

export interface AOSWindow {
  id: string;
  startTime: Date;
  endTime: Date;
  maxElevation: number;
  isCurrent: boolean;
}

export interface OrbitalRelayHop {
  id: string;
  assetId: string;
  latency: number;
  snr: number;
  uplinkFreq: string;
  downlinkFreq: string;
}

// --- END CELESTIAL BREACH ---

export interface TacticalStep {
  id: string;
  name: string;
  command: string;
  delay: number;
  opsecRisk: 'Low' | 'Medium' | 'High';
  requiredIntegrity: 'User' | 'Administrator' | 'SYSTEM';
}

export interface APTChain {
  id: string;
  name: string;
  description: string;
  threatActorMimicry?: string;
  steps: TacticalStep[];
  status: 'Idle' | 'Active' | 'Success' | 'Compromised';
  heatLevel: number;
}

export interface OrbitalCoordinates {
  lat: number;
  lng: number;
  alt: number;
  velocity: number;
}

/**
 * OrbitalAsset: Primary data model for target satellites.
 */
export interface OrbitalAsset {
  id: string;
  designation: string;
  noradId: number;
  type: 'LEO' | 'MEO' | 'GEO';
  inclination: number;
  altitude: number;
  snr: number;
  status: 'tracking' | 'intercepting' | 'synced' | 'searching' | 'auto-tracking';
  currentOperator?: string;
  protocols: string[];
  coords: OrbitalCoordinates;
  tle: TLEData;
  subsystems: SatelliteSubsystem[];
  rfProfile?: RFProfile;
}

export interface AutonomousRule {
  id: string;
  trigger: 'SignalLoss' | 'EDRAlert' | 'Idle' | 'IntegrityChange' | 'MemoryScanDetected';
  action: 'Migrate' | 'SelfTerminate' | 'Sleep' | 'WipeLogs' | 'ReEncryptHeap';
  params: Record<string, any>;
}

export interface WinRMConnection {
  id: string;
  host: string;
  port: number;
  username: string;
  password?: string;
  useSsl: boolean;
  authMethod: AuthMethod;
  status: 'connected' | 'disconnected' | 'error' | 'connecting';
  lastSeen?: Date;
  agentType?: string;
  isPivot?: boolean;
  parentId?: string;
  capabilities: string[];
  integrityLevel?: 'User' | 'Administrator' | 'SYSTEM';
  processName?: string;
  arch?: 'x64' | 'x86';
  entropy: number;
  autonomousRules: AutonomousRule[];
  spectrumMimicry: 'Standard' | 'Office365' | 'AWS' | 'GitHub' | 'Slack' | 'Vectorized';
  stealthMode: 'Normal' | 'Heapless' | 'Phantom';
}

export interface C2Task {
  id: string;
  targetId: string;
  command: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  output?: string;
  timestamp: Date;
  opsecRisk?: 'low' | 'medium' | 'high';
  operatorAlias: string;
}

export interface C2Listener {
  id: string;
  name: string;
  type: 'http' | 'smb_pipe' | 'external' | 'dns' | 'spectrum' | 'phantom-vector';
  lhost: string;
  lport: number;
  active: boolean;
  profiles: string[];
}

export interface SecurityConfig {
  isAuthEnabled: boolean;
  mfaRequired: boolean;
  sessionTimeout: number;
  opsecThreshold: number;
}

export interface Operator {
  id: string;
  alias: string;
  role: 'ADMIN' | 'OPERATOR';
  status: 'active' | 'inactive';
  lastSeen: Date;
}

export interface QuantumForgeConfig {
  obfuscation: 'quantum-random' | 'polymorphic' | 'none';
  heapStealth: boolean;
  amsiBypass: boolean;
  etwPatching: boolean;
  indirectSyscalls: boolean;
  stackSpoofing: boolean;
  executionMode: 'reflective' | 'demon-stream' | 'direct-syscall' | 'heapless-isolation';
  vectorChannel?: 'standard' | 'fragmented' | 'multiplexed';
}

export interface OffensiveModule {
  id: string;
  name: string;
  category: ModuleCategory;
  description: string;
  opsecRisk: 'Low' | 'Medium' | 'High';
  noiseLevel: number;
  requiredIntegrity: 'User' | 'Administrator' | 'SYSTEM';
  author: string;
  commands: { trigger: string; description: string }[];
}

export type PayloadFormat = 'shellcode' | 'exe' | 'dll' | 'service-exe' | 'powershell' | 'hta' | 'lnk' | 'iso';

export interface DropperTemplate {
  id: string;
  name: string;
  format: PayloadFormat;
  template: string;
  description: string;
  evasionLevel: string;
  targetOS: string;
}

export interface PentestTool {
  id: string;
  name: string;
  category: string;
  description: string;
  rawUrl: string;
  githubUrl: string;
  type: 'ps1' | 'exe' | 'reflective_dll';
}

export interface TerminalLine {
  id: string;
  type: 'input' | 'output' | 'error' | 'system';
  content: string;
  timestamp: Date;
}

export interface LootItem {
  id: string;
  type: 'hash' | 'credential' | 'screenshot' | 'file';
  targetId: string;
  content: string;
  metadata: Record<string, any>;
  timestamp: Date;
  verified: boolean;
  capturedBy: string;
}

export interface LigoloTunnel {
  id: string;
  agentId: string;
  remoteAddress: string;
  interfaceName: string;
  status: 'active' | 'inactive';
  rxBytes: number;
  txBytes: number;
  routes: string[];
}

export interface ExploitModule {
  id: string;
  name: string;
  cve: string;
  platform: string;
  rank: 'excellent' | 'great' | 'good' | 'average' | 'low' | 'manual';
  description: string;
  options: Record<string, string | number | boolean>;
}

export interface C2Profile {
  id: string;
  name: string;
  userAgent: string;
  uriPatterns: string[];
  headers: Record<string, string>;
  jitter: number;
  sleep: number;
  allocator: string;
}
