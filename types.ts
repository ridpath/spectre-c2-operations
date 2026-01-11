
export enum AuthMethod {
  BASIC = 'Basic',
  NTLM = 'NTLM',
  KERBEROS = 'Kerberos',
  CERTIFICATE = 'Certificate'
}

export type ModuleCategory = 'Initial Access' | 'Recon' | 'Exploitation' | 'Post-Ex' | 'Persistence' | 'Evasion' | 'Exfiltration' | 'Deception' | 'Vector Testing' | 'Orbital SIGINT';

// --- CELESTIAL BREACH PROTOCOL TYPES ---

export type DspEngine = 'CPU' | 'FPGA' | 'RFNoC';
export type ModulationType = 'BPSK' | 'QPSK' | 'GFSK' | 'OOK' | '8PSK' | 'Unknown';

export interface DPIFrame {
  timestamp: Date;
  scid: number;
  vcid: number;
  frameCount: number;
  status: 'authenticated' | 'anomaly' | 'unencrypted';
  parsedData: Record<string, any>;
  modulationAI?: ModulationType;
}

export interface DopplerData {
  shift: number;
  rate: number;
  drift: number;
}

export interface AntennaState {
  azimuth: number;
  elevation: number;
  status: 'tracking' | 'homing' | 'parked' | 'error';
  rotctld_status: 'connected' | 'offline';
  servo_lock: boolean;
}

export interface CCSDSPacket {
  version: number;
  type: 'TC' | 'TM';
  secondaryHeader: boolean;
  apid: number; 
  sequenceFlags: number;
  sequenceCount: number;
  dataLength: number;
  payload: string;
  crc: string;
}

export interface SatelliteSubsystem {
  id: string;
  name: string;
  status: 'nominal' | 'degraded' | 'critical' | 'fuzzed' | 'offline';
  load: number;
  telemetry: Record<string, string | number>;
  isSpoofed?: boolean;
}

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
  doppler?: DopplerData;
  dspMode?: DspEngine;
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
  type: 'hash' | 'credential' | 'screenshot' | 'file' | 'iq';
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

export type ProtocolType = 'CCSDS' | 'DVB-S2' | 'AX.25' | 'LRPT' | 'APT' | 'SSTV';
export type ExploitChainType = 'cubesat_takeover' | 'weather_sat_hijack' | 'comsat_denial' | 'amateur_sat_beacon_spoof' | 'military_sat_recon';
export type CryptoAttackType = 'known-plaintext' | 'timing' | 'brute-force' | 'differential' | 'side-channel';
export type FirmwareArch = 'ARM' | 'AVR' | 'SPARC' | 'MIPS' | 'x86' | 'PowerPC';

export interface ProtocolEngine {
  id: string;
  name: string;
  protocols: string[];
  capabilities: string[];
  supported: boolean;
}

export interface ExploitChain {
  id: string;
  name: string;
  target_type: 'cubesat' | 'weather' | 'comsat' | 'military' | 'amateur';
  steps: ExploitStep[];
  opsec_risk: 'low' | 'medium' | 'high' | 'extreme';
  estimated_duration: number;
  success_rate: number;
  legal_warning?: string;
}

export interface ExploitStep {
  action: string;
  duration?: number;
  power?: string;
  payload?: string;
}

export interface SatelliteCVE {
  id: string;
  cve_id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  affected_models: string[];
  affected_protocols?: string[];
  exploit_available: boolean;
  exploit_module?: string;
}

export interface FirmwareAnalysis {
  id: string;
  filename: string;
  hash: string;
  size: number;
  architecture?: FirmwareArch;
  entry_point?: string;
  functions_count?: number;
  strings_count?: number;
  vulnerabilities: FirmwareVulnerability[];
  crypto_keys?: string[];
  status: 'pending' | 'analyzing' | 'completed' | 'failed';
}

export interface FirmwareVulnerability {
  type: 'hardcoded_credential' | 'buffer_overflow' | 'command_injection' | 'weak_crypto' | 'backdoor';
  severity: 'low' | 'medium' | 'high' | 'critical';
  offset?: number;
  description: string;
}

export interface CryptoAttack {
  id: string;
  name: string;
  type: CryptoAttackType;
  difficulty: 'easy' | 'medium' | 'hard' | 'extreme';
  gpu_required: boolean;
  estimated_time: string;
  description: string;
}

export interface LinkBudgetParams {
  frequency_hz: number;
  distance_km: number;
  tx_power_dbm: number;
  tx_antenna_gain_dbi: number;
  rx_antenna_gain_dbi: number;
  system_noise_temp_k: number;
  atmospheric_loss_db?: number;
  rain_loss_db?: number;
}

export interface LinkBudgetResult {
  fspl_db: number;
  total_loss_db: number;
  received_power_dbm: number;
  snr_db: number;
  margin_db: number;
  link_viable: boolean;
}

export interface MeshRoute {
  source_sat_id: string;
  dest_sat_id: string;
  hops: string[];
  latency_ms: number;
  bandwidth_mbps: number;
  reliability_score: number;
}

export interface GroundStationProfile {
  id: string;
  name: string;
  operator: string;
  location: {
    lat: number;
    lon: number;
    elevation_m?: number;
  };
  uplink_freq_hz: number;
  downlink_freq_hz: number;
  eirp_dbw: number;
  antenna_diameter_m?: number;
  protocols: string[];
  modulation: string;
  coding?: string;
  timing_precision_ns?: number;
  rf_fingerprint?: Record<string, any>;
}

export interface ReplayBuffer {
  id: string;
  name: string;
  center_freq: number;
  sample_rate: number;
  duration_seconds: number;
  samples_count: number;
  recorded_at: Date;
  metadata: {
    satellite_id?: string;
    signal_type?: string;
    snr?: number;
  };
}

export interface AutonomousHuntSession {
  id: string;
  status: 'idle' | 'scanning' | 'correlating' | 'exploiting' | 'completed' | 'failed';
  freq_range: {
    start_hz: number;
    end_hz: number;
  };
  discovered_satellites: number;
  vulnerable_satellites: number;
  exploited_satellites: number;
  start_time: Date;
  end_time?: Date;
  progress: number;
}

export interface DiscoveredSatellite {
  freq_hz: number;
  modulation: ModulationType;
  protocol?: ProtocolType;
  norad_id?: number;
  designation?: string;
  snr_db: number;
  vulnerabilities: string[];
}

export interface DVBS2Packet {
  modcod: string;
  fec_rate: string;
  pilot_symbols: boolean;
  payload: string;
}

export interface AX25Frame {
  source_callsign: string;
  dest_callsign: string;
  frame_type: 'UI' | 'I' | 'SABM';
  payload: string;
}

export interface LRPTFrame {
  timestamp: Date;
  frame_number: number;
  vcid: number;
  image_data?: string;
  telemetry?: Record<string, any>;
}
