
import { OffensiveModule, DropperTemplate, PentestTool, APTChain, OrbitalAsset, RFProfile } from './types';

export const RF_REGISTRY: RFProfile[] = [
  { id: 'rf-noaa', name: 'NOAA-15 HRPT', frequency: '137.620 MHz', bandwidth: '34 kHz', modulation: 'QPSK', noiseFloor: -110, iqSignature: 'noaa_hrpt_iq' },
  { id: 'rf-iridium', name: 'Iridium-Next L-Band', frequency: '1.616 GHz', bandwidth: '1.25 MHz', modulation: 'DE-QPSK', noiseFloor: -125, iqSignature: 'iridium_burst_iq' },
  { id: 'rf-starlink', name: 'Starlink Ku-Down', frequency: '11.7 GHz', bandwidth: '250 MHz', modulation: '64QAM', noiseFloor: -95, iqSignature: 'sl_phased_array_iq' },
  { id: 'rf-gs-nasa', name: 'NASA Deep Space Mimic', frequency: '2.2 GHz', bandwidth: '10 MHz', modulation: 'BPSK', noiseFloor: -115, iqSignature: 'nasa_uplink_sig', isGroundStationMimic: true },
  { id: 'rf-gs-esa', name: 'ESA Estrack Mimic', frequency: '8.4 GHz', bandwidth: '5 MHz', modulation: 'PCM/PSK/PM', noiseFloor: -140, iqSignature: 'esa_ka_band_sig', isGroundStationMimic: true }
];

export const ORBITAL_ASSETS: OrbitalAsset[] = [
  {
    id: 'sat-leo-01',
    designation: 'STERN-WATCH-4',
    noradId: 43105,
    type: 'LEO',
    inclination: 97.4,
    altitude: 540,
    snr: 42,
    status: 'tracking',
    currentOperator: 'Spectre-Lead',
    protocols: ['CCSDS', 'SpaceWire', 'X-Band'],
    coords: { lat: 37.7749, lng: -122.4194, alt: 540.2, velocity: 7.6 },
    tle: {
      line1: '1 43105U 18004A   24020.12345678  .00000123  00000-0  12345-4 0  9991',
      line2: '2 43105  97.4123 123.4567 0001234 123.4567 123.4567 15.12345678 12345',
      epoch: '2024-01-20T12:00:00Z'
    },
    subsystems: [
      { id: 'eps', name: 'EPS (Power)', status: 'nominal', load: 45, telemetry: { v_bus: '28.2V', i_draw: '1.4A', batt_temp: '22C', discharge_rate: '0.2%/min' } },
      { id: 'aocs', name: 'AOCS (Attitude)', status: 'nominal', load: 12, telemetry: { roll: '0.12', pitch: '-0.04', yaw: '0.01', momentum_wheel: '2400RPM' } },
      { id: 'comms', name: 'COMMS Relay', status: 'degraded', load: 88, telemetry: { bit_error_rate: '1.2e-5', buffer_fill: '92%', x_band_power: '42dBm' } },
      { id: 'thermal', name: 'Thermal Mgmt', status: 'nominal', load: 22, telemetry: { radiator_temp: '-12C', cpu_temp: '34C' } }
    ],
    rfProfile: RF_REGISTRY[0]
  },
  {
    id: 'sat-leo-iridium',
    designation: 'Iridium-Next-142',
    noradId: 43569,
    type: 'LEO',
    inclination: 86.4,
    altitude: 780,
    snr: 65,
    status: 'auto-tracking',
    protocols: ['L-Band', 'ISL', 'CCSDS'],
    coords: { lat: 51.5074, lng: -0.1278, alt: 781.4, velocity: 7.4 },
    tle: {
      line1: '1 43569U 18059A   24020.12345678  .00000123  00000-0  12345-4 0  9991',
      line2: '2 43569  86.4123 123.4567 0001234 123.4567 123.4567 14.12345678 12345',
      epoch: '2024-01-20T12:00:00Z'
    },
    subsystems: [
      { id: 'eps', name: 'EPS (Power)', status: 'nominal', load: 30, telemetry: { v_bus: '32V', i_draw: '0.8A' } },
      { id: 'payload', name: 'Cross-Link Ant', status: 'nominal', load: 5, telemetry: { peer_sat: 'Iridium-141', link_quality: '98%' } }
    ],
    rfProfile: RF_REGISTRY[1]
  }
];

export const APT_TACTICAL_CHAINS: APTChain[] = [
  {
    id: 'chain-shadow-mesh',
    name: 'Distributed Signal Proxy Mesh',
    description: 'Establishes a resilient P2P SMB mesh to channel exfiltration through low-noise egress nodes.',
    threatActorMimicry: 'Multi-Protocol Evasion Pattern',
    status: 'Idle',
    heatLevel: 15,
    steps: [
      { id: 's1', name: 'Environment Fingerprinting', command: 'check-env --detailed', delay: 2000, opsecRisk: 'Low', requiredIntegrity: 'User' },
      { id: 's2', name: 'Inter-Node Linkage', command: 'mesh-connect --peer DC01 --protocol smb_named_pipe', delay: 5000, opsecRisk: 'Medium', requiredIntegrity: 'User' },
      { id: 's3', name: 'Authorized Credential Retrieval', command: 'get-creds --method memory-scan', delay: 10000, opsecRisk: 'High', requiredIntegrity: 'Administrator' }
    ]
  }
];

export const OFFENSIVE_REGISTRY: OffensiveModule[] = [
  {
    id: 'orbital-ccsds-forge',
    name: 'CCSDS Protocol Forge',
    category: 'Orbital SIGINT',
    description: 'Construct and inject space packets for TC/TM manipulation.',
    opsecRisk: 'High',
    noiseLevel: 9,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'ccsds-inject --apid 0x3E5', description: 'Inject Telecommand Space Packet' },
      { trigger: 'ccsds-tm-spoof', description: 'Inject spoofed housekeeping telemetry' }
    ]
  },
  {
    id: 'orbital-relay-bounce',
    name: 'Quantum Relay Bounce',
    category: 'Orbital SIGINT',
    description: 'Bounce C2 signals across LEO assets to hide ground station geolocation.',
    opsecRisk: 'Low',
    noiseLevel: 2,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'relay-init --chain [43105,43569]', description: 'Initiate multi-hop orbital relay' }
    ]
  },
  {
    id: 'orbital-gs-mimic',
    name: 'GS Signature Mimicry',
    category: 'Orbital SIGINT',
    description: 'Simulates the RF footprint of authorized NASA or ESA ground stations.',
    opsecRisk: 'Low',
    noiseLevel: 1,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'gs-mimic --profile NASA_CANBERRA', description: 'Enable Ground Station fingerprint mimicry' }
    ]
  }
];

export const DROPPER_TEMPLATES: DropperTemplate[] = [
  {
    id: 'stager-orbital-aos',
    name: 'AOS-Locked Dead-Drop',
    format: 'shellcode',
    template: '0xDE, 0xAD, 0xBE, 0xEF...',
    description: 'A stager that remains dormant until Acquisition of Signal (AOS) from a specified NORAD target.',
    evasionLevel: 'Strategic',
    targetOS: 'Windows'
  }
];

export const PENTEST_TOOLS: PentestTool[] = [
  {
    id: 'ccsds-fuzzer',
    name: 'CCSDS Protocol Fuzzer',
    category: 'SIGINT',
    description: 'Automated bit-flipping and sequence entropy testing for space-data protocols.',
    rawUrl: 'internal://ccsds-fuzz',
    githubUrl: 'https://github.com/spectre/ccsds-fuzz',
    type: 'exe'
  }
];

export const DEFAULT_SNIPPETS = [
  {
    id: 'snip-1',
    title: 'Privilege Check',
    description: 'Check current user privileges and integrity level.',
    code: 'whoami /priv',
    category: 'Recon'
  },
  {
    id: 'snip-2',
    title: 'Domain Admins',
    description: 'List all members of the Domain Admins group.',
    code: 'net group "Domain Admins" /domain',
    category: 'Recon'
  }
];
