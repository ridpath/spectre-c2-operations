from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SatelliteType(str, Enum):
    CUBESAT = "cubesat"
    SMALLSAT = "smallsat"
    COMMERCIAL = "commercial"
    MILITARY = "military"
    WEATHER = "weather"
    COMMUNICATION = "communication"
    SCIENCE = "science"
    AMATEUR = "amateur"


class ModulationType(str, Enum):
    AFSK = "AFSK"
    FSK = "FSK"
    GMSK = "GMSK"
    BPSK = "BPSK"
    QPSK = "QPSK"
    OQPSK = "OQPSK"
    MSK = "MSK"
    FM = "FM"
    AM = "AM"


@dataclass
class FrequencyBand:
    downlink: float
    uplink: Optional[float]
    modulation: ModulationType
    bandwidth: int
    description: str


@dataclass
class SatelliteSpec:
    name: str
    norad_id: int
    satellite_type: SatelliteType
    frequencies: List[FrequencyBand]
    protocol: str
    baud_rate: Optional[int]
    description: str
    launched: Optional[str]
    status: str
    vulnerabilities: List[str]
    exploitation_notes: str


class SatelliteDatabase:
    def __init__(self):
        self.satellites: Dict[int, SatelliteSpec] = {}
        self._populate_database()
        
    def _populate_database(self):
        cubesats = [
            SatelliteSpec(
                name="FOX-1A (AO-85)",
                norad_id=40967,
                satellite_type=SatelliteType.AMATEUR,
                frequencies=[
                    FrequencyBand(
                        downlink=145.980,
                        uplink=435.180,
                        modulation=ModulationType.BPSK,
                        bandwidth=9600,
                        description="Telemetry downlink"
                    )
                ],
                protocol="AX.25",
                baud_rate=9600,
                description="AMSAT Fox-1A amateur radio satellite with telemetry and digipeater",
                launched="2015-10-08",
                status="operational",
                vulnerabilities=["Unencrypted telemetry", "Open command channel"],
                exploitation_notes="AX.25 frames can be decoded without authentication. Command uplink may be vulnerable to replay attacks."
            ),
            SatelliteSpec(
                name="NOAA-15",
                norad_id=25338,
                satellite_type=SatelliteType.WEATHER,
                frequencies=[
                    FrequencyBand(
                        downlink=137.620,
                        uplink=None,
                        modulation=ModulationType.FM,
                        bandwidth=40000,
                        description="APT weather imagery"
                    ),
                    FrequencyBand(
                        downlink=1702.5,
                        uplink=None,
                        modulation=ModulationType.QPSK,
                        bandwidth=665400,
                        description="HRPT high-resolution data"
                    )
                ],
                protocol="APT/HRPT",
                baud_rate=None,
                description="NOAA polar-orbiting weather satellite with APT and HRPT downlinks",
                launched="1998-05-13",
                status="operational",
                vulnerabilities=["No encryption on weather data"],
                exploitation_notes="APT signal is unencrypted analog FM. HRPT requires higher gain antenna but also unencrypted."
            ),
            SatelliteSpec(
                name="NOAA-18",
                norad_id=28654,
                satellite_type=SatelliteType.WEATHER,
                frequencies=[
                    FrequencyBand(
                        downlink=137.9125,
                        uplink=None,
                        modulation=ModulationType.FM,
                        bandwidth=40000,
                        description="APT weather imagery"
                    )
                ],
                protocol="APT",
                baud_rate=None,
                description="NOAA polar-orbiting weather satellite",
                launched="2005-05-20",
                status="operational",
                vulnerabilities=["Unencrypted weather imagery"],
                exploitation_notes="Standard APT receiver can decode images"
            ),
            SatelliteSpec(
                name="NOAA-19",
                norad_id=33591,
                satellite_type=SatelliteType.WEATHER,
                frequencies=[
                    FrequencyBand(
                        downlink=137.100,
                        uplink=None,
                        modulation=ModulationType.FM,
                        bandwidth=40000,
                        description="APT weather imagery"
                    )
                ],
                protocol="APT",
                baud_rate=None,
                description="NOAA polar-orbiting weather satellite",
                launched="2009-02-06",
                status="operational",
                vulnerabilities=["Unencrypted weather imagery"],
                exploitation_notes="Standard APT receiver can decode images"
            ),
            SatelliteSpec(
                name="ISS (ZARYA)",
                norad_id=25544,
                satellite_type=SatelliteType.SCIENCE,
                frequencies=[
                    FrequencyBand(
                        downlink=145.800,
                        uplink=144.490,
                        modulation=ModulationType.FM,
                        bandwidth=25000,
                        description="Voice repeater"
                    ),
                    FrequencyBand(
                        downlink=437.800,
                        uplink=145.990,
                        modulation=ModulationType.AFSK,
                        bandwidth=1200,
                        description="APRS digipeater"
                    )
                ],
                protocol="FM/APRS",
                baud_rate=1200,
                description="International Space Station with amateur radio equipment",
                launched="1998-11-20",
                status="operational",
                vulnerabilities=["Open amateur radio repeater", "APRS digipeater accessible"],
                exploitation_notes="ISS amateur radio station accepts FM voice and APRS packets from ground stations with proper licensing."
            ),
            SatelliteSpec(
                name="METEOR-M2",
                norad_id=40069,
                satellite_type=SatelliteType.WEATHER,
                frequencies=[
                    FrequencyBand(
                        downlink=137.100,
                        uplink=None,
                        modulation=ModulationType.QPSK,
                        bandwidth=120000,
                        description="LRPT weather data"
                    )
                ],
                protocol="LRPT",
                baud_rate=72000,
                description="Russian weather satellite with LRPT downlink",
                launched="2014-07-08",
                status="operational",
                vulnerabilities=["Unencrypted LRPT imagery"],
                exploitation_notes="QPSK signal at 72k symbols/sec, decodable with SDR and gr-satellites"
            ),
            SatelliteSpec(
                name="LILACSAT-2",
                norad_id=40908,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=437.200,
                        uplink=144.390,
                        modulation=ModulationType.BPSK,
                        bandwidth=9600,
                        description="Telemetry and camera downlink"
                    )
                ],
                protocol="AX.25",
                baud_rate=9600,
                description="Chinese CubeSat with camera and telemetry",
                launched="2015-09-20",
                status="operational",
                vulnerabilities=["No command authentication", "Unencrypted telemetry"],
                exploitation_notes="AX.25 frames can be decoded. Command injection possible if proper authorization codes are discovered."
            ),
            SatelliteSpec(
                name="FUNCUBE-1 (AO-73)",
                norad_id=39444,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=145.935,
                        uplink=435.150,
                        modulation=ModulationType.BPSK,
                        bandwidth=1200,
                        description="Telemetry downlink"
                    )
                ],
                protocol="AX.25",
                baud_rate=1200,
                description="FUNcube amateur radio CubeSat with telemetry and educational transponder",
                launched="2013-11-21",
                status="operational",
                vulnerabilities=["Unencrypted telemetry beacon"],
                exploitation_notes="BPSK telemetry at 1200 baud, easily decoded with SDR"
            ),
            SatelliteSpec(
                name="OSCARS (Multiple)",
                norad_id=0,
                satellite_type=SatelliteType.AMATEUR,
                frequencies=[
                    FrequencyBand(
                        downlink=435.000,
                        uplink=145.000,
                        modulation=ModulationType.FM,
                        bandwidth=25000,
                        description="General amateur band"
                    )
                ],
                protocol="Various",
                baud_rate=None,
                description="OSCAR series amateur radio satellites",
                launched="Various",
                status="various",
                vulnerabilities=["Open access amateur satellites"],
                exploitation_notes="Multiple OSCAR satellites with varying protocols and frequencies"
            ),
            SatelliteSpec(
                name="AAUSAT-4",
                norad_id=41460,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=437.425,
                        uplink=145.930,
                        modulation=ModulationType.GMSK,
                        bandwidth=4800,
                        description="Telemetry downlink"
                    )
                ],
                protocol="Custom GMSK",
                baud_rate=4800,
                description="Aalborg University CubeSat with SDR payload",
                launched="2016-06-22",
                status="operational",
                vulnerabilities=["Unencrypted telemetry", "No command authentication"],
                exploitation_notes="GMSK telemetry at 4800 baud. Custom protocol requires reverse engineering."
            ),
            SatelliteSpec(
                name="GOMX-3",
                norad_id=40948,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=437.250,
                        uplink=145.980,
                        modulation=ModulationType.GMSK,
                        bandwidth=4800,
                        description="Telemetry and payload data"
                    )
                ],
                protocol="CSP/AX.25",
                baud_rate=4800,
                description="GomSpace 3U CubeSat with ADS-B receiver",
                launched="2015-10-05",
                status="operational",
                vulnerabilities=["CSP protocol vulnerabilities", "Weak error correction"],
                exploitation_notes="Uses CubeSat Space Protocol (CSP) over AX.25. Command injection possible."
            ),
            SatelliteSpec(
                name="DUCHIFAT-3",
                norad_id=44854,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=436.400,
                        uplink=145.970,
                        modulation=ModulationType.BPSK,
                        bandwidth=1200,
                        description="Telemetry beacon"
                    )
                ],
                protocol="AX.25",
                baud_rate=1200,
                description="Israeli educational CubeSat with camera",
                launched="2020-03-22",
                status="operational",
                vulnerabilities=["Unencrypted beacon", "Open repeater mode"],
                exploitation_notes="BPSK beacon at 1200 baud. Repeater mode allows signal injection."
            ),
            SatelliteSpec(
                name="NAYIF-1 (EO-88)",
                norad_id=42017,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=145.940,
                        uplink=435.015,
                        modulation=ModulationType.BPSK,
                        bandwidth=1200,
                        description="Linear transponder"
                    )
                ],
                protocol="FM/BPSK",
                baud_rate=1200,
                description="UAE amateur radio CubeSat with educational mission",
                launched="2017-02-15",
                status="operational",
                vulnerabilities=["Open transponder", "No uplink authentication"],
                exploitation_notes="Linear transponder allows any station to transmit. BPSK telemetry easily decoded."
            ),
            SatelliteSpec(
                name="SWIATOWID",
                norad_id=42701,
                satellite_type=SatelliteType.CUBESAT,
                frequencies=[
                    FrequencyBand(
                        downlink=435.500,
                        uplink=145.910,
                        modulation=ModulationType.GMSK,
                        bandwidth=9600,
                        description="High-speed telemetry"
                    )
                ],
                protocol="Custom",
                baud_rate=9600,
                description="Polish military observation CubeSat",
                launched="2017-05-18",
                status="operational",
                vulnerabilities=["Custom protocol without published specs", "Possible command injection"],
                exploitation_notes="High-speed GMSK. Protocol reverse engineering required for exploitation."
            )
        ]
        
        for sat in cubesats:
            if sat.norad_id > 0:
                self.satellites[sat.norad_id] = sat
    
    def get_satellite(self, norad_id: int) -> Optional[SatelliteSpec]:
        return self.satellites.get(norad_id)
    
    def search_by_name(self, name: str) -> List[SatelliteSpec]:
        name_lower = name.lower()
        return [
            sat for sat in self.satellites.values()
            if name_lower in sat.name.lower()
        ]
    
    def get_by_type(self, sat_type: SatelliteType) -> List[SatelliteSpec]:
        return [
            sat for sat in self.satellites.values()
            if sat.satellite_type == sat_type
        ]
    
    def get_vulnerable_satellites(self) -> List[SatelliteSpec]:
        return [
            sat for sat in self.satellites.values()
            if len(sat.vulnerabilities) > 0
        ]
    
    def get_all(self) -> List[SatelliteSpec]:
        return list(self.satellites.values())
    
    def to_dict(self, spec: SatelliteSpec) -> Dict[str, Any]:
        return {
            "name": spec.name,
            "norad_id": spec.norad_id,
            "type": spec.satellite_type.value,
            "frequencies": [
                {
                    "downlink": freq.downlink,
                    "uplink": freq.uplink,
                    "modulation": freq.modulation.value,
                    "bandwidth": freq.bandwidth,
                    "description": freq.description
                }
                for freq in spec.frequencies
            ],
            "protocol": spec.protocol,
            "baud_rate": spec.baud_rate,
            "description": spec.description,
            "launched": spec.launched,
            "status": spec.status,
            "vulnerabilities": spec.vulnerabilities,
            "exploitation_notes": spec.exploitation_notes
        }


satellite_db = SatelliteDatabase()
