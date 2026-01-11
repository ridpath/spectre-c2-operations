import struct
from typing import Optional, Dict, Any, List
from construct import Struct, Int8ub, Int16ub, Bytes, this


class AX25Decoder:
    FLAG = 0x7E
    
    def __init__(self):
        self.buffer = bytearray()
        
    def decode_frame(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 15:
            return None
        
        try:
            dest_callsign = self._decode_callsign(data[0:7])
            src_callsign = self._decode_callsign(data[7:14])
            
            control = data[14]
            pid = data[15] if len(data) > 15 else 0
            
            info_start = 16
            info_data = data[info_start:-2] if len(data) > info_start + 2 else b""
            
            frame_crc = struct.unpack("<H", data[-2:])[0] if len(data) >= 2 else 0
            calculated_crc = self._calculate_crc(data[:-2])
            
            return {
                "destination": dest_callsign,
                "source": src_callsign,
                "control": control,
                "pid": pid,
                "info": info_data.decode("ascii", errors="ignore"),
                "crc": frame_crc,
                "crc_valid": frame_crc == calculated_crc,
                "raw": data.hex()
            }
        except Exception as e:
            return {"error": str(e), "raw": data.hex()}
    
    def _decode_callsign(self, data: bytes) -> str:
        callsign = ""
        for i in range(6):
            char = (data[i] >> 1) & 0x7F
            if char != 0x20:
                callsign += chr(char)
        
        ssid = (data[6] >> 1) & 0x0F
        if ssid > 0:
            callsign += f"-{ssid}"
        
        return callsign.strip()
    
    def _calculate_crc(self, data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
        return crc ^ 0xFFFF


class CCSDSParser:
    def __init__(self):
        self.packet_header = Struct(
            "version" / Int8ub,
            "apid" / Int16ub,
            "sequence_flags" / Int8ub,
            "packet_length" / Int16ub
        )
    
    def parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 6:
            return None
        
        try:
            byte0 = data[0]
            version = (byte0 >> 5) & 0x07
            packet_type = (byte0 >> 4) & 0x01
            secondary_header_flag = (byte0 >> 3) & 0x01
            apid = ((byte0 & 0x07) << 8) | data[1]
            
            byte2 = data[2]
            sequence_flags = (byte2 >> 6) & 0x03
            sequence_count = ((byte2 & 0x3F) << 8) | data[3]
            
            packet_length = (data[4] << 8) | data[5]
            
            payload_start = 6
            if secondary_header_flag:
                payload_start += 10
            
            payload = data[payload_start:payload_start + packet_length + 1]
            
            return {
                "version": version,
                "packet_type": "TM" if packet_type == 0 else "TC",
                "secondary_header_flag": bool(secondary_header_flag),
                "apid": apid,
                "sequence_flags": sequence_flags,
                "sequence_count": sequence_count,
                "packet_length": packet_length,
                "payload": payload.hex(),
                "raw": data.hex()
            }
        except Exception as e:
            return {"error": str(e), "raw": data.hex()}
    
    def forge_packet(self, apid: int, payload: bytes, sequence_count: int = 0) -> bytes:
        byte0 = (0 << 5) | (1 << 4) | ((apid >> 8) & 0x07)
        byte1 = apid & 0xFF
        
        byte2 = (3 << 6) | ((sequence_count >> 8) & 0x3F)
        byte3 = sequence_count & 0xFF
        
        packet_length = len(payload) - 1
        byte4 = (packet_length >> 8) & 0xFF
        byte5 = packet_length & 0xFF
        
        packet = bytes([byte0, byte1, byte2, byte3, byte4, byte5]) + payload
        
        crc = self._calculate_crc(packet)
        packet += struct.pack(">H", crc)
        
        return packet
    
    def _calculate_crc(self, data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return crc


class TelemetryDecoder:
    def __init__(self, satellite_name: str):
        self.satellite_name = satellite_name
        self.definitions = self._load_definitions()
    
    def _load_definitions(self) -> Dict[str, Any]:
        default_definitions = {
            "default": {
                "frequency": 437.5e6,
                "modulation": "BPSK",
                "baud_rate": 9600,
                "packet_format": "ax25",
                "telemetry_points": {
                    "bat_voltage": {"offset": 0, "scale": 0.01, "unit": "V"},
                    "bat_current": {"offset": 2, "scale": 0.001, "unit": "A"},
                    "solar_voltage": {"offset": 4, "scale": 0.01, "unit": "V"},
                    "temp_eps": {"offset": 6, "scale": 0.1, "unit": "C"},
                    "temp_obc": {"offset": 8, "scale": 0.1, "unit": "C"}
                }
            }
        }
        
        return default_definitions.get(self.satellite_name, default_definitions["default"])
    
    def decode_telemetry(self, packet_data: bytes) -> Dict[str, Any]:
        telemetry = {}
        
        for name, definition in self.definitions.get("telemetry_points", {}).items():
            try:
                offset = definition["offset"]
                scale = definition["scale"]
                unit = definition["unit"]
                
                if offset + 2 <= len(packet_data):
                    raw_value = struct.unpack(">H", packet_data[offset:offset+2])[0]
                    scaled_value = raw_value * scale
                    
                    telemetry[name] = {
                        "value": scaled_value,
                        "unit": unit,
                        "raw": raw_value
                    }
            except Exception:
                pass
        
        return telemetry


class ProtocolPlugin:
    def __init__(self, name: str):
        self.name = name
        self.decoder = None
        
    def load(self):
        pass
    
    def decode(self, data: bytes) -> Optional[Dict[str, Any]]:
        return None


ax25_decoder = AX25Decoder()
ccsds_parser = CCSDSParser()
