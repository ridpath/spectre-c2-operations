import socket
import time
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from config import get_settings

settings = get_settings()


class RotatorStatus(str, Enum):
    IDLE = "idle"
    TRACKING = "tracking"
    MOVING = "moving"
    ERROR = "error"
    DISCONNECTED = "disconnected"


@dataclass
class RotatorPosition:
    azimuth: float
    elevation: float
    timestamp: float


class HamlibRotatorControl:
    def __init__(self, host: str = None, port: int = None):
        self.host = host or settings.ROTCTLD_HOST
        self.port = port or settings.ROTCTLD_PORT
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.current_position: Optional[RotatorPosition] = None
        self.target_position: Optional[RotatorPosition] = None
        self.status = RotatorStatus.DISCONNECTED
        
    def connect(self) -> bool:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5.0)
            self.socket.connect((self.host, self.port))
            
            self.socket.sendall(b"\\dump_caps\n")
            response = self.socket.recv(1024)
            
            if response:
                self.connected = True
                self.status = RotatorStatus.IDLE
                return True
            
            return False
            
        except Exception as e:
            print(f"Failed to connect to rotctld: {e}")
            self.status = RotatorStatus.DISCONNECTED
            self.connected = False
            return False
    
    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.connected = False
        self.status = RotatorStatus.DISCONNECTED
    
    def get_position(self) -> Optional[RotatorPosition]:
        if not self.connected:
            return None
        
        try:
            self.socket.sendall(b"p\n")
            
            response = self.socket.recv(1024).decode('utf-8').strip()
            
            lines = response.split('\n')
            if len(lines) >= 2:
                azimuth = float(lines[0])
                elevation = float(lines[1])
                
                self.current_position = RotatorPosition(
                    azimuth=azimuth,
                    elevation=elevation,
                    timestamp=time.time()
                )
                
                return self.current_position
            
            return None
            
        except Exception as e:
            print(f"Failed to get position: {e}")
            return None
    
    def set_position(self, azimuth: float, elevation: float) -> bool:
        if not self.connected:
            return False
        
        azimuth = max(0, min(360, azimuth))
        elevation = max(0, min(90, elevation))
        
        try:
            command = f"P {azimuth:.2f} {elevation:.2f}\n"
            self.socket.sendall(command.encode('utf-8'))
            
            response = self.socket.recv(1024).decode('utf-8').strip()
            
            if "RPRT 0" in response or response == "":
                self.target_position = RotatorPosition(
                    azimuth=azimuth,
                    elevation=elevation,
                    timestamp=time.time()
                )
                self.status = RotatorStatus.MOVING
                return True
            
            return False
            
        except Exception as e:
            print(f"Failed to set position: {e}")
            self.status = RotatorStatus.ERROR
            return False
    
    def stop(self) -> bool:
        if not self.connected:
            return False
        
        try:
            self.socket.sendall(b"S\n")
            
            response = self.socket.recv(1024).decode('utf-8').strip()
            
            if "RPRT 0" in response or response == "":
                self.status = RotatorStatus.IDLE
                return True
            
            return False
            
        except Exception as e:
            print(f"Failed to stop rotator: {e}")
            return False
    
    def park(self) -> bool:
        return self.set_position(0, 0)
    
    def is_on_target(self, tolerance: float = 2.0) -> bool:
        if not self.current_position or not self.target_position:
            return False
        
        az_diff = abs(self.current_position.azimuth - self.target_position.azimuth)
        el_diff = abs(self.current_position.elevation - self.target_position.elevation)
        
        if az_diff > 180:
            az_diff = 360 - az_diff
        
        return az_diff <= tolerance and el_diff <= tolerance
    
    def get_info(self) -> dict:
        return {
            "connected": self.connected,
            "status": self.status.value,
            "host": self.host,
            "port": self.port,
            "current_position": {
                "azimuth": self.current_position.azimuth if self.current_position else 0,
                "elevation": self.current_position.elevation if self.current_position else 0,
                "timestamp": self.current_position.timestamp if self.current_position else 0
            } if self.current_position else None,
            "target_position": {
                "azimuth": self.target_position.azimuth if self.target_position else 0,
                "elevation": self.target_position.elevation if self.target_position else 0
            } if self.target_position else None,
            "on_target": self.is_on_target() if self.connected else False
        }


class AntennaTracker:
    def __init__(self, rotator: HamlibRotatorControl):
        self.rotator = rotator
        self.tracking_active = False
        self.tracking_target: Optional[str] = None
        
    def start_tracking(self, satellite_name: str) -> bool:
        if not self.rotator.connected:
            return False
        
        self.tracking_active = True
        self.tracking_target = satellite_name
        self.rotator.status = RotatorStatus.TRACKING
        return True
    
    def stop_tracking(self):
        self.tracking_active = False
        self.tracking_target = None
        if self.rotator.connected:
            self.rotator.status = RotatorStatus.IDLE
    
    def update_position(self, azimuth: float, elevation: float) -> bool:
        if not self.tracking_active or not self.rotator.connected:
            return False
        
        if elevation < 0:
            return False
        
        return self.rotator.set_position(azimuth, elevation)
    
    def get_tracking_info(self) -> dict:
        rotator_info = self.rotator.get_info()
        return {
            **rotator_info,
            "tracking_active": self.tracking_active,
            "tracking_target": self.tracking_target
        }


hamlib_rotator = HamlibRotatorControl()
antenna_tracker = AntennaTracker(hamlib_rotator)
