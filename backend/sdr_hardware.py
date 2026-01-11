import numpy as np
from scipy import signal
from typing import Optional, List, Tuple
from config import get_settings
import asyncio

settings = get_settings()


class SDRDevice:
    def __init__(self, device_type: str, device_index: int = 0):
        self.device_type = device_type
        self.device_index = device_index
        self.is_streaming = False
        self.center_frequency = settings.SDR_CENTER_FREQ
        self.sample_rate = settings.SDR_SAMPLE_RATE
        self.gain = settings.SDR_GAIN
        
    async def start(self):
        self.is_streaming = True
        
    async def stop(self):
        self.is_streaming = False
        
    async def read_samples(self, num_samples: int) -> np.ndarray:
        return np.random.randn(num_samples) + 1j * np.random.randn(num_samples)


class RTLSDRDevice(SDRDevice):
    def __init__(self, device_index: int = 0):
        super().__init__("RTL-SDR", device_index)
        self.sdr = None
        
    async def start(self):
        if not settings.ENABLE_SDR_HARDWARE:
            return
        
        try:
            from rtlsdr import RtlSdr
            self.sdr = RtlSdr(device_index=self.device_index)
            self.sdr.sample_rate = self.sample_rate
            self.sdr.center_freq = self.center_frequency
            self.sdr.gain = self.gain if isinstance(self.gain, (int, float)) else 'auto'
            self.is_streaming = True
        except Exception as e:
            print(f"RTL-SDR initialization error: {e}")
            self.sdr = None
            
    async def stop(self):
        if self.sdr:
            try:
                self.sdr.close()
            except:
                pass
        self.is_streaming = False
        self.sdr = None
        
    async def read_samples(self, num_samples: int = 1024) -> np.ndarray:
        if self.sdr and settings.ENABLE_SDR_HARDWARE:
            try:
                samples = self.sdr.read_samples(num_samples)
                return np.array(samples)
            except:
                pass
        
        return np.random.randn(num_samples) + 1j * np.random.randn(num_samples)


class HackRFDevice(SDRDevice):
    def __init__(self, device_index: int = 0):
        super().__init__("HackRF", device_index)
        self.device = None
        
    async def start(self):
        if not settings.ENABLE_SDR_HARDWARE:
            return
        self.is_streaming = True
        
    async def read_samples(self, num_samples: int = 1024) -> np.ndarray:
        return np.random.randn(num_samples) + 1j * np.random.randn(num_samples)


class SDRManager:
    def __init__(self):
        self.devices: List[SDRDevice] = []
        self.active_device: Optional[SDRDevice] = None
        
    def detect_devices(self) -> List[dict]:
        detected = []
        
        if not settings.ENABLE_SDR_HARDWARE:
            return [{
                "type": "simulated",
                "index": 0,
                "name": "Simulated SDR (hardware disabled)",
                "available": True
            }]
        
        try:
            from rtlsdr import RtlSdr
            sdr = RtlSdr()
            detected.append({
                "type": "RTL-SDR",
                "index": 0,
                "name": f"RTL-SDR Device",
                "available": True
            })
            sdr.close()
        except Exception as e:
            print(f"RTL-SDR detection: {e}")
        
        return detected if detected else [{
            "type": "none",
            "index": 0,
            "name": "No SDR devices detected",
            "available": False
        }]
    
    async def open_device(self, device_type: str, device_index: int = 0) -> Optional[SDRDevice]:
        if device_type == "RTL-SDR":
            device = RTLSDRDevice(device_index)
        elif device_type == "HackRF":
            device = HackRFDevice(device_index)
        else:
            device = SDRDevice("simulated", device_index)
        
        await device.start()
        self.active_device = device
        self.devices.append(device)
        return device
    
    async def close_device(self, device: SDRDevice):
        if device in self.devices:
            await device.stop()
            self.devices.remove(device)
            if self.active_device == device:
                self.active_device = None


class SpectrumAnalyzer:
    def __init__(self, fft_size: int = 1024, window: str = "hann"):
        self.fft_size = fft_size
        self.window = signal.get_window(window, fft_size)
        self.averaging_factor = 0.7
        self.last_psd = None
        
    def compute_psd(self, samples: np.ndarray) -> np.ndarray:
        if len(samples) < self.fft_size:
            samples = np.pad(samples, (0, self.fft_size - len(samples)))
        
        windowed = samples[:self.fft_size] * self.window
        
        fft_result = np.fft.fft(windowed)
        fft_shifted = np.fft.fftshift(fft_result)
        
        power = np.abs(fft_shifted) ** 2
        
        psd_db = 10 * np.log10(power + 1e-10)
        
        if self.last_psd is not None:
            psd_db = self.averaging_factor * self.last_psd + (1 - self.averaging_factor) * psd_db
        
        self.last_psd = psd_db
        
        return psd_db
    
    def compute_spectrum(self, samples: np.ndarray, sample_rate: int) -> Tuple[np.ndarray, np.ndarray]:
        psd_db = self.compute_psd(samples)
        
        frequencies = np.fft.fftshift(np.fft.fftfreq(self.fft_size, 1/sample_rate))
        
        return frequencies, psd_db


class DopplerCorrector:
    def __init__(self, satellite_velocity_kmps: float, center_frequency_hz: float):
        self.satellite_velocity = satellite_velocity_kmps * 1000
        self.center_frequency = center_frequency_hz
        self.speed_of_light = 299792458
        
    def calculate_doppler_shift(self, radial_velocity_ms: float) -> float:
        doppler_factor = 1 + (radial_velocity_ms / self.speed_of_light)
        shifted_frequency = self.center_frequency * doppler_factor
        return shifted_frequency - self.center_frequency
    
    def correct_frequency(self, radial_velocity_ms: float) -> float:
        doppler_shift = self.calculate_doppler_shift(radial_velocity_ms)
        corrected_frequency = self.center_frequency + doppler_shift
        return corrected_frequency


class IQRecorder:
    def __init__(self, file_path: str, sample_rate: int, center_frequency: int):
        self.file_path = file_path
        self.sample_rate = sample_rate
        self.center_frequency = center_frequency
        self.samples_recorded = 0
        
    def write_samples(self, samples: np.ndarray):
        with open(self.file_path, "ab") as f:
            samples_interleaved = np.empty(len(samples) * 2, dtype=np.float32)
            samples_interleaved[0::2] = samples.real
            samples_interleaved[1::2] = samples.imag
            samples_interleaved.tofile(f)
        
        self.samples_recorded += len(samples)
    
    def write_header(self):
        header = {
            "sample_rate": self.sample_rate,
            "center_frequency": self.center_frequency,
            "format": "complex64",
            "samples": self.samples_recorded
        }
        
        header_path = self.file_path + ".json"
        import json
        with open(header_path, "w") as f:
            json.dump(header, f, indent=2)
    
    def close(self):
        self.write_header()


class IQPlayer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.metadata = self._read_metadata()
        
    def _read_metadata(self) -> dict:
        import json
        header_path = self.file_path + ".json"
        try:
            with open(header_path, "r") as f:
                return json.load(f)
        except:
            return {
                "sample_rate": settings.SDR_SAMPLE_RATE,
                "center_frequency": settings.SDR_CENTER_FREQ,
                "format": "complex64"
            }
    
    def read_samples(self, num_samples: int, offset: int = 0) -> np.ndarray:
        with open(self.file_path, "rb") as f:
            f.seek(offset * 2 * 4)
            
            samples_interleaved = np.fromfile(f, dtype=np.float32, count=num_samples * 2)
            
            if len(samples_interleaved) < num_samples * 2:
                return np.array([])
            
            samples = samples_interleaved[0::2] + 1j * samples_interleaved[1::2]
            return samples


sdr_manager = SDRManager()
