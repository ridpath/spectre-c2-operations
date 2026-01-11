import os
import subprocess
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
from config import get_settings

settings = get_settings()


class DemodulationType(str, Enum):
    FM = "fm"
    AM = "am"
    SSB = "ssb"
    BPSK = "bpsk"
    QPSK = "qpsk"
    OQPSK = "oqpsk"
    FSK = "fsk"
    AFSK = "afsk"
    GMSK = "gmsk"


@dataclass
class DemodulatorConfig:
    sample_rate: int
    center_frequency: int
    modulation: DemodulationType
    bandwidth: int
    gain: float
    output_file: Optional[str] = None


class GNURadioFlowgraph:
    def __init__(self, flowgraph_path: str):
        self.flowgraph_path = flowgraph_path
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        
    def start(self, parameters: Dict[str, Any] = None) -> bool:
        if self.running:
            return False
        
        try:
            cmd = ["python3", self.flowgraph_path]
            
            if parameters:
                for key, value in parameters.items():
                    cmd.extend([f"--{key}", str(value)])
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.running = True
            return True
            
        except Exception as e:
            print(f"Failed to start flowgraph: {e}")
            return False
    
    def stop(self) -> bool:
        if not self.running or not self.process:
            return False
        
        try:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.running = False
            return True
            
        except Exception as e:
            print(f"Failed to stop flowgraph: {e}")
            try:
                self.process.kill()
            except:
                pass
            self.running = False
            return False
    
    def get_status(self) -> Dict[str, Any]:
        if not self.process:
            return {"running": False, "status": "not_started"}
        
        poll_result = self.process.poll()
        
        if poll_result is None:
            return {"running": True, "status": "active"}
        else:
            return {
                "running": False,
                "status": "stopped",
                "exit_code": poll_result
            }


class GNURadioDemodulator:
    def __init__(self):
        self.flowgraphs: Dict[str, GNURadioFlowgraph] = {}
        self.demodulator_templates = self._load_templates()
        
    def _load_templates(self) -> Dict[str, str]:
        templates_dir = os.path.join(os.path.dirname(__file__), "gnuradio_flowgraphs")
        templates = {}
        
        if os.path.exists(templates_dir):
            for filename in os.listdir(templates_dir):
                if filename.endswith('.py'):
                    name = filename[:-3]
                    templates[name] = os.path.join(templates_dir, filename)
        
        return templates
    
    def create_demodulator(
        self,
        demod_id: str,
        config: DemodulatorConfig
    ) -> Optional[GNURadioFlowgraph]:
        template_name = f"{config.modulation.value}_demod"
        
        if template_name not in self.demodulator_templates:
            print(f"No template found for {config.modulation.value}")
            return None
        
        flowgraph_path = self.demodulator_templates[template_name]
        flowgraph = GNURadioFlowgraph(flowgraph_path)
        
        self.flowgraphs[demod_id] = flowgraph
        return flowgraph
    
    def start_demodulator(
        self,
        demod_id: str,
        config: DemodulatorConfig
    ) -> bool:
        flowgraph = self.flowgraphs.get(demod_id)
        
        if not flowgraph:
            flowgraph = self.create_demodulator(demod_id, config)
            if not flowgraph:
                return False
        
        parameters = {
            "samp-rate": config.sample_rate,
            "freq": config.center_frequency,
            "bandwidth": config.bandwidth,
            "gain": config.gain
        }
        
        if config.output_file:
            parameters["output"] = config.output_file
        
        return flowgraph.start(parameters)
    
    def stop_demodulator(self, demod_id: str) -> bool:
        flowgraph = self.flowgraphs.get(demod_id)
        
        if not flowgraph:
            return False
        
        success = flowgraph.stop()
        
        if success:
            del self.flowgraphs[demod_id]
        
        return success
    
    def get_demodulator_status(self, demod_id: str) -> Optional[Dict[str, Any]]:
        flowgraph = self.flowgraphs.get(demod_id)
        
        if not flowgraph:
            return None
        
        return flowgraph.get_status()
    
    def list_active_demodulators(self) -> List[str]:
        return [
            demod_id for demod_id, fg in self.flowgraphs.items()
            if fg.get_status()["running"]
        ]
    
    def get_available_demodulators(self) -> List[str]:
        return list(self.demodulator_templates.keys())


class SatelliteDemodulator:
    def __init__(self):
        self.gr_demod = GNURadioDemodulator()
        self.satellite_configs: Dict[str, DemodulatorConfig] = {}
        
    def add_satellite_config(
        self,
        satellite_name: str,
        modulation: str,
        frequency: int,
        bandwidth: int = 25000
    ):
        try:
            mod_type = DemodulationType(modulation.lower())
        except ValueError:
            print(f"Invalid modulation type: {modulation}")
            return False
        
        config = DemodulatorConfig(
            sample_rate=settings.SDR_SAMPLE_RATE,
            center_frequency=frequency,
            modulation=mod_type,
            bandwidth=bandwidth,
            gain=settings.SDR_GAIN if isinstance(settings.SDR_GAIN, (int, float)) else 30.0,
            output_file=f"./storage/demod/{satellite_name.replace(' ', '_')}.raw"
        )
        
        self.satellite_configs[satellite_name] = config
        return True
    
    def start_satellite_demod(self, satellite_name: str) -> bool:
        config = self.satellite_configs.get(satellite_name)
        
        if not config:
            print(f"No configuration found for {satellite_name}")
            return False
        
        demod_id = f"sat_{satellite_name.replace(' ', '_')}"
        return self.gr_demod.start_demodulator(demod_id, config)
    
    def stop_satellite_demod(self, satellite_name: str) -> bool:
        demod_id = f"sat_{satellite_name.replace(' ', '_')}"
        return self.gr_demod.stop_demodulator(demod_id)
    
    def get_status(self, satellite_name: str) -> Optional[Dict[str, Any]]:
        demod_id = f"sat_{satellite_name.replace(' ', '_')}"
        status = self.gr_demod.get_demodulator_status(demod_id)
        
        if status:
            config = self.satellite_configs.get(satellite_name)
            status["config"] = {
                "modulation": config.modulation.value if config else None,
                "frequency": config.center_frequency if config else None,
                "bandwidth": config.bandwidth if config else None
            }
        
        return status


gnuradio_demod = GNURadioDemodulator()
satellite_demod = SatelliteDemodulator()
