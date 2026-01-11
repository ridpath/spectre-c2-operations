import nmap
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
import subprocess


class VulnerabilityScanner:
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        
    def _parse_nmap_output(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse nmap output into structured vulnerability data"""
        findings = []
        hosts_scanned = []
        
        for host in scan_result.get('scan', {}).values():
            host_info = {
                'ip': host.get('addresses', {}).get('ipv4', 'unknown'),
                'hostname': host.get('hostnames', [{}])[0].get('name', ''),
                'state': host.get('status', {}).get('state', 'unknown'),
                'ports': []
            }
            
            for proto in host.get('all_protocols', []):
                ports = host.get(proto, {}).keys()
                for port in ports:
                    port_info = host[proto][port]
                    port_data = {
                        'port': port,
                        'protocol': proto,
                        'state': port_info.get('state', 'unknown'),
                        'service': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'cpe': port_info.get('cpe', '')
                    }
                    host_info['ports'].append(port_data)
                    
                    if port_info.get('state') == 'open':
                        finding = {
                            'id': str(uuid.uuid4()),
                            'host': host_info['ip'],
                            'port': port,
                            'service': port_info.get('name', 'unknown'),
                            'severity': self._assess_severity(port, port_info),
                            'description': f"Open {port_info.get('name', 'unknown')} service on port {port}",
                            'cve': self._check_known_vulns(port_info)
                        }
                        findings.append(finding)
            
            hosts_scanned.append(host_info)
        
        return {
            'hosts': hosts_scanned,
            'findings': findings,
            'total_hosts': len(hosts_scanned),
            'total_findings': len(findings)
        }
    
    def _assess_severity(self, port: int, port_info: Dict[str, Any]) -> str:
        """Assess severity based on service and version"""
        service = port_info.get('name', '').lower()
        version = port_info.get('version', '').lower()
        
        critical_services = ['smb', 'msrpc', 'microsoft-ds', 'netbios-ssn']
        high_services = ['rdp', 'ms-wbt-server', 'ssh', 'telnet', 'ftp']
        
        if service in critical_services:
            if 'smb' in service and port in [139, 445]:
                return 'Critical'
            return 'High'
        elif service in high_services:
            return 'High'
        elif port in [80, 443, 8080, 8443]:
            return 'Medium'
        else:
            return 'Low'
    
    def _check_known_vulns(self, port_info: Dict[str, Any]) -> Optional[str]:
        """Check for known vulnerabilities based on service/version"""
        service = port_info.get('name', '').lower()
        product = port_info.get('product', '').lower()
        version = port_info.get('version', '').lower()
        
        if 'smb' in service and 'windows' in product:
            return 'CVE-2017-0144'  # EternalBlue
        elif service == 'rdp' and 'windows' in product:
            return 'CVE-2019-0708'  # BlueKeep
        elif 'apache' in product and version:
            return 'CVE-2021-41773'  # Path Traversal
        
        return None
    
    async def quick_scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Quick TCP SYN scan"""
        try:
            self.nm.scan(
                hosts=target,
                arguments=f'-sS -p {ports} -T4 --max-retries 2',
                sudo=False
            )
            
            result = self._parse_nmap_output(self.nm._scan_result)
            result['scan_type'] = 'quick'
            result['target'] = target
            result['timestamp'] = datetime.utcnow().isoformat()
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': 'quick',
                'target': target
            }
    
    async def full_scan(self, target: str) -> Dict[str, Any]:
        """Comprehensive scan with version detection"""
        try:
            self.nm.scan(
                hosts=target,
                arguments='-sV -sC -p- -A -T4 --version-intensity 5',
                sudo=False
            )
            
            result = self._parse_nmap_output(self.nm._scan_result)
            result['scan_type'] = 'full'
            result['target'] = target
            result['timestamp'] = datetime.utcnow().isoformat()
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': 'full',
                'target': target
            }
    
    async def vuln_scan(self, target: str, cve: Optional[str] = None) -> Dict[str, Any]:
        """Vulnerability-specific scan using NSE scripts"""
        try:
            if cve:
                script_args = f'--script vuln --script-args=cve={cve}'
            else:
                script_args = '--script vuln,exploit'
            
            self.nm.scan(
                hosts=target,
                arguments=f'-sV {script_args} -p 1-65535 -T4',
                sudo=False
            )
            
            result = self._parse_nmap_output(self.nm._scan_result)
            result['scan_type'] = 'vulnerability'
            result['target'] = target
            result['cve_filter'] = cve
            result['timestamp'] = datetime.utcnow().isoformat()
            
            result['nse_results'] = self._extract_nse_scripts(self.nm._scan_result)
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': 'vulnerability',
                'target': target
            }
    
    async def smb_vuln_scan(self, target: str) -> Dict[str, Any]:
        """SMB-specific vulnerability scan (EternalBlue, MS17-010, etc.)"""
        try:
            self.nm.scan(
                hosts=target,
                arguments='--script smb-vuln* -p 445,139 -T4',
                sudo=False
            )
            
            result = self._parse_nmap_output(self.nm._scan_result)
            result['scan_type'] = 'smb_vulnerability'
            result['target'] = target
            result['timestamp'] = datetime.utcnow().isoformat()
            result['nse_results'] = self._extract_nse_scripts(self.nm._scan_result)
            
            eternalblue = self._check_eternalblue(result)
            if eternalblue:
                result['findings'].append({
                    'id': str(uuid.uuid4()),
                    'host': target,
                    'port': 445,
                    'service': 'smb',
                    'severity': 'Critical',
                    'description': 'EternalBlue vulnerability detected (MS17-010)',
                    'cve': 'CVE-2017-0144'
                })
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': 'smb_vulnerability',
                'target': target
            }
    
    async def rdp_scan(self, target: str) -> Dict[str, Any]:
        """RDP vulnerability scan (BlueKeep, etc.)"""
        try:
            self.nm.scan(
                hosts=target,
                arguments='--script rdp-vuln* -p 3389 -T4',
                sudo=False
            )
            
            result = self._parse_nmap_output(self.nm._scan_result)
            result['scan_type'] = 'rdp_vulnerability'
            result['target'] = target
            result['timestamp'] = datetime.utcnow().isoformat()
            result['nse_results'] = self._extract_nse_scripts(self.nm._scan_result)
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': 'rdp_vulnerability',
                'target': target
            }
    
    async def service_scan(self, target: str, service: str) -> Dict[str, Any]:
        """Service-specific vulnerability scan"""
        service_ports = {
            'http': '80,443,8080,8443',
            'smb': '139,445',
            'rdp': '3389',
            'ssh': '22',
            'ftp': '21',
            'telnet': '23',
            'sql': '1433,3306,5432'
        }
        
        ports = service_ports.get(service.lower(), '1-65535')
        
        try:
            self.nm.scan(
                hosts=target,
                arguments=f'-sV --script {service}-* -p {ports} -T4',
                sudo=False
            )
            
            result = self._parse_nmap_output(self.nm._scan_result)
            result['scan_type'] = f'{service}_scan'
            result['target'] = target
            result['timestamp'] = datetime.utcnow().isoformat()
            result['nse_results'] = self._extract_nse_scripts(self.nm._scan_result)
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': f'{service}_scan',
                'target': target
            }
    
    async def network_discovery(self, subnet: str) -> Dict[str, Any]:
        """Network host discovery scan"""
        try:
            self.nm.scan(
                hosts=subnet,
                arguments='-sn -T4',
                sudo=False
            )
            
            hosts = []
            for host in self.nm.all_hosts():
                hosts.append({
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'addresses': self.nm[host].get('addresses', {}),
                    'vendor': self.nm[host].get('vendor', {})
                })
            
            return {
                'scan_type': 'discovery',
                'subnet': subnet,
                'hosts_found': len(hosts),
                'hosts': hosts,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_type': 'discovery',
                'subnet': subnet
            }
    
    def _extract_nse_scripts(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract NSE script results from scan"""
        nse_results = []
        
        for host in scan_result.get('scan', {}).values():
            for proto in host.get('all_protocols', []):
                ports = host.get(proto, {}).keys()
                for port in ports:
                    port_info = host[proto][port]
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            nse_results.append({
                                'host': host.get('addresses', {}).get('ipv4', 'unknown'),
                                'port': port,
                                'script': script_name,
                                'output': script_output
                            })
        
        return nse_results
    
    def _check_eternalblue(self, result: Dict[str, Any]) -> bool:
        """Check if EternalBlue vulnerability detected"""
        for nse in result.get('nse_results', []):
            if 'ms17-010' in nse.get('script', '').lower():
                if 'VULNERABLE' in nse.get('output', ''):
                    return True
        return False


vuln_scanner = VulnerabilityScanner()
