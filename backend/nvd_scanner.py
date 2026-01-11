import requests
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from config import get_settings

settings = get_settings()


class NVDScanner:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache: Dict[str, Any] = {}
        self.cache_expiry: Dict[str, datetime] = {}
        self.cache_ttl = timedelta(hours=24)
        
    def search_vulnerabilities(
        self,
        keywords: List[str],
        severity_threshold: str = "MEDIUM"
    ) -> List[Dict[str, Any]]:
        results = []
        
        for keyword in keywords:
            cache_key = f"search_{keyword}_{severity_threshold}"
            
            if self._is_cached(cache_key):
                results.extend(self.cache[cache_key])
                continue
            
            try:
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 20
                }
                
                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key
                
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    for vuln_item in vulnerabilities:
                        cve_data = vuln_item.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        
                        descriptions = cve_data.get("descriptions", [])
                        description = ""
                        if descriptions:
                            description = descriptions[0].get("value", "")
                        
                        metrics = cve_data.get("metrics", {})
                        cvss_score = 0.0
                        severity = "UNKNOWN"
                        
                        if "cvssMetricV31" in metrics:
                            cvss_v3 = metrics["cvssMetricV31"]
                            if cvss_v3:
                                cvss_data = cvss_v3[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore", 0.0)
                                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        elif "cvssMetricV2" in metrics:
                            cvss_v2 = metrics["cvssMetricV2"]
                            if cvss_v2:
                                cvss_data = cvss_v2[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore", 0.0)
                                severity = self._cvss2_to_severity(cvss_score)
                        
                        published_date = cve_data.get("published", "")
                        last_modified = cve_data.get("lastModified", "")
                        
                        references = []
                        for ref in cve_data.get("references", []):
                            references.append(ref.get("url", ""))
                        
                        vuln_info = {
                            "cve": cve_id,
                            "description": description,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "published_date": published_date,
                            "last_modified": last_modified,
                            "references": references,
                            "keyword": keyword
                        }
                        
                        if self._meets_severity_threshold(severity, severity_threshold):
                            results.append(vuln_info)
                    
                    self._cache_result(cache_key, results)
                    
                elif response.status_code == 403:
                    print("NVD API rate limit exceeded or API key required")
                else:
                    print(f"NVD API error: {response.status_code}")
                    
            except Exception as e:
                print(f"Error querying NVD for {keyword}: {e}")
        
        return results
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        cache_key = f"cve_{cve_id}"
        
        if self._is_cached(cache_key):
            return self.cache[cache_key]
        
        try:
            url = f"{self.base_url}?cveId={cve_id}"
            
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    
                    self._cache_result(cache_key, cve_data)
                    return cve_data
                    
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
        
        return None
    
    def scan_satellite_vulnerabilities(
        self,
        satellite_name: str,
        subsystems: List[str] = None
    ) -> List[Dict[str, Any]]:
        if subsystems is None:
            subsystems = ["telemetry", "command", "communication", "firmware"]
        
        keywords = [f"{satellite_name} satellite", "satellite security"]
        keywords.extend([f"satellite {subsystem}" for subsystem in subsystems])
        
        return self.search_vulnerabilities(keywords, severity_threshold="MEDIUM")
    
    def _is_cached(self, key: str) -> bool:
        if key not in self.cache:
            return False
        
        if key not in self.cache_expiry:
            return False
        
        if datetime.now(timezone.utc) > self.cache_expiry[key]:
            del self.cache[key]
            del self.cache_expiry[key]
            return False
        
        return True
    
    def _cache_result(self, key: str, data: Any):
        self.cache[key] = data
        self.cache_expiry[key] = datetime.now(timezone.utc) + self.cache_ttl
    
    def _cvss2_to_severity(self, score: float) -> str:
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _meets_severity_threshold(self, severity: str, threshold: str) -> bool:
        severity_levels = {
            "NONE": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        
        severity_level = severity_levels.get(severity.upper(), 0)
        threshold_level = severity_levels.get(threshold.upper(), 0)
        
        return severity_level >= threshold_level
    
    def clear_cache(self):
        self.cache.clear()
        self.cache_expiry.clear()


nvd_scanner = NVDScanner()
