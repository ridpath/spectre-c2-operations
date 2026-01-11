import requests
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import time
from config import get_settings

settings = get_settings()


class SatelliteTLEFetcher:
    """
    Fetches TLE data from multiple free sources with API key support
    Sources:
    - CelesTrak (free, optional API key for higher rate limits)
    - Space-Track.org (requires free registration, API key)
    - N2YO (free tier available, API key)
    - SatNOGS DB (free, optional API key)
    """
    
    def __init__(self):
        self.celestrak_base = settings.CELESTRAK_BASE_URL
        self.celestrak_api_key = settings.CELESTRAK_API_KEY
        self.spacetrack_username = settings.SPACETRACK_USERNAME
        self.spacetrack_password = settings.SPACETRACK_PASSWORD
        self.spacetrack_api_key = settings.SPACETRACK_API_KEY
        self.n2yo_api_key = settings.N2YO_API_KEY
        self.satnogs_api_key = settings.SATNOGS_API_KEY
        
        self.spacetrack_token = None
        self.token_expiry = None
        
        # Free satellite groups on CelesTrak
        self.default_groups = [
            "stations",          # ISS and other space stations
            "active",            # Active satellites
            "analyst",           # Analyst satellites
            "weather",           # Weather satellites
            "noaa",              # NOAA satellites
            "goes",              # GOES satellites
            "resource",          # Earth resource satellites
            "sarsat",            # Search and rescue satellites
            "dmc",               # Disaster monitoring
            "tdrss",             # Tracking and data relay
            "argos",             # ARGOS data collection
            "planet",            # Planet Labs
            "spire",             # Spire Global
            "geo",               # Geostationary satellites
            "intelsat",          # Intelsat satellites
            "ses",               # SES satellites
            "iridium",           # Iridium constellation
            "iridium-NEXT",      # Iridium NEXT
            "starlink",          # Starlink constellation
            "oneweb",            # OneWeb constellation
            "orbcomm",           # Orbcomm satellites
            "globalstar",        # Globalstar satellites
            "amateur",           # Amateur radio satellites
            "cubesat",           # CubeSats
            "engineering",       # Engineering satellites
            "education",         # Educational satellites
            "military",          # Military satellites
            "radar",             # Radar satellites
            "science",           # Science missions
            "geodetic",          # Geodetic satellites
            "x-comm",            # Experimental communications
            "other-comm",        # Other communications
            "satnogs",           # SatNOGS tracked satellites
            "gps-ops",           # GPS operational
            "glo-ops",           # GLONASS operational
            "galileo",           # Galileo constellation
            "beidou",            # BeiDou constellation
            "sbas",              # Satellite-based augmentation
            "nnss",              # Navy navigation satellites
            "musson",            # Russian navigation
            "cosmos-2251-debris",# Debris from collisions
            "iridium-33-debris", # Iridium 33 collision debris
        ]
    
    async def fetch_celestrak_group(self, group: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch TLE data from CelesTrak for a specific group with rate limiting"""
        try:
            time.sleep(0.5)
            
            headers = {}
            if self.celestrak_api_key:
                headers['Authorization'] = f'Bearer {self.celestrak_api_key}'
            
            url = f"{self.celestrak_base}/NORAD/elements/gp.php?GROUP={group}&FORMAT=TLE"
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code != 200:
                print(f"[CelesTrak] Failed to fetch {group}: {response.status_code}")
                return None
            
            lines = response.text.strip().split('\n')
            satellites = []
            
            for i in range(0, len(lines), 3):
                if i + 2 >= len(lines):
                    break
                
                name = lines[i].strip()
                tle_line1 = lines[i + 1].strip()
                tle_line2 = lines[i + 2].strip()
                
                # Extract NORAD ID from TLE
                try:
                    norad_id = int(tle_line1.split()[1][:5])
                except:
                    continue
                
                satellites.append({
                    'name': name,
                    'norad_id': norad_id,
                    'tle_line1': tle_line1,
                    'tle_line2': tle_line2,
                    'source': 'celestrak',
                    'group': group,
                    'fetched_at': datetime.utcnow().isoformat()
                })
            
            print(f"[CelesTrak] Fetched {len(satellites)} satellites from group '{group}'")
            return satellites
            
        except Exception as e:
            print(f"[CelesTrak] Error fetching group {group}: {e}")
            return None
    
    async def fetch_all_celestrak_groups(self, groups: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Fetch TLE data from multiple CelesTrak groups"""
        if groups is None:
            groups = self.default_groups
        
        all_satellites = []
        seen_norad_ids = set()
        
        for group in groups:
            satellites = await self.fetch_celestrak_group(group)
            if satellites:
                for sat in satellites:
                    # Avoid duplicates
                    if sat['norad_id'] not in seen_norad_ids:
                        all_satellites.append(sat)
                        seen_norad_ids.add(sat['norad_id'])
            
            # Rate limiting - be nice to CelesTrak
            await asyncio.sleep(0.5)
        
        print(f"[CelesTrak] Total unique satellites fetched: {len(all_satellites)}")
        return all_satellites
    
    async def authenticate_spacetrack(self) -> bool:
        """Authenticate with Space-Track.org and get session token"""
        if not self.spacetrack_username or not self.spacetrack_password:
            print("[Space-Track] No credentials configured")
            return False
        
        # Check if token is still valid
        if self.spacetrack_token and self.token_expiry:
            if datetime.utcnow() < self.token_expiry:
                return True
        
        try:
            url = "https://www.space-track.org/ajaxauth/login"
            data = {
                'identity': self.spacetrack_username,
                'password': self.spacetrack_password
            }
            
            response = requests.post(url, data=data, timeout=15)
            
            if response.status_code == 200:
                # Space-Track uses cookies for authentication
                self.spacetrack_token = response.cookies
                self.token_expiry = datetime.utcnow() + timedelta(hours=2)
                print("[Space-Track] Authentication successful")
                return True
            else:
                print(f"[Space-Track] Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[Space-Track] Authentication error: {e}")
            return False
    
    async def fetch_spacetrack_tle(self, norad_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Fetch TLE data from Space-Track.org with rate limiting (max 30 requests/min for free tier)"""
        if not await self.authenticate_spacetrack():
            return []
        
        try:
            time.sleep(2.0)
            
            if norad_ids:
                norad_query = ','.join(map(str, norad_ids))
                url = f"https://www.space-track.org/basicspacedata/query/class/tle_latest/ORDINAL/1/NORAD_CAT_ID/{norad_query}/format/3le"
            else:
                # Get latest TLEs for all active satellites
                url = "https://www.space-track.org/basicspacedata/query/class/tle_latest/ORDINAL/1/limit/1000/format/3le"
            
            response = requests.get(url, cookies=self.spacetrack_token, timeout=30)
            
            if response.status_code != 200:
                print(f"[Space-Track] Failed to fetch TLEs: {response.status_code}")
                return []
            
            lines = response.text.strip().split('\n')
            satellites = []
            
            for i in range(0, len(lines), 3):
                if i + 2 >= len(lines):
                    break
                
                name = lines[i].strip()
                tle_line1 = lines[i + 1].strip()
                tle_line2 = lines[i + 2].strip()
                
                try:
                    norad_id = int(tle_line1.split()[1][:5])
                except:
                    continue
                
                satellites.append({
                    'name': name,
                    'norad_id': norad_id,
                    'tle_line1': tle_line1,
                    'tle_line2': tle_line2,
                    'source': 'spacetrack',
                    'fetched_at': datetime.utcnow().isoformat()
                })
            
            print(f"[Space-Track] Fetched {len(satellites)} satellites")
            return satellites
            
        except Exception as e:
            print(f"[Space-Track] Error fetching TLEs: {e}")
            return []
    
    async def fetch_n2yo_tle(self, norad_id: int) -> Optional[Dict[str, Any]]:
        """Fetch TLE data from N2YO API for a specific satellite with rate limiting (free tier: 1000 requests/hour)"""
        if not self.n2yo_api_key:
            print("[N2YO] No API key configured")
            return None
        
        try:
            time.sleep(3.6)
            
            url = f"https://api.n2yo.com/rest/v1/satellite/tle/{norad_id}"
            params = {'apiKey': self.n2yo_api_key}
            
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            
            if 'tle' in data:
                return {
                    'name': data['info']['satname'],
                    'norad_id': norad_id,
                    'tle_line1': data['tle'].split('\n')[0],
                    'tle_line2': data['tle'].split('\n')[1],
                    'source': 'n2yo',
                    'fetched_at': datetime.utcnow().isoformat()
                }
            
            return None
            
        except Exception as e:
            print(f"[N2YO] Error fetching TLE for {norad_id}: {e}")
            return None
    
    async def fetch_satnogs_satellites(self) -> List[Dict[str, Any]]:
        """Fetch satellite list from SatNOGS DB with rate limiting"""
        try:
            time.sleep(1.0)
            
            url = "https://db.satnogs.org/api/satellites/"
            headers = {}
            if self.satnogs_api_key:
                headers['Authorization'] = f'Token {self.satnogs_api_key}'
            
            response = requests.get(url, headers=headers, timeout=20)
            
            if response.status_code != 200:
                print(f"[SatNOGS] Failed to fetch satellite list: {response.status_code}")
                return []
            
            satellites_data = response.json()
            satellites = []
            
            for sat in satellites_data[:500]:  # Limit to 500 for performance
                if 'norad_cat_id' in sat and sat['norad_cat_id']:
                    satellites.append({
                        'name': sat['name'],
                        'norad_id': sat['norad_cat_id'],
                        'status': sat.get('status', 'unknown'),
                        'source': 'satnogs',
                        'fetched_at': datetime.utcnow().isoformat()
                    })
            
            print(f"[SatNOGS] Fetched {len(satellites)} satellites")
            return satellites
            
        except Exception as e:
            print(f"[SatNOGS] Error fetching satellites: {e}")
            return []
    
    async def fetch_all_sources(self, celestrak_groups: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch from all available sources"""
        results = {
            'celestrak': [],
            'spacetrack': [],
            'satnogs': []
        }
        
        # Fetch from CelesTrak
        print("[TLE Fetcher] Fetching from CelesTrak...")
        results['celestrak'] = await self.fetch_all_celestrak_groups(celestrak_groups)
        
        # Fetch from Space-Track if credentials available
        if self.spacetrack_username and self.spacetrack_password:
            print("[TLE Fetcher] Fetching from Space-Track...")
            results['spacetrack'] = await self.fetch_spacetrack_tle()
        
        # Fetch from SatNOGS
        print("[TLE Fetcher] Fetching from SatNOGS...")
        results['satnogs'] = await self.fetch_satnogs_satellites()
        
        return results
    
    def merge_satellite_data(self, sources: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Merge satellite data from multiple sources, preferring newer TLEs"""
        merged = {}
        
        # Priority: Space-Track > CelesTrak > SatNOGS
        for source_name in ['satnogs', 'celestrak', 'spacetrack']:
            for sat in sources.get(source_name, []):
                norad_id = sat['norad_id']
                
                # Only use satellites with TLE data
                if 'tle_line1' in sat and 'tle_line2' in sat:
                    # Overwrite if we don't have this satellite or if this source has higher priority
                    if norad_id not in merged or source_name == 'spacetrack':
                        merged[norad_id] = sat
        
        return list(merged.values())


tle_fetcher = SatelliteTLEFetcher()
