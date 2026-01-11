#!/usr/bin/env python3
import sys
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import TLEData

DATABASE_URL = "sqlite:///./spectre_c2.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
db = Session(engine)

# Hardcoded satellites with realistic TLEs
satellites = [
    {
        "norad_id": 25544,
        "name": "ISS (ZARYA)",
        "line1": "1 25544U 98067A   23365.50000000  .00016717  00000-0  10270-3 0  9009",
        "line2": "2 25544  51.6400 150.5000 0001400  90.5000  90.5000 15.50000000 12345"
    },
    {
        "norad_id": 20580,
        "name": "HUBBLE SPACE TELESCOPE",
        "line1": "1 20580U 90037B   23365.50000000  .00000621  00000-0  33256-4 0  9990",
        "line2": "2 20580  28.4690  50.0000 0002900 180.0000 180.0000 15.09677062123456"
    },
    {
        "norad_id": 40730,
        "name": "NOAA 19",
        "line1": "1 40730U 15011A   23365.50000000  .00000100  00000-0  60000-4 0  9990",
        "line2": "2 40730  98.7400 120.0000 0014400 100.0000 260.0000 14.12600000456789"
    },
    {
        "norad_id": 43205,
        "name": "STARLINK-30",
        "line1": "1 43205U 18017A   23365.50000000  .00001200  00000-0  82000-4 0  9990",
        "line2": "2 43205  53.0500 200.0000 0001500  90.0000 270.0000 15.19400000234567"
    },
    {
        "norad_id": 24946,
        "name": "IRIDIUM 7",
        "line1": "1 24946U 97051C   23365.50000000  .00000080  00000-0  45000-4 0  9990",
        "line2": "2 24946  86.4000  90.0000 0002000  80.0000 280.0000 14.34200000345678"
    }
]

print("Populating satellites database...")
count = 0

try:
    for sat in satellites:
        existing = db.query(TLEData).filter(TLEData.norad_id == sat['norad_id']).first()
        if existing:
            print(f"  Skipping {sat['name']} (already exists)")
            continue
        
        tle_entry = TLEData(
            norad_id=sat['norad_id'],
            satellite_name=sat['name'],
            tle_line1=sat['line1'],
            tle_line2=sat['line2'],
            epoch=datetime.now(timezone.utc),
            source='hardcoded',
            group_name='manual',
            fetched_at=datetime.now(timezone.utc)
        )
        
        db.add(tle_entry)
        count += 1
        print(f"  Added {sat['name']}")
    
    db.commit()
    print(f"\nSUCCESS: Added {count} satellites to database")
    
except Exception as e:
    db.rollback()
    print(f"ERROR: {e}")
    sys.exit(1)
finally:
    db.close()
