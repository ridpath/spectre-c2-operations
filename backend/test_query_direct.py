from models import TLEData
from database import SessionLocal
from sqlalchemy import desc

db = SessionLocal()
try:
    query = db.query(TLEData).order_by(desc(TLEData.epoch))
    satellites = query.limit(5).all()
    
    print(f"Found {len(satellites)} satellites")
    
    for s in satellites:
        print(f"\nSatellite: {s.satellite_name}")
        print(f"  ID: {s.id}")
        print(f"  NORAD: {s.norad_id}")
        print(f"  Epoch: {s.epoch}")
        print(f"  Source: {s.source}")
        print(f"  TLE1: {s.tle_line1[:50]}...")
        
        # Try to create the response dict
        try:
            result = {
                "id": str(s.id),
                "name": s.satellite_name,
                "norad_id": s.norad_id,
                "tle_line1": s.tle_line1,
                "tle_line2": s.tle_line2,
                "epoch": s.epoch.isoformat(),
                "source": s.source
            }
            print(f"  ✓ Dict creation successful")
        except Exception as e:
            print(f"  ✗ Dict creation failed: {e}")
            
except Exception as e:
    print(f"Query error: {e}")
    import traceback
    traceback.print_exc()
finally:
    db.close()
