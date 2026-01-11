from models import TLEData
from database import SessionLocal

db = SessionLocal()
try:
    count = db.query(TLEData).count()
    print(f"TLE Count: {count}")
    if count > 0:
        first = db.query(TLEData).first()
        print(f"First satellite: {first.satellite_name} (NORAD: {first.norad_id})")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    db.close()
