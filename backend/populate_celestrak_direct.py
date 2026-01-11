import requests
from database import SessionLocal
from models import TLEData
from datetime import datetime, timezone

# Try fetching from CelesTrak's stations (amateur radio satellites) - simpler endpoint
url = "https://celestrak.org/NORAD/elements/stations.txt"

print(f"Fetching from: {url}")
headers = {
    'User-Agent': 'SpectreC2/2.0 (Research; contact@example.com)'
}
response = requests.get(url, headers=headers, timeout=30)

print(f"Status: {response.status_code}")

if response.status_code == 200:
    text = response.text
    lines = text.strip().split('\n')
    
    print(f"Got {len(lines)} lines")
    
    db = SessionLocal()
    try:
        count = 0
        for i in range(0, len(lines), 3):
            if i + 2 >= len(lines):
                break
            
            name = lines[i].strip()
            tle1 = lines[i + 1].strip()
            tle2 = lines[i + 2].strip()
            
            # Extract NORAD ID from line 1
            try:
                norad_id = int(tle1.split()[1][:5])
            except:
                continue
            
            existing = db.query(TLEData).filter(TLEData.norad_id == norad_id).first()
            if not existing:
                tle_record = TLEData(
                    norad_id=norad_id,
                    satellite_name=name,
                    tle_line1=tle1,
                    tle_line2=tle2,
                    epoch=datetime.now(timezone.utc),
                    source='celestrak',
                    group_name='active'
                )
                db.add(tle_record)
                count += 1
                
                if count % 50 == 0:
                    print(f"Processed {count} satellites...")
        
        db.commit()
        print(f"✓ Added {count} satellites to database")
        
        # Verify
        total = db.query(TLEData).count()
        print(f"✓ Total satellites in database: {total}")
        
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()
else:
    print(f"Failed: {response.text[:500]}")
