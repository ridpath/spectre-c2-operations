import asyncio
from satellite_tle_fetcher import tle_fetcher
from database import SessionLocal
from models import TLEData
from datetime import datetime, timezone

async def populate():
    print("Fetching satellites from CelesTrak...")
    results = await tle_fetcher.fetch_all_sources(celestrak_groups=['active'])
    merged = tle_fetcher.merge_satellite_data(results)
    
    print(f"Fetched {len(merged)} satellites")
    
    db = SessionLocal()
    try:
        count = 0
        for sat in merged:
            existing = db.query(TLEData).filter(TLEData.norad_id == sat['norad_id']).first()
            if not existing:
                # Handle both field name formats
                tle1 = sat.get('tle_line1') or sat.get('line1')
                tle2 = sat.get('tle_line2') or sat.get('line2')
                
                if not tle1 or not tle2:
                    continue
                
                tle_record = TLEData(
                    norad_id=sat['norad_id'],
                    satellite_name=sat['name'],
                    tle_line1=tle1,
                    tle_line2=tle2,
                    epoch=sat.get('epoch', datetime.now(timezone.utc)),
                    source=sat.get('source', 'celestrak'),
                    group_name=sat.get('group', None)
                )
                db.add(tle_record)
                count += 1
                
                if count % 500 == 0:
                    db.commit()
                    print(f"Progress: {count} satellites added...")
        
        db.commit()
        print(f"Added {count} new satellites to database")
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(populate())
