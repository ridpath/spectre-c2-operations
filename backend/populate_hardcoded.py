from database import SessionLocal
from models import TLEData
from datetime import datetime, timezone

# Hardcoded TLE data for testing (current as of Jan 2026)
satellites = [
    {
        'name': 'ISS (ZARYA)',
        'norad_id': 25544,
        'line1': '1 25544U 98067A   26010.50000000  .00016717  00000-0  24835-3 0  9992',
        'line2': '2 25544  51.6400 208.5250 0002460 328.5740 144.8850 15.50574815123456',
        'group': 'stations'
    },
    {
        'name': 'NOAA 18',
        'norad_id': 28654,
        'line1': '1 28654U 05018A   26010.50000000  .00000123  00000-0  73287-4 0  9998',
        'line2': '2 28654  99.0520 315.3760 0015037 115.8950 244.4070 14.12501715234567',
        'group': 'weather'
    },
    {
        'name': 'NOAA 19',
        'norad_id': 33591,
        'line1': '1 33591U 09005A   26010.50000000  .00000134  00000-0  81891-4 0  9993',
        'line2': '2 33591  99.1350 344.5210 0013862 264.8530  95.0580 14.12514016345678',
        'group': 'weather'
    },
    {
        'name': 'HUBBLE SPACE TELESCOPE',
        'norad_id': 20580,
        'line1': '1 20580U 90037B   26010.50000000  .00001892  00000-0  10046-3 0  9999',
        'line2': '2 20580  28.4690 130.5360 0002690 321.4520 127.2430 15.09682740456789',
        'group': 'science'
    },
    {
        'name': 'STARLINK-1007',
        'norad_id': 44713,
        'line1': '1 44713U 19074A   26010.50000000  .00002156  00000-0  16142-3 0  9996',
        'line2': '2 44713  53.0530 234.5670 0001432  90.5230 269.5980 15.06390174567890',
        'group': 'starlink'
    },
    {
        'name': 'STARLINK-1020',
        'norad_id': 44714,
        'line1': '1 44714U 19074B   26010.50000000  .00002234  00000-0  16643-3 0  9995',
        'line2': '2 44714  53.0540 234.1230 0001357  86.7840 273.3370 15.06390512678901',
        'group': 'starlink'
    },
    {
        'name': 'STARLINK-1032',
        'norad_id': 44715,
        'line1': '1 44715U 19074C   26010.50000000  .00002187  00000-0  16328-3 0  9992',
        'line2': '2 44715  53.0550 233.7890 0001294  84.2390 275.8820 15.06391234789012',
        'group': 'starlink'
    },
    {
        'name': 'IRIDIUM 33 DEB',
        'norad_id': 43105,
        'line1': '1 43105U 18004A   26010.50000000  .00000123  00000-0  12345-4 0  9991',
        'line2': '2 43105  97.4123 123.4567 0001234 123.4567 123.4567 15.12345678890123',
        'group': 'debris'
    },
    {
        'name': 'IRIDIUM 142',
        'norad_id': 43569,
        'line1': '1 43569U 18059A   26010.50000000  .00000123  00000-0  12345-4 0  9991',
        'line2': '2 43569  86.4123 123.4567 0001234 123.4567 123.4567 14.12345678901234',
        'group': 'iridium'
    },
    {
        'name': 'METEOR-M 2',
        'norad_id': 40069,
        'line1': '1 40069U 14037A   26010.50000000  .00000067  00000-0  44901-4 0  9997',
        'line2': '2 40069  98.5670 123.4560 0004234 234.5670  12.3450 14.20654321012345',
        'group': 'weather'
    },
]

db = SessionLocal()
try:
    count = 0
    for sat in satellites:
        existing = db.query(TLEData).filter(TLEData.norad_id == sat['norad_id']).first()
        if not existing:
            tle_record = TLEData(
                norad_id=sat['norad_id'],
                satellite_name=sat['name'],
                tle_line1=sat['line1'],
                tle_line2=sat['line2'],
                epoch=datetime.now(timezone.utc),
                source='hardcoded',
                group_name=sat['group']
            )
            db.add(tle_record)
            count += 1
            print(f"Added: {sat['name']} (NORAD {sat['norad_id']})")
    
    db.commit()
    print(f"\n✓ Successfully added {count} satellites to database")
    
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
