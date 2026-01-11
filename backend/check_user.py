import sqlite3

conn = sqlite3.connect('spectre_c2.db')
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("Tables in database:")
for table in tables:
    print(f"  - {table[0]}")

# Check if users table exists
if any('user' in table[0].lower() for table in tables):
    # Find the actual users table name
    user_table = [t[0] for t in tables if 'user' in t[0].lower()][0]
    print(f"\nQuerying {user_table} table:")
    cursor.execute(f'SELECT * FROM {user_table} LIMIT 5')
    rows = cursor.fetchall()
    
    # Get column names
    cursor.execute(f'PRAGMA table_info({user_table})')
    columns = cursor.fetchall()
    col_names = [col[1] for col in columns]
    print(f"Columns: {col_names}")
    
    for row in rows:
        print(row)
else:
    print("\nNo users table found!")

conn.close()
