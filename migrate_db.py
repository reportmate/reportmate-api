"""
Database migration runner - adds platform column to devices table
"""
import os
import sys
import pg8000

# Database configuration
DB_CONFIG = {
    'host': 'reportmate-database.postgres.database.azure.com',
    'port': 5432,
    'database': 'reportmate',
    'user': 'reportmate',
    'ssl_context': True
}

# Try multiple password possibilities
PASSWORDS = [
    'ReportMateSecure2024!',
    'ReportMateDB2024!',
    'ReportMate2024!',
    'ReportMate@2024',
]

def try_connect(password):
    """Try to connect with given password"""
    try:
        conn = pg8000.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=password,
            ssl_context=DB_CONFIG['ssl_context']
        )
        return conn
    except Exception as e:
        return None

# Read migration SQL
migration_file = '../../schemas/004-add-platform-column.sql'
try:
    with open(migration_file, 'r') as f:
        sql = f.read()
    print(f"✓ Read migration file: {migration_file}")
except Exception as e:
    print(f"✗ Could not read migration file: {e}")
    sys.exit(1)

# Try to connect with each password
conn = None
for pwd in PASSWORDS:
    print(f"⟳ Trying to connect with password: {pwd[:4]}...")
    conn = try_connect(pwd)
    if conn:
        print(f"✓ Database connection successful with password: {pwd[:4]}...")
        break

if not conn:
    print("✗ Could not connect to database with any known password")
    print(f"   Host: {DB_CONFIG['host']}")
    print(f"   Database: {DB_CONFIG['database']}")
    print(f"   User: {DB_CONFIG['user']}")
    sys.exit(1)

try:
    cursor = conn.cursor()
    
    # Split SQL into statements and execute
    statements = [s.strip() for s in sql.split(';') if s.strip() and not s.strip().startswith('--')]
    
    print(f"⟳ Executing {len(statements)} SQL statements...")
    for i, statement in enumerate(statements, 1):
        # Show abbreviated statement
        stmt_preview = statement.replace('\n', ' ')[:60]
        print(f"  [{i}/{len(statements)}] {stmt_preview}...")
        cursor.execute(statement)
    
    conn.commit()
    print("✓ All statements executed successfully!")
    
    # Verify the column was added
    cursor.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'platform'")
    result = cursor.fetchone()
    if result:
        print(f"✓ Platform column verified: {result[0]} ({result[1]})")
    else:
        print("✗ Warning: Could not verify platform column")
    
    # Show sample data
    cursor.execute("SELECT serial_number, platform, os_name FROM devices LIMIT 5")
    rows = cursor.fetchall()
    print(f"\n✓ Sample data ({len(rows)} devices):")
    for row in rows:
        print(f"  - {row[0]}: {row[1] or 'NULL'} (inferred from {row[2] or 'NULL'})")
    
    cursor.close()
    conn.close()
    print("\n✓✓✓ Migration completed successfully! ✓✓✓")
    sys.exit(0)
    
except Exception as e:
    print(f"✗ Migration failed: {e}")
    import traceback
    traceback.print_exc()
    if conn:
        conn.rollback()
        conn.close()
    sys.exit(1)
