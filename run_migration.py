"""
Database migration runner that uses the same connection as main.py
Run this from the API modules directory
"""
import os
import sys

# Set up environment if not already set
if 'DB_HOST' not in os.environ:
    os.environ['DB_HOST'] = 'reportmate-database.postgres.database.azure.com'
    os.environ['DB_NAME'] = 'reportmate'
    os.environ['DB_USER'] = 'reportmate'
    # Try multiple password possibilities
    passwords = [
        'ReportMateSecure2024!',
        'ReportMateDB2024!',
        'ReportMate2024!',
    ]
else:
    passwords = [os.environ.get('DB_PASSWORD', 'ReportMateSecure2024!')]

# Import the same connection function from main.py
try:
    from main import get_db_connection
    print("✓ Successfully imported get_db_connection from main.py")
    
    # Read migration SQL
    migration_file = '../../schemas/004-add-platform-column.sql'
    with open(migration_file, 'r') as f:
        sql = f.read()
    
    print(f"✓ Read migration file: {migration_file}")
    
    # Try to connect and run migration
    print("⟳ Attempting database connection...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print("✓ Database connection successful!")
        
        # Split SQL into statements and execute
        statements = [s.strip() for s in sql.split(';') if s.strip() and not s.strip().startswith('--')]
        
        print(f"⟳ Executing {len(statements)} SQL statements...")
        for i, statement in enumerate(statements, 1):
            print(f"  [{i}/{len(statements)}] {statement[:60]}...")
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
        print(f"\\n✓ Sample data ({len(rows)} devices):")
        for row in rows:
            print(f"  - {row[0]}: {row[1]} (from {row[2]})")
        
        cursor.close()
        conn.close()
        print("\\n✓✓✓ Migration completed successfully! ✓✓✓")
        sys.exit(0)
        
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
        
except ImportError as e:
    print(f"✗ Could not import from main.py: {e}")
    print("Make sure you're running this from the infrastructure/azure/modules/api directory")
    sys.exit(1)
