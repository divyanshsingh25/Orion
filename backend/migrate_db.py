import sqlite3

conn = sqlite3.connect('orion.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cursor.fetchall()]
print("Existing tables:", tables)

# Check if the new columns exist in scans table
cursor.execute("PRAGMA table_info(scans)")
columns = [r[1] for r in cursor.fetchall()]
print("Scans columns:", columns)

new_cols = ['recon_dns_json', 'recon_whois_json', 'recon_ports_json', 
            'recon_services_json', 'recon_os_json', 'endpoints_json',
            'requests_count', 'endpoints_count']

for col in new_cols:
    if col not in columns:
        if col in ('requests_count', 'endpoints_count'):
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {col} INTEGER DEFAULT 0")
        else:
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {col} JSON")
        print(f"Added column: {col}")
    else:
        print(f"Column exists: {col}")

# Migrate ai_analysis table
cursor.execute("PRAGMA table_info(ai_analysis)")
ai_columns = [r[1] for r in cursor.fetchall()]
print("AI Analysis columns:", ai_columns)

ai_new_cols = [
    ("verification_verdict", "TEXT DEFAULT 'POTENTIAL'"),
    ("verification_reasoning", "TEXT"),
    ("verification_confidence", "NUMERIC DEFAULT 0.50"),
]

for col_name, col_type in ai_new_cols:
    if col_name not in ai_columns:
        cursor.execute(f"ALTER TABLE ai_analysis ADD COLUMN {col_name} {col_type}")
        print(f"Added column to ai_analysis: {col_name}")
    else:
        print(f"Column exists in ai_analysis: {col_name}")

conn.commit()
conn.close()
print("Database migration complete!")
