import sqlite3

db_path = "armaguard.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get table schema
cursor.execute("PRAGMA table_info(security_settings)")
columns = cursor.fetchall()

print("=== security_settings 테이블 구조 ===\n")
for col in columns:
    print(f"Column: {col[1]}, Type: {col[2]}")

# Try to get the webhook URL
print("\n=== 현재 설정 값 ===\n")
cursor.execute("SELECT * FROM security_settings WHERE id=1")
result = cursor.fetchone()

if result:
    print(f"레코드 발견:")
    for i, col in enumerate(columns):
        print(f"  {col[1]}: {result[i]}")
else:
    print("설정이 없습니다.")

conn.close()
