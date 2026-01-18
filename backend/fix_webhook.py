import sqlite3
import sys

db_path = "armaguard.db"

def check_webhook():
    """Check current webhook URL"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # GORM uses snake_case for column names
    cursor.execute("SELECT id, discord_webhook_url  FROM security_settings WHERE id=1")
    result = cursor.fetchone()
    
    if result:
        print(f"현재 Webhook URL: {result[1] if result[1] else '(비어있음)'}")
        return result[1]
    else:
        print("Security settings not found")
        return None
    
    conn.close()

def disable_webhook():
    """Disable webhook by clearing the URL"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE security_settings SET discord_webhook_url = '' WHERE id=1")
    conn.commit()
    
    print("✅ Discord Webhook이 비활성화되었습니다.")
    conn.close()

if __name__ == "__main__":
    print("=== Discord Webhook 진단 도구 ===\n")
    
    current_url = check_webhook()
    
    if current_url:
        print(f"\n이 URL로 접속 시도 중 에러가 발생하고 있습니다.")
        print("Discord Webhook을 비활성화하시겠습니까? (y/n): ", end="")
        
        choice = input().lower()
        if choice == 'y':
            disable_webhook()
            print("\n서비스를 재시작하면 에러가 해결됩니다.")
        else:
            print("취소되었습니다.")
