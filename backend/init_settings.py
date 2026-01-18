import sqlite3
import sys

db_path = "armaguard.db"

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get actual table info
    cursor.execute("PRAGMA table_info(security_settings)")
    columns = cursor.fetchall()
    
    print("=== 테이블 컬럼 목록 ===")
    col_names = []
    for col in columns:
        col_names.append(col[1])
        print(f"  - {col[1]}")
    
    print("\n=== 기본 설정 생성 중 ===")
    
 # Build INSERT with only known columns
    # Start with minimal required fields
    values_dict = {
        'id': 1
    }
    
    # Only add columns that exist
    if 'global_protection' in col_names:
        values_dict['global_protection'] = 1
    if 'protection_level' in col_names:
        values_dict['protection_level'] = 2
    if 'discord_webhook_url' in col_names:
        values_dict['discord_webhook_url'] = ''
    if 'steam_query_bypass' in col_names:
        values_dict['steam_query_bypass'] = 1
    if 'ebpf_enabled' in col_names:
        values_dict['ebpf_enabled'] = 0
    if 'geo_allowed_countries' in col_names:
        values_dict['geo_allowed_countries'] = 'KR'
    if 'xdp_hard_blocking' in col_names:
        values_dict['xdp_hard_blocking'] = 0
    if 'xdp_rate_limit_pps' in col_names:
        values_dict['xdp_rate_limit_pps'] = 0
    if 'attack_history_days' in col_names:
        values_dict['attack_history_days'] = 30
    if 'syn_cookies' in col_names:
        values_dict['syn_cookies'] = 1
    if 'alert_on_attack' in col_names:
        values_dict['alert_on_attack'] = 1
    if 'alert_on_block' in col_names:
        values_dict['alert_on_block'] = 0
    
    # Build SQL
    cols = ', '.join(values_dict.keys())
    placeholders = ', '.join(['?' for _ in values_dict])
    sql = f"INSERT OR REPLACE INTO security_settings ({cols}) VALUES ({placeholders})"
    
    cursor.execute(sql, list(values_dict.values()))
    conn.commit()
    
    print("✅ 기본 보안 설정이 생성되었습니다!")
    print("✅  Discord Webhook: 비활성화")
    print("\n이제 서비스를 재시작해주세요.")
    
    conn.close()
    
except Exception as e:
    print(f"❌ 에러 발생: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
