# 🔧 서버 Outbound 트래픽 차단 문제 해결 - 구현 계획

**버전**: v1.11.13  
**생성일**: 2026-01-14 22:00 KST  
**우선순위**: 🔴 Critical

---

## 📊 문제 분석

### 증상
- Discord Webhook 전송 실패 ("persistent network error: Post")
- GeoIP 데이터베이스 자동 업데이트 실패
- 외부 API 호출 불가
- 서비스는 실행 중이나 웹 포트(8080) 응답 없음

### 근본 원인
**iptables OUTPUT chain에서 서버 자신의 outbound 트래픽이 차단됨**

```iptables
# 문제 코드 (firewall.go Line 466-473)
:OUTPUT ACCEPT [0:0]
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# ❌ OUTPUT chain에는 ESTABLISHED,RELATED 규칙 없음!
```

**영향 범위**:
- Discord webhook (HTTPS to discord.com)
- GeoIP API 호출 (MaxMind, IPinfo.io)
- DNS 쿼리
- 시스템 업데이트
- 모든 서버-initiated HTTP(S) 요청

---

## 🎯 해결 방안

### 1. 방화벽 규칙 수정

**파일**: `backend/services/firewall.go`  
**위치**: Line 474-482 (OUTPUT chain 섹션)

**변경 내용**:
```go
// CRITICAL: Allow all outbound traffic from server (OUTPUT chain)
// This is essential for:
// - Discord webhook notifications (HTTPS to discord.com)
// - GeoIP database updates (HTTPS to MaxMind/IPinfo APIs)
// - DNS queries
// - System updates
// Without this, the server cannot initiate external connections
sb.WriteString("-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n")
```

**적용 시점**: iptables-restore 실행 시 (`ApplyRules()` 호출)

**검증 방법**:
```bash
# 1. 방화벽 규칙 확인
iptables -L OUTPUT -n -v

# 2. Discord 접속 테스트
curl -v https://discord.com/api

# 3. Webhook 테스트 (웹 UI)
Security Settings → Test Webhook

# 4. 로그 확인
journalctl -u kg-proxy -f | grep -i "webhook\|network error"
```

---

### 2. GitHub Actions 최적화

**파일**: `.github/workflows/release.yml`  
**위치**: Line 78-80

**변경 내용**:
```yaml
# Reduce storage usage: artifacts expire after 3 days
# GitHub's default is 90 days which consumes excessive storage
retention-days: 3
```

**효과**:
- 아티팩트 보존기간: 90일 → 3일
- 저장공간 사용량: ~97% 감소
- 비용 절감 (GitHub Actions storage quota)

---

## 🚀 배포 절차

### VPS 배포 (Linux)

```bash
# 1. 백업
cd /opt/kg-proxy
sudo cp armaguard.db armaguard.db.backup

# 2. 새 버전 다운로드
wget https://github.com/AstralEUD/kg-proxy-web-gui/releases/download/v1.11.13/release.tar.gz
tar -xzf release.tar.gz

# 3. 서비스 재시작
sudo systemctl restart kg-proxy

# 4. 로그 확인
sudo journalctl -u kg-proxy -f
```

### 기대 결과
✅ "persistent network error" 에러 사라짐  
✅ "Discord webhook sent successfully" 로그 확인  
✅ GeoIP 자동 업데이트 정상 작동  
✅ 웹 UI 정상 접속 (http://서버IP:8080)

---

## 🔍 위험 평가

| 위험 | 가능성 | 영향 | 완화 방안 |
|------|--------|------|-----------|
| OUTPUT chain 규칙으로 인한 보안 취약점 | 낮음 | 중간 | OUTPUT은 서버에서 시작한 연결만 허용, INPUT은 여전히 엄격 |
| 방화벽 재적용 실패 | 낮음 | 높음 | SSH 접속 유지, 수동 rollback 가능 |
| 기존 연결 끊김 | 낮음 | 낮음 | ESTABLISHED,RELATED 규칙이 기존 연결 보호 |

**Rollback 계획**:
```bash
# 이전 버전으로 복구
git checkout v1.11.12
sudo systemctl restart kg-proxy
```

---

## 📈 검증 체크리스트

### 즉시 확인 (배포 후 5분 이내)
- [ ] 서비스 정상 실행 (`systemctl status kg-proxy`)
- [ ] 웹 UI 접속 가능
- [ ] 로그에 에러 없음
- [ ] Discord Webhook 테스트 성공

### 지연 확인 (배포 후 24시간)
- [ ] GeoIP 자동 업데이트 성공 (12시간 후)
- [ ] 주기적 통계 리포트 정상 전송
- [ ] 메모리/CPU 사용량 정상
- [ ] 트래픽 차단 기능 정상 작동

---

## 📝 관련 이슈
- Conversation: `bb6d2149-036c-4449-b498-c2f111d5876b`
- 사용자 보고: "어제까지 접속 잘됐는데 오늘 접속 안됨"
- 로그 증거: uploaded_image_0_1768394609352.png, uploaded_image_1_1768394609352.png
