# 📘 v1.11.13 - 서버 Outbound 트래픽 차단 문제 해결

**릴리즈 날짜**: 2026-01-14  
**타입**: 🔧 Bug Fix (Critical)  
**커밋**: a71bcf4

---

## 🎯 변경 요약

### 핵심 개선사항
1. **서버 Outbound 트래픽 차단 문제 해결** (Critical)
   - OUTPUT chain에 ESTABLISHED,RELATED,NEW 상태 허용 규칙 추가
   - Discord Webhook, GeoIP API 등 외부 연결 정상화

2. **GitHub Actions 저장공간 최적화**
   - 아티팩트 보존기간: 90일 → 3일
   - 저장공간 사용량 ~97% 감소

---

## 🐛 버그 수정

### 🔴 Critical: 서버 자신의 Outbound 트래픽이 차단되는 문제

**증상**:
```
[ERROR] persistent network error: Post "https://discord.com/api/..."
[ERROR] Auto-refresh change due to a permanent network error
[ERROR] statengine.go:161: state ensure error
```

**원인**:
- `firewall.go`의 OUTPUT chain에 ESTABLISHED,RELATED 허용 규칙 누락
- 서버가 시작한 HTTPS, DNS 요청이 차단됨

**영향 범위**:
- ❌ Discord Webhook 알림 전송 실패
- ❌ GeoIP 데이터베이스 자동 업데이트 실패
- ❌ 외부 API 호출 불가
- ❌ 시스템 업데이트 불가

**해결**:
```diff
// backend/services/firewall.go (Line 474-482)

sb.WriteString("-A INPUT -i lo -j ACCEPT\n")
sb.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
- sb.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
+ sb.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
+ 
+ // CRITICAL: Allow all outbound traffic from server (OUTPUT chain)
+ // This is essential for:
+ // - Discord webhook notifications (HTTPS to discord.com)
+ // - GeoIP database updates (HTTPS to MaxMind/IPinfo APIs)
+ // - DNS queries
+ // - System updates
+ sb.WriteString("-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n")
```

**검증**:
```bash
# 테스트 1: Discord API 접속
curl -v https://discord.com/api

# 테스트 2: Webhook 전송 (웹 UI)
Security Settings → Test Webhook → Success ✅

# 테스트 3: 로그 확인
journalctl -u kg-proxy | grep "webhook sent successfully"
```

---

## ⚙️ 개선사항

### GitHub Actions 아티팩트 보존기간 최적화

**변경**:
```diff
// .github/workflows/release.yml (Line 78-80)

- name: Create Release
  uses: softprops/action-gh-release@v2
  if: startsWith(github.ref, 'refs/tags/')
  with:
    files: |
      release.tar.gz
      install.sh
+   # Reduce storage usage: artifacts expire after 3 days
+   # GitHub's default is 90 days which consumes excessive storage
+   retention-days: 3
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**효과**:
- 저장공간 사용량: 90일분 → 3일분 (97% 감소)
- CI/CD 비용 절감
- 릴리즈 자동화는 영향 없음 (태그 기반 릴리즈는 영구 보존)

---

## 📊 영향 분석

### 사용자 경험 개선
| 기능 | 이전 | 이후 |
|------|------|------|
| Discord 알림 | ❌ 전송 실패 | ✅ 정상 작동 |
| GeoIP 업데이트 | ❌ 실패 | ✅ 자동 업데이트 |
| 웹 UI 접속 | ⚠️ 불안정 | ✅ 안정적 |
| 로그 에러 | 🔴 반복 발생 | ✅ 깨끗 |

### 보안 영향
- **OUTPUT chain 변경**: 서버가 시작한 연결만 허용 (수신 연결은 여전히 엄격 차단)
- **INPUT chain**: 변경 없음 (GeoIP, Flood Protection 유지)
- **위험도**: 낮음 (정상적인 outbound 트래픽 허용)

---

## 🚀 업그레이드 가이드

### 자동 업그레이드 (권장)
```bash
cd /opt/kg-proxy
sudo systemctl stop kg-proxy
wget https://github.com/AstralEUD/kg-proxy-web-gui/releases/download/v1.11.13/release.tar.gz
tar -xzf release.tar.gz
sudo systemctl start kg-proxy
```

### 수동 업그레이드 (Git)
```bash
cd /opt/kg-proxy
git pull origin main
git checkout v1.11.13
sudo systemctl restart kg-proxy
```

### 검증
```bash
# 1. 서비스 상태
systemctl status kg-proxy

# 2. 로그 확인 (에러 없어야 함)
journalctl -u kg-proxy -f

# 3. 웹 UI 접속 테스트
curl http://localhost:8080

# 4. Webhook 테스트 (웹 UI)
Security Settings → Discord Webhook → Test
```

---

## 🔄 롤백 방법

문제 발생 시:
```bash
# 이전 버전으로 복구
cd /opt/kg-proxy
git checkout v1.11.12
sudo systemctl restart kg-proxy
```

---

## 📚 관련 문서
- [Task Tracker](./.agent/artifacts/task.md)
- [Implementation Plan](./.agent/artifacts/implementation_plan.md)
- [Firewall 설정 가이드](./backend/services/firewall.go)

---

## 🙏 기여자
- **Antigravity Agent** (Google Deepmind)
- **사용자 피드백**: "어제까지 접속 잘됐는데 오늘 접속 안됨"
- **디버깅 기여**: VPS 콘솔 로그 분석

---

**다음 릴리즈 예정**: v1.12.0 (기능 추가 예정)
