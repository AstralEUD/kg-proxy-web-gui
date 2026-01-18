# 🔧 Fix Server Outbound Traffic Blocking Issue

## 📋 Task Overview
**Objective**: 서버 자신의 Outbound 트래픽이 차단되어 Discord Webhook 및 GeoIP API 호출이 실패하는 문제를 해결

**Priority**: 🔴 Critical (Production Issue)
**Created**: 2026-01-14 22:00 KST

---

## ✅ Completed Tasks

- [x] **문제 진단 완료**
  - Discord Webhook 전송 실패 원인 파악: OUTPUT chain에서 outbound 트래픽 차단
  - GeoIP API 호출 실패도 동일 원인
  - 로그 분석: "persistent network error: Post" 에러 근본 원인 확인

- [x] **방화벽 규칙 수정**
  - `firewall.go` OUTPUT chain에 ESTABLISHED,RELATED,NEW 상태 허용 규칙 추가
  - 서버의 HTTPS, DNS 등 모든 outbound 연결 허용
  - 주석으로 명확한 설명 추가 (Discord webhook, GeoIP API 등)

- [x] **GitHub Workflow 최적화**
  - `.github/workflows/release.yml` 수정
  - 아티팩트 보존기간: 90일 → 3일로 변경
  - 저장공간 사용량 대폭 감소 예상

---

## 🔄 Next Steps

- [ ] **코드 커밋 & 릴리즈**
  - Git commit with detailed message
  - 버전 태그 생성 (v1.11.13 - 버그 픽스)
  - GitHub에 푸시 및 릴리즈 트리거

- [ ] **서버 배포 및 검증**
  - VPS에 새 버전 배포
  - 방화벽 규칙 재적용
  - Discord Webhook 테스트
  - GeoIP 자동 업데이트 확인
  - 로그에서 "persistent network error" 사라짐 확인

---

## 📝 Technical Details

### 수정된 파일
1. `backend/services/firewall.go` (Line 474-482 추가)
   - OUTPUT chain에 outbound 트래픽 허용 규칙 추가
   
2. `.github/workflows/release.yml` (Line 78-80 추가)
   - `retention-days: 3` 설정 추가

### 변경 전 문제
```
:OUTPUT ACCEPT [0:0]
-A OUTPUT -o lo -j ACCEPT
# ❌ ESTABLISHED,RELATED 규칙 없음! 
```

### 변경 후 해결
```
:OUTPUT ACCEPT [0:0]
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
# ✅ 모든 outbound 연결 허용
```

---

## 🎯 Expected Outcome
- ✅ Discord Webhook 정상 작동
- ✅ GeoIP 데이터베이스 자동 업데이트 성공
- ✅ 외부 API 호출 정상화
- ✅ 로그 에러 제거
- ✅ GitHub Actions 저장공간 사용량 감소
