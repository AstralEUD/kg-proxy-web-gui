# KG-Proxy Web GUI

ArmaGuard DDoS 프록시 시스템을 위한 웹 기반 관리 인터페이스입니다.

## 📋 개요

이 프로젝트는 WireGuard VPN 기반 게임 서버 보호 프록시를 관리하기 위한 모던 웹 GUI를 제공합니다. 실시간 트래픽 모니터링, 방화벽 규칙 관리, Origin 서버 설정 등의 기능을 포함합니다.

### Mock 모드 vs Live 모드

| 모드 | 실행 환경 | 데이터 소스 |
|------|----------|------------|
| **MOCK** | Windows | 시뮬레이션 데이터 (개발용) |
| **LIVE** | Linux | 실제 시스템 정보 (운영용) |

> ⚠️ **Windows에서 실행 시 대시보드에 MOCK 배지가 표시되며, 모든 데이터는 테스트용 목업입니다.**

---

## 🛠 시스템 요구사항

### Linux 서버 (운영 환경)

- **OS**: Ubuntu 22.04 LTS / Debian 12 이상 권장
- **Runtime**:
  - Go 1.21+
  - Node.js 18+ (프론트엔드 빌드용)
- **시스템 패키지**:
  - WireGuard (`wireguard-tools`)
  - iptables / nftables
  - ipset

### 개발 환경 (Windows/macOS)

- Go 1.21+
- Node.js 18+
- (시스템 명령어는 Mock 모드로 시뮬레이션됨)

---

## 📦 설치 방법

### 1. 저장소 클론 및 빌드
(로컬 개발 환경에서 수행)

```bash
# 1. 소스 클론
git clone https://github.com/AstralEUD/kg-proxy-web-gui.git
cd kg-proxy-web-gui

# 2. 백엔드 빌드 (Linux용)
cd backend
GOOS=linux GOARCH=amd64 go build -o ../kg-proxy-backend .
cd ..

# 3. 프론트엔드 빌드
cd frontend
npm install
npm run build
cd ..
```

### 2. 파일 업로드 및 설치
(Linux 서버에서 수행)

1. 빌드된 파일(`kg-proxy-backend`, `frontend/dist`)과 `install.sh`를 서버로 업로드합니다.
2. 설치 스크립트를 실행합니다.

```bash
chmod +x install.sh
sudo ./install.sh
```

스크립트가 자동으로 다음 작업을 수행합니다:
- 필수 패키지 설치 (`wireguard`, `iptables` 등)
- `/opt/kg-proxy` 경로에 파일 배포
- Systemd 서비스 등록 및 자동 시작
- 방화벽 포트(8080, 51820) 오픈

---

## 💻 개발 모드 실행

### 백엔드 (Go)

```bash
cd backend
go run .
```

서버가 `http://localhost:8080`에서 시작됩니다.

### 프론트엔드 (Vite + React)

```bash
cd frontend
npm run dev
```

개발 서버가 `http://localhost:5173`에서 시작됩니다.

---

## 🔒 프로덕션 권장 사항

### Nginx 리버스 프록시 (선택적)

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        root /opt/kg-proxy/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### SSL/TLS 설정 (Let's Encrypt)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## 📁 프로젝트 구조

```
kg-proxy-web-gui/
├── backend/
│   ├── main.go           # 진입점
│   ├── handlers/         # HTTP 핸들러
│   ├── services/         # 비즈니스 로직 (Firewall, WireGuard)
│   ├── models/           # 데이터 모델
│   └── system/           # 시스템 명령어 실행 (Mock/Real)
├── frontend/
│   ├── src/
│   │   ├── pages/        # React 페이지 컴포넌트
│   │   ├── components/   # 재사용 컴포넌트
│   │   └── api/          # API 클라이언트
│   └── dist/             # 빌드 출력
└── README.md
```

---

## 📝 API 엔드포인트

| Method | Endpoint | 설명 |
|--------|----------|------|
| POST | `/api/login` | 사용자 로그인 |
| PUT | `/api/auth/password` | 비밀번호 변경 |
| GET | `/api/origins` | Origin 목록 조회 |
| POST | `/api/origins` | Origin 추가 |
| GET | `/api/status` | 시스템 상태 조회 |
| GET | `/api/events` | 시스템 이벤트 조회 |
| GET | `/api/firewall/status` | 방화벽 규칙 조회 |
| POST | `/api/firewall/apply` | 방화벽 규칙 적용 |
| GET | `/api/users` | 사용자 목록 |
| POST | `/api/users` | 사용자 생성 |
| DELETE | `/api/users/:id` | 사용자 삭제 |

---

## 🔧 문제 해결

### 백엔드가 시작되지 않는 경우

```bash
# 로그 확인
sudo journalctl -u kg-proxy -f

# 권한 확인 (iptables 실행에 root 필요)
sudo /opt/kg-proxy/kg-proxy-backend
```

### WireGuard 명령어 오류

```bash
# WireGuard 설치 확인
which wg
wg --version

# 모듈 로드 확인
lsmod | grep wireguard
```

### 데이터베이스 초기화

```bash
# 기존 DB 삭제 후 재시작 (데이터 손실 주의)
rm /opt/kg-proxy/armaguard.db
sudo systemctl restart kg-proxy
```

---

## 📄 라이선스

이 프로젝트는 내부 사용 목적으로 개발되었습니다.
