# Arma Reforger DDoS 방어 중계 프록시 완전 가이드

## 개요

이 지침서는 **Vultr Seoul 프록시 1대 + WireGuard full-tunnel로 오리진 6대 연결 + iptables/ipset(GeoIP/allowlist/ban/flood 완화) + 자체 Web GUI(단일, React + Go 백엔드)**로 구축하는 "공개 서버 리스트 노출은 유지하면서" 오리진(자택/개별 서버)의 IP를 숨기고, **클라이언트 원본 IP를 오리진에 그대로 보내는** DDoS 방어 중계 인프라를 완벽히 구축하기 위한 단계별 지침입니다.

### 핵심 목표
- **DDoS 1차 완화**: Vultr DDoS Protection(AMF, 인스턴스당 10Gbps L3/L4 TCP/UDP)  
- **DDoS 2차 정책**: Ubuntu/Debian의 iptables/ipset으로 "한국만 허용 + 해외는 개별 IP 예외 + 포트별 flood 완화"  
- **트래픽 분산**: 단일 프록시에서 멀티 오리진(6대)으로 WireGuard full-tunnel 중계  
- **원본 IP 보존**: DNAT만 사용(SNAT 금지) + full-tunnel 대칭 경로로 클라이언트 IP 그대로 전달  
- **통합 관리**: 단일 Web GUI에서 오리진/서비스/정책/방어 프리셋을 모두 관리  

---

## 1. 준비물 및 사전 설정

### 1.1 하드웨어/클라우드 환경

| 항목 | 사양 | 비고 |
|---|---|---|
| 프록시(VPS) | Vultr Seoul, 2GB RAM, 40GB SSD, 고정 공인 IPv4 | Vultr DDoS Protection 옵션 필수 |
| 오리진(자택/IDC) | 6대, 각각 IPv4 주소(공인/사설), Arma Reforger 서버 | Reforger는 기본 포트(20001/17777/27016) 유지 |
| 네트워크 | 프록시→오리진: 안정적인 WireGuard 터널 | ISP에서 UDP 51820 블록 없음 확인 |

### 1.2 프록시 VPS 초기화

**OS**: Debian 12(권장) 또는 Ubuntu 24.04  
**DNS**: Vultr DDoS Protection을 받으려면 리졸버를 108.61.10.10으로 설정해야 함(필수)  

```bash
# DNS 확인/수정
cat /etc/resolv.conf
# 혹은 Vultr 대시보드에서 설정

# 시스템 업데이트
apt update && apt upgrade -y

# 필수 패키지 설치
apt install -y \
  wireguard wireguard-tools \
  iptables ipset \
  curl wget git \
  python3 python3-pip \
  postgresql-client  # (옵션, 이후 DB 연동용)
```

**iptables 백엔드 확인**(Debian 12부터는 nft 백엔드가 기본):
```bash
# 현재 상태 확인
update-alternatives --display iptables

# 필요시 legacy로 전환(ipset과 호환성 좋음)
update-alternatives --set iptables /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

### 1.3 디렉터리 생성

```bash
mkdir -p /etc/armaguard
mkdir -p /var/lib/armaguard/{db,logs,tmp}
mkdir -p /usr/local/bin
chmod 700 /etc/armaguard /var/lib/armaguard
```

### 1.4 IPv4 Forwarding 활성화(라우터 역할)

```bash
cat > /etc/sysctl.d/99-armaguard.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF

sysctl --system
sysctl -p
```

---

## 2. 네트워크 설계

### 2.1 주소 계획(IPv4 only, 오리진 6대)

**프록시 WireGuard**:
- Interface: `wg0`
- 내부 서브넷: `10.200.0.0/24`
- 프록시 IP: `10.200.0.1`

**오리진 WireGuard 클라이언트**(full-tunnel):
- 오리진 0: `10.200.0.2/32`
- 오리진 1: `10.200.0.3/32`
- 오리진 2: `10.200.0.4/32`
- 오리진 3: `10.200.0.5/32`
- 오리진 4: `10.200.0.6/32`
- 오리진 5: `10.200.0.7/32`

### 2.2 포트 배정(멀티 서버)

Arma Reforger 기본 포트: 게임(UDP 20001), 서버 브라우저(UDP 17777), Steam Query(UDP 27016)

**프록시가 외부에 노출하는 포트** (오리진은 기본 포트 고정, 외부만 시프트):
- 서버 0: 20001/17777/27016 → 오리진 0(10.200.0.2):20001/17777/27016
- 서버 1: 20011/17787/27026 → 오리진 1(10.200.0.3):20001/17777/27016
- 서버 2: 20021/17797/27036 → 오리진 2(10.200.0.4):20001/17777/27016
- 서버 3: 20031/17807/27046 → 오리진 3(10.200.0.5):20001/17777/27016
- 서버 4: 20041/17817/27056 → 오리진 4(10.200.0.6):20001/17777/27016
- 서버 5: 20051/17827/27066 → 오리진 5(10.200.0.7):20001/17777/27016

배정 규칙: `public_port = base + index * stride` (stride=10)

### 2.3 원본 IP 보존 원리

1. **DNAT만 사용**(SNAT/MASQUERADE 금지): 프록시가 목적지(오리진 WG IP)만 바꾸고, 출발지(클라이언트 IP)는 그대로 둠
2. **full-tunnel 대칭 경로**: 오리진은 응답을 반드시 WireGuard 터널을 통해 프록시로 보내야 함(AllowedIPs=0.0.0.0/0, 단 endpoint 제외)
3. **결과**: 오리진 애플리케이션(Reforger)은 클라이언트 원본 IP를 `getpeername()`으로 읽을 수 있음

---

## 3. WireGuard 설정

### 3.1 프록시(VPS) 서버 설정: `/etc/wireguard/wg0.conf`

먼저 키 생성:
```bash
wg genkey | tee /etc/wireguard/server_privatekey | wg pubkey > /etc/wireguard/server_publickey
chmod 600 /etc/wireguard/server_privatekey*
```

설정 파일:
```ini
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/server_privatekey)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -s 10.200.0.0/24 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -s 10.200.0.0/24 -j MASQUERADE

# 오리진 0
[Peer]
PublicKey = <origin_0_publickey>
AllowedIPs = 10.200.0.2/32

# 오리진 1
[Peer]
PublicKey = <origin_1_publickey>
AllowedIPs = 10.200.0.3/32

# ... (오리진 2~5도 같은 방식, AllowedIPs는 /32로 제한)

[Peer]
PublicKey = <origin_5_publickey>
AllowedIPs = 10.200.0.7/32
```

**핵심**: 각 Peer의 `AllowedIPs`는 **절대 0.0.0.0/0로 두면 안 되고**, 해당 오리진의 WG IP(/32)만 설정. 이렇게 해야 6대 오리진 간 라우팅 충돌이 없음.

### 3.2 오리진 클라이언트 설정 생성(파이썬 스니펫)

**원본 IP 보존 핵심**: 오리진은 `AllowedIPs=0.0.0.0/0`를 쓰되, **VPS Endpoint까지 터널로 보내면 자기 자신을 우회**하는 문제가 있어서, "0.0.0.0/0에서 특정 대역을 빼는" 리스트를 생성해야 함.

```python
#!/usr/bin/env python3
import ipaddress
import json

def generate_allowedips_exclude(vps_public_ip, origin_local_lan):
    """
    0.0.0.0/0에서 특정 CIDR를 제외한 리스트 생성
    """
    exclude = [
        ipaddress.ip_network(vps_public_ip),
        ipaddress.ip_network(origin_local_lan),
        ipaddress.ip_network("169.254.0.0/16"),  # link-local
        ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ]
    
    base = ipaddress.ip_network("0.0.0.0/0")
    result = []
    for subnet in base.address_exclude(*exclude):
        result.append(str(subnet))
    
    return ",".join(result)

# 예시
vps_ip = "X.X.X.X/32"
origin_lan = "192.168.0.0/16"
allowed = generate_allowedips_exclude(vps_ip, origin_lan)
print(f"AllowedIPs = {allowed}")
```

**오리진 client config** (각 오리진별로 생성/배포):
```ini
[Interface]
Address = 10.200.0.2/32
PrivateKey = <origin_privatekey>
DNS = 8.8.8.8

[Peer]
PublicKey = <vps_publickey>
Endpoint = <VPS_PUBLIC_IP>:51820
AllowedIPs = <generated_cidrs_above>
PersistentKeepalive = 25
```

---

## 4. 방화벽 설정(iptables/ipset)

### 4.1 ipset 정의: `/etc/armaguard/ipset.rules`

ipset의 restore 포맷으로, 총 3개 세트를 정의 (룰은 고정, 세트만 변경):

```text
create geo_kr hash:net family inet -exist
create allow_foreign hash:ip family inet -exist
create ban hash:ip family inet -exist

flush geo_kr
flush allow_foreign
flush ban

# geo_kr: 한국 CIDR(자동 갱신 서비스가 채움)
# allow_foreign: 해외 예외 허용 IP(GUI에서 추가)
# ban: 차단 IP(GUI에서 추가/만료)
```

### 4.2 iptables 규칙: `/etc/armaguard/iptables.rules.v4`

아래는 "정책 체인 고정 + 서비스별 DNAT 생성"하는 구조입니다. GUI가 서비스를 추가할 때 `*nat` 섹션의 DNAT 라인만 추가하면 됨.

```text
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ARMA_GUARD - [0:0]

# === INPUT: 프록시 자신의 트래픽 ===
# 기본 연결 허용
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT

# SSH(관리용)
-A INPUT -p tcp --dport 22 -j ACCEPT

# WireGuard 리스닝
-A INPUT -p udp --dport 51820 -j ACCEPT

# 백엔드 API(예: 8080)
-A INPUT -p tcp --dport 8080 -j ACCEPT

# === FORWARD: 패킷 포워딩(eth0 ↔ wg0) ===
-A FORWARD -i eth0 -o wg0 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i wg0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

COMMIT

*mangle
:PREROUTING ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ARMA_PRE - [0:0]
:ARMA_GUARD - [0:0]

# === PREROUTING: 게임 포트 도착 패킷 정책 체크 ===
# 프록시가 중계하는 모든 포트(서버 6개 * 3포트 = 18포트)
-A PREROUTING -i eth0 -p udp -m multiport --dports 20001,17777,27016,20011,17787,27026,20021,17797,27036,20031,17807,27046,20041,17817,27056,20051,17827,27066 -j ARMA_PRE

# === 정책 체인: ban -> (KR or allow_foreign) -> drop ===
-A ARMA_GUARD -m set --match-set ban src -j DROP
-A ARMA_GUARD -m set --match-set geo_kr src -j RETURN
-A ARMA_GUARD -m set --match-set allow_foreign src -j RETURN
-A ARMA_GUARD -j DROP

# === ARMA_PRE: 국가 정책 + flood 완화 ===
-A ARMA_PRE -j ARMA_GUARD

# (선택) Flood 완화: hashlimit(단위: /second, 값은 튜닝)
# A2S(Steam Query, 27016): PPS 상한 30, 버스트 60
-A ARMA_PRE -p udp --dport 27016 -m hashlimit --hashlimit-above 30/second --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name A2S_PPS -j DROP

# 서버 브라우저(17777): PPS 상한 50, 버스트 100
-A ARMA_PRE -p udp --dport 17777 -m hashlimit --hashlimit-above 50/second --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name BROWSER_PPS -j DROP

# 게임 포트(20001): PPS 상한 300, 버스트 600(쿼리보다 관대)
-A ARMA_PRE -p udp --dport 20001 -m hashlimit --hashlimit-above 300/second --hashlimit-burst 600 --hashlimit-mode srcip --hashlimit-name GAME_PPS -j DROP

COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ARMA_DNAT - [0:0]

# === DNAT: 외부 포트 → 오리진 WG IP(원본 IP 보존) ===
# 서버 0(오리진 0: 10.200.0.2)
-A PREROUTING -i eth0 -p udp --dport 20001 -j DNAT --to-destination 10.200.0.2:20001
-A PREROUTING -i eth0 -p udp --dport 17777 -j DNAT --to-destination 10.200.0.2:17777
-A PREROUTING -i eth0 -p udp --dport 27016 -j DNAT --to-destination 10.200.0.2:27016

# 서버 1(오리진 1: 10.200.0.3)
-A PREROUTING -i eth0 -p udp --dport 20011 -j DNAT --to-destination 10.200.0.3:20001
-A PREROUTING -i eth0 -p udp --dport 17787 -j DNAT --to-destination 10.200.0.3:17777
-A PREROUTING -i eth0 -p udp --dport 27026 -j DNAT --to-destination 10.200.0.3:27016

# 서버 2(오리진 2: 10.200.0.4)
-A PREROUTING -i eth0 -p udp --dport 20021 -j DNAT --to-destination 10.200.0.4:20001
-A PREROUTING -i eth0 -p udp --dport 17797 -j DNAT --to-destination 10.200.0.4:17777
-A PREROUTING -i eth0 -p udp --dport 27036 -j DNAT --to-destination 10.200.0.4:27016

# 서버 3(오리진 3: 10.200.0.5)
-A PREROUTING -i eth0 -p udp --dport 20031 -j DNAT --to-destination 10.200.0.5:20001
-A PREROUTING -i eth0 -p udp --dport 17807 -j DNAT --to-destination 10.200.0.5:17777
-A PREROUTING -i eth0 -p udp --dport 27046 -j DNAT --to-destination 10.200.0.5:27016

# 서버 4(오리진 4: 10.200.0.6)
-A PREROUTING -i eth0 -p udp --dport 20041 -j DNAT --to-destination 10.200.0.6:20001
-A PREROUTING -i eth0 -p udp --dport 17817 -j DNAT --to-destination 10.200.0.6:17777
-A PREROUTING -i eth0 -p udp --dport 27056 -j DNAT --to-destination 10.200.0.6:27016

# 서버 5(오리진 5: 10.200.0.7)
-A PREROUTING -i eth0 -p udp --dport 20051 -j DNAT --to-destination 10.200.0.7:20001
-A PREROUTING -i eth0 -p udp --dport 17827 -j DNAT --to-destination 10.200.0.7:17777
-A PREROUTING -i eth0 -p udp --dport 27066 -j DNAT --to-destination 10.200.0.7:27016

# === POSTROUTING: 오리진(full-tunnel)의 인터넷 사용을 위한 NAT ===
# 오리진 WG 대역이 외부 인터넷(eth0)으로 나갈 때만 MASQUERADE
-A POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE

COMMIT
```

---

## 5. systemd 자동화

### 5.1 ipset 복원 서비스: `/etc/systemd/system/armaguard-ipset.service`

ipset을 먼저 로드해야 iptables-restore가 실패하지 않음.

```ini
[Unit]
Description=ArmaGuard - Restore ipset sets
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ipset restore < /etc/armaguard/ipset.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

### 5.2 iptables 복원 서비스: `/etc/systemd/system/armaguard-iptables.service`

ipset이 있어야 하므로 ipset 서비스에 의존.

```ini
[Unit]
Description=ArmaGuard - Restore iptables rules
After=network-online.target armaguard-ipset.service
Wants=network-online.target
Requires=armaguard-ipset.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/armaguard/iptables.rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

### 5.3 WireGuard 시작: `/etc/systemd/system/wg-quick@wg0.service`

Debian에서 기본 제공되지만, 명시적으로 수동 시작하려면:

```bash
systemctl enable --now wg-quick@wg0
```

### 5.4 백엔드(API) 서비스: `/etc/systemd/system/armaguard-api.service`

```ini
[Unit]
Description=ArmaGuard API (Control Plane)
After=wg-quick@wg0.service armaguard-iptables.service
Wants=wg-quick@wg0.service
Requires=armaguard-iptables.service

[Service]
Type=simple
User=armaguard
WorkingDirectory=/var/lib/armaguard
ExecStart=/usr/local/bin/armaguard-api --config /etc/armaguard/config.yaml
Restart=always
RestartSec=2s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

사용자 생성:
```bash
useradd -r -s /bin/false armaguard
chown -R armaguard:armaguard /var/lib/armaguard
```

### 5.5 GeoIP 업데이트(선택이지만 권장): `/etc/systemd/system/armaguard-geoip.service`

한국 CIDR을 정기적으로 갱신하려면:

```ini
[Unit]
Description=ArmaGuard - Update KR GeoIP set
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/armaguard-update-geoip
StandardOutput=journal
StandardError=journal
```

및 타이머: `/etc/systemd/system/armaguard-geoip.timer`

```ini
[Unit]
Description=ArmaGuard - GeoIP update timer

[Timer]
OnBootSec=1h
OnUnitActiveSec=1d
Persistent=true

[Install]
WantedBy=timers.target
```

---

## 6. 서버 시작/부팅 명령

### 6.1 한 번에 모두 활성화

```bash
# systemd 리로드
systemctl daemon-reload

# WireGuard(주의: 먼저 /etc/wireguard/wg0.conf 작성 필요)
systemctl enable --now wg-quick@wg0

# ipset/iptables(주의: 먼저 /etc/armaguard/*.rules 작성 필요)
systemctl enable --now armaguard-ipset.service
systemctl enable --now armaguard-iptables.service

# 백엔드 API
systemctl enable --now armaguard-api.service

# (선택) GeoIP 자동 갱신
systemctl enable --now armaguard-geoip.timer
```

### 6.2 상태 확인

```bash
# WireGuard
wg show
ip addr show wg0

# ipset
ipset list

# iptables
iptables -L -v -n
iptables -t nat -L -v -n

# systemd 서비스
systemctl status armaguard-{ipset,iptables,api}.service

# 로그
journalctl -u armaguard-api.service -f
```

### 6.3 문제 해결

**ipset 없이 iptables-restore 실패**:
```bash
# ipset 서비스가 먼저 실행되었는지 확인
systemctl status armaguard-ipset.service

# 수동 복원
ipset restore < /etc/armaguard/ipset.rules
iptables-restore /etc/armaguard/iptables.rules.v4
```

**WireGuard 연결 문제**:
```bash
# Endpoint 접근성 확인
ping <VPS_PUBLIC_IP>
# 또는
wg-quick down wg0 && wg-quick up wg0
```

**포트 리스닝 확인**:
```bash
ss -tuln | grep -E "(20001|17777|27016|51820)"
```

---

## 7. GUI 개발(백엔드 API 스펙)

### 7.1 기술 스택(권장)

- **Frontend**: React 18 + Vite + MUI v5 + TanStack Query  
- **Backend**: Go 1.22+ + Fiber 또는 Chi + SQLite  
- **배포**: Docker + systemd 또는 단일 바이너리

### 7.2 설정 파일: `/etc/armaguard/config.yaml`

```yaml
# API 설정
api:
  listen: "0.0.0.0:8080"
  tls: false  # (프로덕션: true, cert/key 경로 지정)

# WireGuard 설정
wireguard:
  ifname: "wg0"
  subnet: "10.200.0.0/24"
  server_ip: "10.200.0.1"
  listen_port: 51820

# 방화벽 설정
firewall:
  ipset_rules_path: "/etc/armaguard/ipset.rules"
  iptables_rules_path: "/etc/armaguard/iptables.rules.v4"
  allow_kr_enabled: true
  geoip_set_name: "geo_kr"
  allow_foreign_set: "allow_foreign"
  ban_set: "ban"

# flood 완화 프리셋(기본값)
flood_protection:
  a2s_pps_above: 30         # per second
  a2s_burst: 60
  browser_pps_above: 50
  browser_burst: 100
  game_pps_above: 300
  game_burst: 600

# 데이터베이스
database:
  type: "sqlite"
  path: "/var/lib/armaguard/db/armaguard.db"

# 포트 배정
port_allocation:
  stride: 10
  base_game: 20001
  base_browser: 17777
  base_a2s: 27016
  max_origins: 6

# GeoIP(선택)
geoip:
  update_interval: "24h"
  source: "https://git.io/GeoLite2-Country-CSV"  # 예시
```

### 7.3 데이터 모델(DB 스키마, SQLite)

```sql
-- 오리진 관리
CREATE TABLE origins (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  wg_ip TEXT NOT NULL,
  reforger_game_port INTEGER DEFAULT 20001,
  reforger_browser_port INTEGER DEFAULT 17777,
  reforger_a2s_port INTEGER DEFAULT 27016,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 서비스(=공개 포트 세트)
CREATE TABLE services (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  origin_id INTEGER NOT NULL REFERENCES origins(id),
  public_game_port INTEGER NOT NULL,
  public_browser_port INTEGER NOT NULL,
  public_a2s_port INTEGER NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(public_game_port, public_browser_port, public_a2s_port)
);

-- 정책: 해외 허용 IP
CREATE TABLE allow_foreign (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  label TEXT,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 정책: 차단 IP
CREATE TABLE ban_ips (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  reason TEXT,
  is_auto BOOLEAN DEFAULT 0,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 감사 로그
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id INTEGER,
  old_value TEXT,
  new_value TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- WireGuard 피어 추적
CREATE TABLE wg_peers (
  id INTEGER PRIMARY KEY,
  origin_id INTEGER UNIQUE NOT NULL REFERENCES origins(id),
  public_key TEXT NOT NULL UNIQUE,
  private_key TEXT NOT NULL,
  last_handshake TIMESTAMP,
  rx_bytes INTEGER DEFAULT 0,
  tx_bytes INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 7.4 REST API 엔드포인트

| 메서드 | 경로 | 기능 |
|---|---|---|
| POST | `/api/origins` | 오리진 등록(키 자동 생성) |
| GET | `/api/origins` | 오리진 목록 + 터널 상태 |
| DELETE | `/api/origins/{id}` | 오리진 제거 |
| POST | `/api/services` | 서비스 등록(포트 자동 배정) |
| GET | `/api/services` | 서비스 목록 |
| DELETE | `/api/services/{id}` | 서비스 제거 |
| POST | `/api/policy/allow_foreign` | 해외 허용 IP 추가 |
| DELETE | `/api/policy/allow_foreign/{ip}` | 해외 허용 IP 제거 |
| POST | `/api/policy/ban` | 차단 IP 추가 |
| DELETE | `/api/policy/ban/{ip}` | 차단 IP 제거 |
| POST | `/api/firewall/apply` | iptables/ipset 갱신 적용 |
| GET | `/api/firewall/status` | 방화벽 현황 |
| GET | `/api/stats` | 통계(카운터, 드롭, 허용) |
| GET | `/api/audit-log` | 감사 로그 |
| GET | `/api/wg/peers/{id}/config` | 오리진 WG 클라이언트 설정 다운로드 |
| GET | `/api/wg/peers/{id}/qr` | WireGuard QR 코드 |

---

## 8. GUI 프론트엔드(React)

### 8.1 주요 화면

#### Dashboard
- 오리진 6대 카드(이름, WG IP, 마지막 핸드셰이크, TxRx 바)
- 서비스 목록(포트, 대상 오리진)
- 실시간 통계(허용/드롭 카운터)

#### Origins 관리
- 추가 버튼(자동 키 생성 + AllowedIPs 계산)
- 각 오리진별 카드: 편집/삭제, WG config 다운로드, QR 코드
- 터널 상태 라이브 업데이트

#### Services 관리
- 추가 버튼(오리진 선택 → 포트 자동 배정 → 충돌 검사)
- 서비스별 카드: 공개 포트 세트, 대상 오리진, 편집/삭제
- "원클릭 적용" 버튼 (iptables 재적용)

#### Policy
- 한국만 허용 토글(ON/OFF)
- 해외 허용 IP 테이블: IP, 라벨, 만료일, 추가/삭제
- 차단 IP 테이블: IP, 사유, 만료일, 추가/삭제
- flood 프리셋: "쿼리 강하게", "전체 약화", "긴급 모드(해외 차단)" 버튼

#### 적용/롤백
- "변경사항 적용" 버튼: `iptables-restore` + `ipset restore` + 헬스 체크
- "마지막 적용 상태로 롤백" 버튼(전 버전 JSON 저장)
- 적용 결과 로그(성공/실패/타임아웃)

---

## 9. 운영 가이드

### 9.1 일상 운영(GUI 기반)

1. **오리진 추가**
   - "Origins" 탭 → "+추가" → 자동 키 생성(QR 코드, config 다운로드)
   - 오리진에서 WireGuard 클라이언트 설정 적용(`wg-quick up ...`)
   - "마지막 핸드셰이크" 업데이트 확인

2. **서비스(게임 서버) 추가**
   - "Services" 탭 → "+추가" → 오리진 선택 → 포트 자동 배정 (충돌 검사 자동)
   - "변경사항 적용" 클릭 (iptables/ipset 갱신, systemd 재시작)
   - 클라이언트가 공개 포트로 접속 가능한지 확인

3. **정책 갱신**
   - "Policy" 탭에서 "한국만 허용" 토글(GeoIP DB 자동 갱신)
   - 해외 VPN 사용자: "허용 IP 추가" (일시적 또는 만료일 지정)
   - 악성 스캐너/공격자: "차단 IP 추가"

4. **Flood 공격 대응**
   - "Policy" 탭의 "Protection 프리셋"에서:
     - 저강도: 기본값(PPS 30/50/300)
     - 중강도: "쿼리 강하게"(PPS 10/20/300)
     - 고강도: "긴급 모드"(해외 전부 DROP)
   - "변경사항 적용" 후 모니터링

### 9.2 모니터링/로깅

**systemd 로그 실시간 보기**:
```bash
journalctl -u armaguard-api.service -f
journalctl -u armaguard-iptables.service -f
```

**WireGuard 상태**:
```bash
wg show
# 또는 GUI에서 실시간 표시
```

**iptables 카운터**(통계용):
```bash
iptables -L -v -n
iptables -t nat -L -v -n
iptables -t mangle -L -v -n
ipset list
```

**포트 리스닝**(헬스 체크):
```bash
ss -tuln | grep -E "(20001|17777|27016|20011|...)"
```

### 9.3 문제 해결 체크리스트

| 문제 | 확인 사항 | 해결책 |
|---|---|---|
| 클라이언트가 포트로 접속 불가 | (1) 방화벽이 UDP 포트 차단? (2) Vultr DDoS가 공격 감지했나?(AMF 모드) | (1) `ss -tuln` 확인 (2) Vultr 대시보드 확인 |
| 오리진이 WireGuard 연결 안 됨 | (1) Endpoint 접근성? (2) PublicKey/AllowedIPs 맞나? | (1) `ping <VPS_IP>` (2) `wg show` |
| 원본 IP가 안 보임(SNAT이 되었나?) | POSTROUTING에서 포워딩 트래픽에 MASQUERADE 걸렸나? | DNAT 규칙 확인 + SNAT 제거 |
| ipset 로드 실패 | ipset 패키지 설치 여부? | `apt install ipset` |
| 한국 IP 차단됨 | GeoIP DB가 오래됐나? | geoip 타이머 강제 실행 또는 수동 업데이트 |

---

## 10. Arma Reforger 오리진 설정(참고)

각 오리진에서 Reforger 서버의 `config.json`은 **기본 포트를 유지**해야 합니다(프록시가 외부 포트만 시프트).

```json
{
  "bindPort": 20001,
  "publicAddress": "10.200.0.2",
  "publicPort": 20001,
  "maxPlayers": 64,
  "serverName": "Your Server Name",
  "a2s": {
    "enable": true,
    "port": 27016,
    "queryPort": 27016
  }
}
```

**중요**: `publicAddress`는 오리진의 WireGuard IP(10.200.0.x)로 설정. 이렇게 해야 브라우저 쿼리가 정상 작동합니다(게임 리스트가 공개 IP로 노출되지만, 클라이언트는 공개 IP로 접속하고 프록시가 DNAT로 오리진으로 포워드).

---

## 11. 확인 및 테스트

### 11.1 배포 후 체크리스트

- [ ] Vultr DDoS Protection 활성화 + DNS 리졸버 확인(108.61.10.10)
- [ ] IPv4 forwarding 활성화(`net.ipv4.ip_forward=1`)
- [ ] WireGuard 인터페이스 UP(`ip addr show wg0`)
- [ ] ipset 세트 로드(`ipset list`)
- [ ] iptables 규칙 설치(`iptables -L -v -n`)
- [ ] 오리진 WireGuard 클라이언트 연결(`wg show`)
- [ ] 게임 포트 리스닝(`ss -tuln | grep 2000`)
- [ ] 백엔드 API 실행 중(`systemctl status armaguard-api.service`)
- [ ] GUI 접속 가능(프록시 IP:8080)

### 11.2 원본 IP 보존 테스트

1. 클라이언트에서 게임 서버 접속
2. 오리진에서 로그 확인(또는 게임 내 플레이어 IP 확인)
3. 클라이언트 IP == 로그에 보이는 IP? → 성공

### 11.3 DDoS 시뮬레이션(선택)

```bash
# 프록시 공인 IP의 게임 포트에 UDP 플러딩
hping3 -2 --flood -p 20001 <VPS_PUBLIC_IP>

# 대기 중... Vultr DDoS Protection이 감지/완화하는지 모니터링
journalctl -u armaguard-api.service -f
```

---

## 12. 마무리 및 참고 자료

### 12.1 이 설계의 장점

✅ 공개 서버 리스트 노출 유지(프록시 IP만 보임)  
✅ 오리진(자택) IP 숨김(WireGuard 터널)  
✅ 클라이언트 원본 IP 보존(DNAT만 사용, full-tunnel 대칭 경로)  
✅ DDoS 2차 방어(GeoIP/allowlist/flood)  
✅ 단일 GUI로 통합 운영  
✅ 멀티 오리진(6대 동시 중계)  
✅ 스케일 가능(서비스 추가/삭제 용이)  

### 12.2 한계

⚠️ 대형 볼류메트릭 DDoS(100Gbps+)는 Vultr AMF에 의존 → 호스트 레벨 방어로는 한계  
⚠️ UDP 스푸핑 공격: IP별 hashlimit은 무력화 가능 → "저강도 억제용"  
⚠️ GeoIP DB 오탐: 일부 정상 유저가 차단될 수 있음 → allowlist로 예외 처리  

### 12.3 참고 링크

- [Vultr DDoS Protection](https://docs.vultr.com/ddos-protection)
- [WireGuard Full-Tunnel Configuration](https://docs.pi-hole.net/guides/vpn/wireguard/route-everything/)
- [iptables Extensions Manual](https://ipset.netfilter.org/iptables-extensions.man.html)
- [Debian WireGuard Wiki](https://wiki.debian.org/WireGuard)
- [Arma Reforger Server Config](https://hosthavoc.com/blog/how-to-host-arma-reforger-server)

---

**문서 버전**: 1.0  
**마지막 업데이트**: 2026-01-04  
**작성자**: ArmaGuard Development Team

---
