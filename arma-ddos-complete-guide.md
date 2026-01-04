# Arma Reforger & Arma 3 DDoS 방어 중계 프록시 완전 가이드

> **2026-01-04 업데이트**: Arma 3 멀티 서버 지원 추가

## 개요

이 지침서는 **Vultr Seoul 프록시 1대 + WireGuard full-tunnel로 오리진 6대 연결 + iptables/ipset(GeoIP/allowlist/ban/flood 완화) + 자체 Web GUI(단일, React + Go 백엔드)**로 구축하는 "공개 서버 리스트 노출은 유지하면서" 오리진(자택/개별 서버)의 IP를 숨기고, **클라이언트 원본 IP를 오리진에 그대로 보내는** DDoS 방어 중계 인프라를 완벽히 구축하기 위한 단계별 지침입니다.

**지원 게임**:
- ✅ Arma Reforger (포트 20001/17777/27016)
- ✅ Arma 3 (포트 2302~2306, TCP+UDP)
- ✅ 혼합 배포 (Reforger + Arma 3 동시)

### 핵심 목표
- **DDoS 1차 완화**: Vultr DDoS Protection(AMF, 인스턴스당 10Gbps L3/L4 TCP/UDP)  
- **DDoS 2차 정책**: Ubuntu/Debian의 iptables/ipset으로 "한국만 허용 + 해외는 개별 IP 예외 + 포트별 flood 완화"  
- **트래픽 분산**: 단일 프록시에서 멀티 오리진(6대)으로 WireGuard full-tunnel 중계  
- **원본 IP 보존**: DNAT만 사용(SNAT 금지) + full-tunnel 대칭 경로로 클라이언트 IP 그대로 전달  
- **통합 관리**: 단일 Web GUI에서 오리진/서비스/정책/방어 프리셋을 모두 관리  
- **게임 호환성**: Reforger, Arma 3을 같은 프록시에서 동시 운영 가능  

---

## 1. 준비물 및 사전 설정

### 1.1 하드웨어/클라우드 환경

| 항목 | 사양 | 비고 |
|---|---|---|
| 프록시(VPS) | Vultr Seoul, 2GB RAM, 40GB SSD, 고정 공인 IPv4 | Vultr DDoS Protection 옵션 필수 |
| 오리진(자택/IDC) | 6대, 각각 IPv4 주소(공인/사설), Arma Reforger 또는 Arma 3 서버 | 기본 포트 유지(포트 시프트는 프록시에서) |
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
  postgresql-client
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

### 2.2 포트 배정(멀티 게임 지원)

#### Arma Reforger 포트(stride=10)

| 서버 | Game | Browser | A2S |
|---|---|---|---|
| 서버 0 | 20001/UDP | 17777/UDP | 27016/UDP |
| 서버 1 | 20011/UDP | 17787/UDP | 27026/UDP |
| 서버 2 | 20021/UDP | 17797/UDP | 27036/UDP |
| 서버 3 | 20031/UDP | 17807/UDP | 27046/UDP |
| 서버 4 | 20041/UDP | 17817/UDP | 27056/UDP |
| 서버 5 | 20051/UDP | 17827/UDP | 27066/UDP |

#### Arma 3 포트(stride=10, TCP+UDP)

| 서버 | Game | Query | Steam | BattlEye |
|---|---|---|---|---|
| 서버 0 | 2302 | 2303 | 2304 | 2306 |
| 서버 1 | 2312 | 2313 | 2314 | 2316 |
| 서버 2 | 2322 | 2323 | 2324 | 2326 |
| 서버 3 | 2332 | 2333 | 2334 | 2336 |
| 서버 4 | 2342 | 2343 | 2344 | 2346 |
| 서버 5 | 2352 | 2353 | 2354 | 2356 |

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

# 오리진 2~5도 같은 방식
[Peer]
PublicKey = <origin_5_publickey>
AllowedIPs = 10.200.0.7/32
```

### 3.2 오리진 AllowedIPs 자동 생성(파이썬)

```python
#!/usr/bin/env python3
import ipaddress

def generate_allowedips_exclude(vps_public_ip, origin_local_lan):
    """
    0.0.0.0/0에서 특정 CIDR를 제외한 리스트 생성
    """
    exclude = [
        ipaddress.ip_network(vps_public_ip),
        ipaddress.ip_network(origin_local_lan),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]
    
    base = ipaddress.ip_network("0.0.0.0/0")
    result = []
    for subnet in base.address_exclude(*exclude):
        result.append(str(subnet))
    
    return ",".join(result)

vps_ip = "X.X.X.X/32"
origin_lan = "192.168.0.0/16"
allowed = generate_allowedips_exclude(vps_ip, origin_lan)
print(f"AllowedIPs = {allowed}")
```

**오리진 클라이언트 설정** (`/etc/wireguard/wg0-client.conf`):
```ini
[Interface]
Address = 10.200.0.2/32
PrivateKey = <origin_privatekey>
DNS = 8.8.8.8

[Peer]
PublicKey = <vps_publickey>
Endpoint = <VPS_PUBLIC_IP>:51820
AllowedIPs = <generated_cidrs>
PersistentKeepalive = 25
```

---

## 4. 게임 서버 설정

### 4.1 Arma Reforger 설정

각 오리진에서 `config.json` (기본 포트 유지):

```json
{
  "bindPort": 20001,
  "publicAddress": "10.200.0.2",
  "publicPort": 20001,
  "maxPlayers": 64,
  "serverName": "Your Reforger Server",
  "a2s": {
    "enable": true,
    "port": 27016,
    "queryPort": 27016
  }
}
```

### 4.2 Arma 3 설정

각 오리진에서 `server.cfg` (기본 포트 유지):

```cfg
hostname = "My Arma 3 Server";
passwordAdmin = "AdminPassword";
maxPlayers = 64;
persistent = 1;
BattlEye = 1;
verifySignatures = 2;
kickDuplicate = 1;

logFile = "server_console.log";
timeStampFormat = "short";

disableVoN = 0;
vonCodecQuality = 10;

class Missions
{
    class Mission1
    {
        template = "MyMission.Altis";
        difficulty = "Regular";
    };
};
```

**시작 명령**:
```bash
./arma3server -config=server.cfg -port=2302 -profiles=. -world=empty
```

---

## 5. 방화벽 설정(iptables/ipset)

### 5.1 ipset 정의: `/etc/armaguard/ipset.rules`

```text
create geo_kr hash:net family inet -exist
create allow_foreign hash:ip family inet -exist
create ban hash:ip family inet -exist

flush geo_kr
flush allow_foreign
flush ban
```

### 5.2 iptables 규칙: `/etc/armaguard/iptables.rules.v4`

```text
*mangle
:PREROUTING ACCEPT [0:0]
:ARMA_PRE - [0:0]
:ARMA_GUARD - [0:0]

# Reforger + Arma 3 포트 정책 체크
-A PREROUTING -i eth0 -p udp -m multiport --dports 20001,17777,27016,20011,17787,27026,20021,17797,27036,20031,17807,27046,20041,17817,27056,20051,17827,27066 -j ARMA_PRE
-A PREROUTING -i eth0 -p tcp -m multiport --dports 2302,2303,2304,2306,2312,2313,2314,2316,2322,2323,2324,2326,2332,2333,2334,2336,2342,2343,2344,2346,2352,2353,2354,2356 -j ARMA_PRE
-A PREROUTING -i eth0 -p udp -m multiport --dports 2302,2303,2304,2306,2312,2313,2314,2316,2322,2323,2324,2326,2332,2333,2334,2336,2342,2343,2344,2346,2352,2353,2354,2356 -j ARMA_PRE

# 정책: ban -> (KR or allow_foreign) -> drop
-A ARMA_GUARD -m set --match-set ban src -j DROP
-A ARMA_GUARD -m set --match-set geo_kr src -j RETURN
-A ARMA_GUARD -m set --match-set allow_foreign src -j RETURN
-A ARMA_GUARD -j DROP

-A ARMA_PRE -j ARMA_GUARD

# Reforger Flood 완화
-A ARMA_PRE -p udp --dport 27016 -m hashlimit --hashlimit-above 30/second --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name REFORGER_A2S -j DROP
-A ARMA_PRE -p udp --dport 17777 -m hashlimit --hashlimit-above 50/second --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name REFORGER_BROWSER -j DROP
-A ARMA_PRE -p udp --dport 20001 -m hashlimit --hashlimit-above 300/second --hashlimit-burst 600 --hashlimit-mode srcip --hashlimit-name REFORGER_GAME -j DROP

# Arma 3 Flood 완화
-A ARMA_PRE -p udp -m multiport --dports 2303,2313,2323,2333,2343,2353 -m hashlimit --hashlimit-above 20/second --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name ARMA3_QUERY -j DROP
-A ARMA_PRE -p udp --dport 2302 -m hashlimit --hashlimit-above 250/second --hashlimit-burst 500 --hashlimit-mode srcip --hashlimit-name ARMA3_GAME -j DROP

COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# Reforger DNAT
-A PREROUTING -i eth0 -p udp --dport 20001 -j DNAT --to-destination 10.200.0.2:20001
-A PREROUTING -i eth0 -p udp --dport 17777 -j DNAT --to-destination 10.200.0.2:17777
-A PREROUTING -i eth0 -p udp --dport 27016 -j DNAT --to-destination 10.200.0.2:27016

# Arma 3 DNAT (서버 0, TCP+UDP)
-A PREROUTING -i eth0 -p tcp --dport 2302 -j DNAT --to-destination 10.200.0.2:2302
-A PREROUTING -i eth0 -p udp --dport 2302 -j DNAT --to-destination 10.200.0.2:2302
-A PREROUTING -i eth0 -p tcp --dport 2303 -j DNAT --to-destination 10.200.0.2:2303
-A PREROUTING -i eth0 -p udp --dport 2303 -j DNAT --to-destination 10.200.0.2:2303
-A PREROUTING -i eth0 -p tcp --dport 2304 -j DNAT --to-destination 10.200.0.2:2304
-A PREROUTING -i eth0 -p udp --dport 2304 -j DNAT --to-destination 10.200.0.2:2304
-A PREROUTING -i eth0 -p tcp --dport 2306 -j DNAT --to-destination 10.200.0.2:2306
-A PREROUTING -i eth0 -p udp --dport 2306 -j DNAT --to-destination 10.200.0.2:2306

# 더 많은 서버/오리진 매핑은 위 패턴 반복...

# NAT for origin internet
-A POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE

COMMIT

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p udp --dport 51820 -j ACCEPT
-A INPUT -p tcp --dport 8080 -j ACCEPT

-A FORWARD -i eth0 -o wg0 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i wg0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

COMMIT
```

---

## 6. systemd 자동화

### 6.1 ipset 복원: `/etc/systemd/system/armaguard-ipset.service`

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

### 6.2 iptables 복원: `/etc/systemd/system/armaguard-iptables.service`

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

### 6.3 시작 명령

```bash
systemctl daemon-reload

# WireGuard
systemctl enable --now wg-quick@wg0

# 방화벽
systemctl enable --now armaguard-ipset.service
systemctl enable --now armaguard-iptables.service
```

---

## 7. 운영 가이드

### 7.1 Reforger 서버 추가

1. GUI에서 "Origins" 탭 → "+추가"
2. WireGuard 자동 키 생성
3. "Services" 탭에서 "Reforger 추가" → 포트 자동 배정
4. "변경사항 적용"

### 7.2 Arma 3 서버 추가

1. GUI에서 오리진 선택
2. "Services" 탭에서 "Arma 3 추가" → 포트 자동 배정(2302/2303/2304/2306)
3. 오리진에서 Arma 3 시작
4. "변경사항 적용"

---

## 8. 검증

```bash
# 포트 리스닝 확인
ss -tuln | grep -E "(20001|2302|51820)"

# 클라이언트 원본 IP 확인(오리진 로그)
tail -f server_console.log | grep "Player"
```

---

**문서 버전**: 2.0 (Arma 3 지원 추가)  
**마지막 업데이트**: 2026-01-04
