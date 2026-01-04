# Arma 서버를 위한 고급 DDoS 방어 규칙 (심화)

> 기존 flood 완화에 추가적으로 적용 가능한 iptables/sysctl 방어 규칙들

## 개요

Vultr DDoS Protection(1차) + GeoIP/allowlist(2차) + flood 완화(3차)에 더해, **TCP/UDP 패킷 검증 + 연결 추적 강화 + 비정상 플래그 차단 + 커널 설정 최적화**로 보다 정교한 DDoS 완화를 구현할 수 있습니다.

핵심 원칙: **정상 게임 패킷은 통과, 공격 패킷은 조기에 커널 레벨에서 DROP** (CPU 낭비 최소화)

---

## 1. 커널 TCP/IP 스택 강화 (sysctl)

### 1.1 SYN Cookie 활성화 (SYN flood 대비)

```bash
cat > /etc/sysctl.d/99-ddos-hardening.conf <<'EOF'
# === SYN Flood 방어 ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_timestamps = 1

# === 연결 추적(conntrack) 최적화 ===
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 60

# === TCP 설정 ===
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15

# === 비정상 역방향 경로 필터링 ===
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# === ICMP flood 방어 ===
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === IP 스푸핑 방어 ===
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

sysctl --system
sysctl -p
```

---

## 2. iptables mangle 체인 강화 (패킷 검증)

### 2.1 기본 mangle 규칙 (추가 적용)

```bash
cat > /etc/armaguard/iptables-hardened.rules.v4 <<'EOFIPTABLES'
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ARMA_PREROUTE - [0:0]
:ARMA_GUARD - [0:0]

# === 1단계: 비정상 패킷 조기 차단 ===

# 1-1) INVALID 상태 패킷 차단
-A PREROUTING -m conntrack --ctstate INVALID -j DROP

# 1-2) 비정상 TCP 플래그 조합 차단
-A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
-A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP

# 1-3) 새 연결(NEW)인데 SYN이 아닌 패킷 차단
-A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# 1-4) MSS 비정상 값 차단
-A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

# 1-5) 조각화 패킷 차단
-A PREROUTING -f -j DROP

# === 2단계: Arma 포트 진입 필터링 ===
-A PREROUTING -i eth0 -p udp -m multiport --dports 20001,17777,27016,20011,17787,27026,20021,17797,27036,20031,17807,27046,20041,17817,27056,20051,17827,27066 -j ARMA_PREROUTE
-A PREROUTING -i eth0 -p tcp -m multiport --dports 2302,2303,2304,2306,2312,2313,2314,2316,2322,2323,2324,2326,2332,2333,2334,2336,2342,2343,2344,2346,2352,2353,2354,2356 -j ARMA_PREROUTE
-A PREROUTING -i eth0 -p udp -m multiport --dports 2302,2303,2304,2306,2312,2313,2314,2316,2322,2323,2324,2326,2332,2333,2334,2336,2342,2343,2344,2346,2352,2353,2354,2356 -j ARMA_PREROUTE

# === 3단계: GeoIP + flood 정책 ===
-A ARMA_GUARD -m set --match-set ban src -j DROP
-A ARMA_GUARD -m set --match-set geo_kr src -j RETURN
-A ARMA_GUARD -m set --match-set allow_foreign src -j RETURN
-A ARMA_GUARD -j DROP

-A ARMA_PREROUTE -j ARMA_GUARD

# Reforger flood
-A ARMA_PREROUTE -p udp --dport 27016 -m hashlimit --hashlimit-above 30/second --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name REFORGER_A2S -j DROP
-A ARMA_PREROUTE -p udp --dport 17777 -m hashlimit --hashlimit-above 50/second --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name REFORGER_BROWSER -j DROP
-A ARMA_PREROUTE -p udp --dport 20001 -m hashlimit --hashlimit-above 300/second --hashlimit-burst 600 --hashlimit-mode srcip --hashlimit-name REFORGER_GAME -j DROP

# Arma 3 flood
-A ARMA_PREROUTE -p udp -m multiport --dports 2303,2313,2323,2333,2343,2353 -m hashlimit --hashlimit-above 20/second --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name ARMA3_QUERY -j DROP
-A ARMA_PREROUTE -p udp --dport 2302 -m hashlimit --hashlimit-above 250/second --hashlimit-burst 500 --hashlimit-mode srcip --hashlimit-name ARMA3_GAME -j DROP

# Arma 3 TCP flood 제한
-A ARMA_PREROUTE -p tcp -m multiport --dports 2302,2303,2304,2306,2312,2313,2314,2316,2322,2323,2324,2326,2332,2333,2334,2336,2342,2343,2344,2346,2352,2353,2354,2356 -m limit --limit 100/second --limit-burst 200 -j RETURN
-A ARMA_PREROUTE -p tcp -m multiport --dports 2302,2303,2304,2306,2312,2313,2314,2316,2322,2323,2324,2326,2332,2333,2334,2336,2342,2343,2344,2346,2352,2353,2354,2356 -j DROP

COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# Reforger DNAT
-A PREROUTING -i eth0 -p udp --dport 20001 -j DNAT --to-destination 10.200.0.2:20001
-A PREROUTING -i eth0 -p udp --dport 17777 -j DNAT --to-destination 10.200.0.2:17777
-A PREROUTING -i eth0 -p udp --dport 27016 -j DNAT --to-destination 10.200.0.2:27016

# Arma 3 DNAT (서버 0)
-A PREROUTING -i eth0 -p tcp --dport 2302 -j DNAT --to-destination 10.200.0.2:2302
-A PREROUTING -i eth0 -p udp --dport 2302 -j DNAT --to-destination 10.200.0.2:2302
-A PREROUTING -i eth0 -p tcp --dport 2303 -j DNAT --to-destination 10.200.0.2:2303
-A PREROUTING -i eth0 -p udp --dport 2303 -j DNAT --to-destination 10.200.0.2:2303
-A PREROUTING -i eth0 -p tcp --dport 2304 -j DNAT --to-destination 10.200.0.2:2304
-A PREROUTING -i eth0 -p udp --dport 2304 -j DNAT --to-destination 10.200.0.2:2304
-A PREROUTING -i eth0 -p tcp --dport 2306 -j DNAT --to-destination 10.200.0.2:2306
-A PREROUTING -i eth0 -p udp --dport 2306 -j DNAT --to-destination 10.200.0.2:2306

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

# 연결 제한
-A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

# RST flood 방어
-A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
-A INPUT -p tcp --tcp-flags RST RST -j DROP

# ICMP flood 방어
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j DROP

-A FORWARD -i eth0 -o wg0 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i wg0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

COMMIT
EOFIPTABLES
```

---

## 3. 연결 제한 (connlimit)

```bash
# 소스 IP당 최대 80개 동시 연결
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

# Arma 3 TCP 연결 제한
iptables -A INPUT -p tcp -m multiport --dports 2302,2312,2322,2332,2342,2352 -m connlimit --connlimit-above 200 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```

---

## 4. TCP RST 플러드 제한

```bash
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
```

---

## 5. ICMP 플러드 방어

```bash
# Option A: 모든 ICMP 차단
iptables -t mangle -A PREROUTING -p icmp -j DROP

# Option B: 핑 제한
iptables -t mangle -A PREROUTING -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -t mangle -A PREROUTING -p icmp --icmp-type echo-request -j DROP
```

---

## 6. DNS/NTP Reflection 방지 (오리진에서)

```bash
# DNS 포트 차단
iptables -A INPUT -p udp --dport 53 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP

# NTP 포트 차단
iptables -A INPUT -p udp --dport 123 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p udp --dport 123 -j DROP
```

---

## 7. UDP 기반 공격 완화

```bash
# 비정상 UDP 패킷(7바이트 이하) 차단
iptables -t mangle -A PREROUTING -p udp -m multiport --dports 20001,17777,27016,2302,2303,2304,2306 -m length --length 0:7 -j DROP

# DNS/NTP 포트로의 UDP 차단
iptables -A INPUT -p udp -m multiport --dports 53,123 -j DROP
```

---

## 8. 실시간 모니터링

```bash
# 패킷 카운터 확인
iptables -L -v -n -t mangle
iptables -L -v -n -t nat

# 실시간 모니터링
watch -n 1 'iptables -L -v -n | grep -E "ARMA|Chain"'

# ipset 상태
ipset list

# 비정상 SYN 급증 감시
watch -n 1 'netstat -an | grep SYN | wc -l'

# 특정 포트 패킷 분석
tcpdump -i eth0 -nn "port 20001" -c 100
```

---

**문서 버전**: 1.0  
**마지막 업데이트**: 2026-01-04
