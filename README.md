<img width="1917" height="913" alt="Screenshot 2026-03-17 233428" src="https://github.com/user-attachments/assets/5b21cff4-47c6-48de-8653-55cdccd0aef1" />

# HoneyTrap — Live Threat Intelligence Dashboard

A professional honeypot + real-time dashboard built with Python and Flask.
Single command launch. Captures, classifies, and visualizes attacks live.

---

## Quick Start (Windows)

```
pip install -r requirements.txt
python run.py
```
Open: http://localhost:5000

---

## Features

### Dashboard
- 8 live stat cards (total attacks, today, last hour, unique IPs, countries, critical, high, bytes)
- Live world map with ripple animation on new attacks (map locked — no infinite scroll)
- Hourly activity line chart
- Attacks by port bar chart

### Attack Log (with filters)
- Filter by: port, country, attack type, severity, protocol, free-text search, row limit
- 14 attack types classified automatically
- Export to CSV or JSON
- Sticky table headers, scrollable log

### Intelligence
- Attack types doughnut chart
- Severity distribution doughnut chart
- Top countries bar chart
- Daily 7-day volume chart
- Top 10 attacker IPs with percentage share

### Payloads
- Last 10 captured raw payloads with attacker IP, type, and timestamp

### Right panel
- System status (honeypot, dashboard, GeoIP, database, refresh rate, uptime)
- Per-port hit counter for all 8 ports
- Top countries with animated progress bars
- Top ISPs / organisations
- Live activity timeline
- Protocol breakdown chart

### Scrolling ticker
- Updates in real time with new attacker IPs and top attacker info

---

## Ports monitored

| Port  | Fakes           |
|-------|-----------------|
| 2222  | SSH             |
| 8080  | HTTP server     |
| 2323  | Telnet          |
| 9200  | Elasticsearch   |
| 3306  | MySQL           |
| 5900  | VNC             |
| 6379  | Redis           |
| 27017 | MongoDB         |

---

## Attack types detected

brute_force · ssh_probe · telnet_probe · http_probe · web_scan ·
sql_injection · xss_attempt · path_traversal · elasticsearch_scan ·
redis_probe · mongodb_probe · mysql_probe · vnc_probe · unknown_probe

---

## Port forwarding (home internet)

Forward ports 2222, 8080, 2323, 9200, 3306, 5900, 6379, 27017
to your PC's local IP in your router settings.
NEVER forward port 5000 (your private dashboard).

---

## Production / VPS

```
# Upload
scp -r honeypot_final/ root@YOUR_VPS_IP:/opt/honeytrap

# On VPS
pip3 install -r requirements.txt
ufw allow 2222,8080,2323,9200,3306,5900,6379,27017/tcp
ufw deny 5000/tcp
PRODUCTION=1 python3 run.py

# Access dashboard via SSH tunnel from your PC
ssh -L 5000:127.0.0.1:5000 root@YOUR_VPS_IP
# Open: http://localhost:5000
```

---

## Test locally (Windows)

```
python -c "import socket,time;ports=[2222,8080,2323,9200];[( s:=socket.socket(),s.connect(('localhost',p)),s.send(b'root password123\n'),s.close(),print(f'Hit port {p}')) for p in ports*5];print('Done!')"
```

---

## Stack

Python 3 · Flask · SQLite · Leaflet.js · Chart.js · JetBrains Mono · Inter
