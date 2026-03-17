import sqlite3
from datetime import datetime

DB_PATH = "honeypot.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocklist (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT UNIQUE,
            note      TEXT,
            added     TEXT,
            hit_count INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT,
            src_ip       TEXT,
            src_port     INTEGER,
            dst_port     INTEGER,
            payload      TEXT,
            country      TEXT,
            country_code TEXT,
            city         TEXT,
            region       TEXT,
            isp          TEXT,
            org          TEXT,
            lat          REAL,
            lon          REAL,
            attack_type  TEXT,
            severity     TEXT,
            protocol     TEXT,
            bytes_sent   INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def classify_attack(dst_port, payload):
    p = payload.lower()
    if dst_port in (22, 2222):
        if any(x in p for x in ['root','admin','pass','user','login','ubuntu','pi']):
            return 'brute_force', 'high'
        return 'ssh_probe', 'medium'
    if dst_port in (23, 2323):
        return 'telnet_probe', 'high'
    if dst_port in (80, 8080, 8443):
        if any(x in p for x in ['select','union','drop','insert','sleep(','1=1']):
            return 'sql_injection', 'critical'
        if any(x in p for x in ['<script','alert(','onerror','onload']):
            return 'xss_attempt', 'high'
        if any(x in p for x in ['../','etc/passwd','/proc/','/etc/shadow']):
            return 'path_traversal', 'critical'
        if any(x in p for x in ['phpunit','wp-admin','.env','config.php','wp-login']):
            return 'web_scan', 'medium'
        if any(x in p for x in ['cmd=','exec(','system(','passthru(']):
            return 'rce_attempt', 'critical'
        return 'http_probe', 'low'
    if dst_port == 9200:
        return 'elasticsearch_scan', 'high'
    if dst_port == 3306:
        return 'mysql_probe', 'high'
    if dst_port == 5900:
        return 'vnc_probe', 'medium'
    if dst_port == 3389:
        return 'rdp_probe', 'high'
    if dst_port == 6379:
        if any(x in p for x in ['flushall','config','slaveof']):
            return 'redis_exploit', 'critical'
        return 'redis_probe', 'high'
    if dst_port == 27017:
        return 'mongodb_probe', 'high'
    if dst_port == 5432:
        return 'postgres_probe', 'high'
    if dst_port == 21:
        return 'ftp_probe', 'medium'
    return 'unknown_probe', 'low'

def get_protocol(dst_port):
    m = {22:'SSH',2222:'SSH',23:'Telnet',2323:'Telnet',80:'HTTP',8080:'HTTP',
         8443:'HTTPS',9200:'Elasticsearch',3306:'MySQL',5900:'VNC',3389:'RDP',
         6379:'Redis',27017:'MongoDB',5432:'PostgreSQL',21:'FTP'}
    return m.get(dst_port, 'TCP')

def save_attack(src_ip, src_port, dst_port, payload,
                country, country_code, city, region, isp, org, lat, lon):
    attack_type, severity = classify_attack(dst_port, payload)
    protocol  = get_protocol(dst_port)
    bytes_sent= len(payload.encode('utf-8', errors='replace'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO attacks
        (timestamp,src_ip,src_port,dst_port,payload,country,country_code,
         city,region,isp,org,lat,lon,attack_type,severity,protocol,bytes_sent)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (datetime.utcnow().isoformat(), src_ip, src_port, dst_port,
          payload[:500], country, country_code, city, region, isp, org,
          lat, lon, attack_type, severity, protocol, bytes_sent))
    conn.commit()
    conn.close()

def get_attacks(limit=200, port=None, country=None, attack_type=None,
                severity=None, protocol=None, search=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    query  = "SELECT * FROM attacks WHERE 1=1"
    params = []
    if port:         query += " AND dst_port=?";           params.append(int(port))
    if country:      query += " AND country LIKE ?";       params.append(f"%{country}%")
    if attack_type:  query += " AND attack_type=?";        params.append(attack_type)
    if severity:     query += " AND severity=?";           params.append(severity)
    if protocol:     query += " AND protocol=?";           params.append(protocol)
    if search:
        query += " AND (src_ip LIKE ? OR payload LIKE ? OR city LIKE ? OR isp LIKE ? OR country LIKE ?)"
        s = f"%{search}%"
        params += [s, s, s, s, s]
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = [dict(r) for r in c.execute(query, params).fetchall()]
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    def q(sql, p=[]): return c.execute(sql, p).fetchall()
    def q1(sql, p=[]): return c.execute(sql, p).fetchone()[0]

    total            = q1("SELECT COUNT(*) FROM attacks")
    today            = q1("SELECT COUNT(*) FROM attacks WHERE timestamp >= date('now')")
    last_hour        = q1("SELECT COUNT(*) FROM attacks WHERE timestamp >= datetime('now','-1 hour')")
    unique_ips       = q1("SELECT COUNT(DISTINCT src_ip) FROM attacks")
    unique_countries = q1("SELECT COUNT(DISTINCT country) FROM attacks")
    total_bytes      = q1("SELECT COALESCE(SUM(bytes_sent),0) FROM attacks")
    critical         = q1("SELECT COUNT(*) FROM attacks WHERE severity='critical'")
    high             = q1("SELECT COUNT(*) FROM attacks WHERE severity='high'")

    top_ips       = q("SELECT src_ip,COUNT(*) c FROM attacks GROUP BY src_ip ORDER BY c DESC LIMIT 10")
    top_ports     = q("SELECT dst_port,COUNT(*) c FROM attacks GROUP BY dst_port ORDER BY c DESC LIMIT 8")
    top_countries = q("SELECT country,COUNT(*) c FROM attacks GROUP BY country ORDER BY c DESC LIMIT 10")
    top_types     = q("SELECT attack_type,COUNT(*) c FROM attacks GROUP BY attack_type ORDER BY c DESC LIMIT 10")
    top_severity  = q("SELECT severity,COUNT(*) c FROM attacks GROUP BY severity ORDER BY c DESC")
    top_protocols = q("SELECT protocol,COUNT(*) c FROM attacks GROUP BY protocol ORDER BY c DESC LIMIT 8")
    top_isps      = q("SELECT isp,COUNT(*) c FROM attacks WHERE isp!='' AND isp!='Unknown' GROUP BY isp ORDER BY c DESC LIMIT 8")
    hourly        = q("SELECT strftime('%H',timestamp) h,COUNT(*) c FROM attacks GROUP BY h ORDER BY h")
    daily         = q("SELECT date(timestamp) d,COUNT(*) c FROM attacks GROUP BY d ORDER BY d DESC LIMIT 7")
    recent_pay    = q("SELECT src_ip,payload,attack_type,severity,timestamp FROM attacks WHERE payload!='' ORDER BY id DESC LIMIT 15")
    recent_all    = q("SELECT src_ip,dst_port,attack_type,severity,country,timestamp FROM attacks ORDER BY id DESC LIMIT 10")

    conn.close()
    return {
        "total":total,"today":today,"last_hour":last_hour,
        "unique_ips":unique_ips,"unique_countries":unique_countries,
        "total_bytes":total_bytes,"critical":critical,"high":high,
        "top_ips":        [{"ip":r[0],"count":r[1]} for r in top_ips],
        "top_ports":      [{"port":r[0],"count":r[1]} for r in top_ports],
        "top_countries":  [{"country":r[0],"count":r[1]} for r in top_countries],
        "top_types":      [{"type":r[0],"count":r[1]} for r in top_types],
        "top_severity":   [{"severity":r[0],"count":r[1]} for r in top_severity],
        "top_protocols":  [{"protocol":r[0],"count":r[1]} for r in top_protocols],
        "top_isps":       [{"isp":r[0],"count":r[1]} for r in top_isps],
        "hourly":         [{"hour":r[0],"count":r[1]} for r in hourly],
        "daily":          [{"date":r[0],"count":r[1]} for r in daily],
        "recent_payloads":[{"ip":r[0],"payload":r[1],"type":r[2],"severity":r[3],"time":r[4]} for r in recent_pay],
        "recent_attacks": [{"ip":r[0],"port":r[1],"type":r[2],"severity":r[3],"country":r[4],"time":r[5]} for r in recent_all],
    }

# ── Blocklist ─────────────────────────────────────────────────────────

# In-memory set for ultra-fast lookups inside the listener thread
_blocked_ips: set = set()

def load_blocked_ips():
    """Load all blocked IPs into memory — called once at startup."""
    global _blocked_ips
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT ip FROM blocklist").fetchall()
    conn.close()
    _blocked_ips = {r[0] for r in rows}

def is_blocked(ip: str) -> bool:
    """Ultra-fast in-memory check — called on every connection."""
    return ip in _blocked_ips

def block_ip(ip: str, note: str = "") -> bool:
    """Add IP to DB blocklist and in-memory set. Returns False if already blocked."""
    global _blocked_ips
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO blocklist (ip, note, added, hit_count) VALUES (?,?,?,0)",
            (ip, note, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        _blocked_ips.add(ip)
        return True
    except Exception:
        return False  # UNIQUE constraint — already blocked

def unblock_ip(ip: str):
    """Remove IP from DB and in-memory set."""
    global _blocked_ips
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM blocklist WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    _blocked_ips.discard(ip)

def increment_block_hit(ip: str):
    """Count how many times a blocked IP tried to connect."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE blocklist SET hit_count=hit_count+1 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

def get_blocklist():
    """Return full blocklist from DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM blocklist ORDER BY hit_count DESC, added DESC"
    ).fetchall()]
    conn.close()
    return rows
