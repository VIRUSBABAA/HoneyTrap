"""
HoneyTrap — All-in-one honeypot + dashboard
Run:  python run.py
"""
import os, csv, json, socket, threading, requests, io
from datetime import datetime
from flask import Flask, jsonify, render_template, request, abort, Response
from flask_cors import CORS
from database import (init_db, save_attack, get_attacks, get_stats,
                       load_blocked_ips, is_blocked, block_ip, unblock_ip,
                       increment_block_hit, get_blocklist)

# ── Config ────────────────────────────────────────────────────────────
PORTS_TO_LISTEN = [2222, 8080, 2323, 9200, 3306, 5900, 6379, 27017]
FLASK_PORT = int(os.environ.get("PORT", 5000))
IS_PROD    = os.environ.get("PRODUCTION", "0") == "1"
FLASK_HOST = "0.0.0.0" if IS_PROD else "127.0.0.1"
ALLOWED_IPS= os.environ.get("ALLOWED_IPS", "")
WHITELIST  = [ip.strip() for ip in ALLOWED_IPS.split(",") if ip.strip()]

# ── Flask ─────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

def check_access():
    if WHITELIST:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        if ip not in WHITELIST:
            abort(403)

@app.route("/")
def index():
    check_access()
    return render_template("index.html")

@app.route("/api/attacks")
def api_attacks():
    check_access()
    return jsonify(get_attacks(
        limit       = request.args.get("limit", 200),
        port        = request.args.get("port"),
        country     = request.args.get("country"),
        attack_type = request.args.get("attack_type"),
        severity    = request.args.get("severity"),
        protocol    = request.args.get("protocol"),
        search      = request.args.get("search"),
    ))

@app.route("/api/stats")
def api_stats():
    check_access()
    return jsonify(get_stats())

@app.route("/api/export/csv")
def export_csv():
    check_access()
    attacks = get_attacks(limit=10000)
    si = io.StringIO()
    # BOM for Excel UTF-8 compatibility on Windows
    si.write('\ufeff')
    fields = ['id','timestamp','src_ip','src_port','dst_port','payload',
              'country','city','region','isp','lat','lon',
              'attack_type','severity','protocol','bytes_sent']
    writer = csv.DictWriter(si, fieldnames=fields, extrasaction='ignore',
                            lineterminator='\r\n')
    writer.writeheader()
    writer.writerows(attacks)
    output = si.getvalue()
    return Response(
        output,
        mimetype='text/csv; charset=utf-8',
        headers={"Content-Disposition": "attachment; filename=honeypot_attacks.csv",
                 "Content-Type": "text/csv; charset=utf-8"}
    )

@app.route("/api/export/json")
def export_json():
    check_access()
    attacks = get_attacks(limit=10000)
    return Response(
        json.dumps(attacks, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={"Content-Disposition": "attachment; filename=honeypot_attacks.json"}
    )

@app.route("/api/clear", methods=["POST"])
def clear_db():
    check_access()
    import sqlite3
    from database import DB_PATH
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM attacks")
    conn.commit()
    conn.close()
    return jsonify({"status": "cleared"})

@app.route("/api/blocklist", methods=["GET"])
def api_get_blocklist():
    check_access()
    return jsonify(get_blocklist())

@app.route("/api/blocklist/add", methods=["POST"])
def api_block_ip():
    check_access()
    data = request.json or {}
    ip   = (data.get("ip") or "").strip()
    note = (data.get("note") or "").strip()
    if not ip:
        return jsonify({"error": "no IP provided"}), 400
    ok = block_ip(ip, note)
    if ok:
        print(f"  [BLOCK] {ip} added to blocklist — {note}")
    return jsonify({"status": "blocked" if ok else "already_blocked", "ip": ip})

@app.route("/api/blocklist/remove", methods=["POST"])
def api_unblock_ip():
    check_access()
    data = request.json or {}
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "no IP provided"}), 400
    unblock_ip(ip)
    print(f"  [UNBLOCK] {ip} removed from blocklist")
    return jsonify({"status": "unblocked", "ip": ip})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})

# ── GeoIP ─────────────────────────────────────────────────────────────
def geoip_lookup(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,lat,lon",
            timeout=3)
        d = r.json()
        if d.get("status") == "success":
            return (d.get("country","Unknown"), d.get("countryCode","??"),
                    d.get("city","Unknown"), d.get("regionName",""),
                    d.get("isp",""), d.get("org",""),
                    d.get("lat",0.0), d.get("lon",0.0))
    except Exception:
        pass
    return "Unknown","??","Unknown","","","",0.0,0.0

# ── Honeypot listener ─────────────────────────────────────────────────
def handle_connection(conn, addr, dst_port):
    src_ip, src_port = addr

    # ── BLOCK CHECK — instant cut if IP is on blocklist ──────────────
    if is_blocked(src_ip):
        try:
            conn.close()          # slam the door immediately
        except Exception:
            pass
        increment_block_hit(src_ip)
        print(f"  [BLOCKED] {src_ip} tried :{dst_port} — connection dropped")
        return                    # do NOT log, do NOT process
    # ─────────────────────────────────────────────────────────────────

    try:
        conn.settimeout(3)
        payload = conn.recv(1024).decode(errors="replace").strip()
    except Exception:
        payload = ""
    finally:
        try: conn.close()
        except: pass
    country, cc, city, region, isp, org, lat, lon = geoip_lookup(src_ip)
    save_attack(src_ip, src_port, dst_port, payload[:500],
                country, cc, city, region, isp, org, lat, lon)
    print(f"  [HIT] {src_ip}:{src_port} → :{dst_port} | {country}/{city} | {repr(payload[:50])}")

def listen_on_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except (PermissionError, OSError) as e:
        print(f"  [SKIP] Port {port}: {e}")
        return
    s.listen(100)
    print(f"  [OK]   Listening on port {port}")
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_connection, args=(conn, addr, port), daemon=True).start()
        except Exception as e:
            print(f"  [ERR]  Port {port}: {e}")

def start_honeypot():
    print("\n[HONEYPOT] Starting listeners...")
    for port in PORTS_TO_LISTEN:
        threading.Thread(target=listen_on_port, args=(port,), daemon=True).start()
    print(f"[HONEYPOT] Watching {len(PORTS_TO_LISTEN)} ports\n")

# ── Main ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 52)
    print("   HoneyTrap — Live Threat Intelligence")
    print("=" * 52)
    init_db()
    load_blocked_ips()
    start_honeypot()
    print(f"[DASHBOARD] http://localhost:{FLASK_PORT}")
    print("=" * 52 + "\n")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, threaded=True)
