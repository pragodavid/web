import csv
import io
import ipaddress
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import Flask, jsonify, render_template, request

NETFLOW_DIR = "/home/dejvaval/netflow"
NETQUALITY_DIR = "/home/dejvaval/netquality"
DHCP_REFRESH_INTERVAL = 600       # 10 minut
LIVE_POLL_INTERVAL = 3            # sekund
EXTERNAL_REFRESH_INTERVAL = 86400  # 24 hodin

ROUTEROS_HOST = "192.168.0.1"
ROUTEROS_USER = "dejvaval"

STATIC_NAMES = {
    "192.168.0.1": "MikroTik router",
    "192.168.0.153": "acer-debian",
    "192.168.0.101": "CAP chodba",
    "192.168.0.102": "CAP ložnice",
    "192.168.0.2": "Switch ValNet",
    "192.168.0.100": "NAS NSA320",
    "192.168.0.114": "DVR kamery",
    "192.168.0.178": "Kamera Xiaomi",
    "192.168.0.110": "Philips TV",
    "192.168.0.108": "Hyundai TV",
    "192.168.0.103": "Xbox One",
    "192.168.0.130": "Tiskárna Xerox",
    "192.168.0.131": "Tiskárna Brother",
    "192.168.0.140": "ESP spínač 1",
    "192.168.0.141": "ESP spínač 2",
    "192.168.0.151": "ESP spínač 3",
    "192.168.0.152": "ESP spínač 4",
    "192.168.0.181": "Google Nest Ana Pokoj",
    "192.168.0.139": "Google Nest Eli Pokoj",
    "192.168.0.148": "Google Nest Hub Kuchyně",
    "192.168.0.250": "Kamera - ulice příjezd",
    "192.168.0.99": "Kamera - ulice zahrada",
    "192.168.0.228": "Kamera - hlavní vchod",
    "192.168.0.173": "Kamera - zahrada",
    "192.168.0.154": "Kamera - garáž",
    "192.168.0.158": "Kamera - zadní vchod",
    "160.79.104.10": "Anthropic (Claude)",
    "192.168.5.95": "WAN (CGNAT ISP)",
    "167.235.72.200": "Tailscale DERP (Hetzner)",
}

app = Flask(__name__)

_dhcp_lock = threading.Lock()
_dhcp_cache = {}

_external_lock = threading.Lock()
_external_names = {}


def resolve_name(ip):
    with _dhcp_lock:
        name = _dhcp_cache.get(ip)
    if name:
        return name
    if ip in STATIC_NAMES:
        return STATIC_NAMES[ip]
    with _external_lock:
        name = _external_names.get(ip)
    if name:
        return name
    return ip


# ---------- DHCP cache ----------

def refresh_dhcp_cache():
    password = os.environ.get("ROUTEROS_PASS")
    if not password:
        print("ROUTEROS_PASS není nastaven, DHCP cache se nenačítá.", file=sys.stderr)
        return
    try:
        import routeros_api

        connection = routeros_api.RouterOsApiPool(
            ROUTEROS_HOST, username=ROUTEROS_USER, password=password, plaintext_login=True,
        )
        api = connection.get_api()
        leases = api.get_resource("/ip/dhcp-server/lease").get()
        new_cache = {}
        for lease in leases:
            ip = lease.get("address")
            host = lease.get("host-name") or lease.get("comment")
            if ip and host:
                new_cache[ip] = host
        connection.disconnect()
        with _dhcp_lock:
            _dhcp_cache.clear()
            _dhcp_cache.update(new_cache)
        print(f"DHCP cache obnovena: {len(new_cache)} záznamů", file=sys.stderr)
    except Exception as exc:
        print(f"Nepodařilo se obnovit DHCP cache: {exc}", file=sys.stderr)


def dhcp_refresh_loop():
    while True:
        refresh_dhcp_cache()
        time.sleep(DHCP_REFRESH_INTERVAL)


# ---------- Automatické pojmenování externích IP (RDAP + reverzní DNS) ----------

def _is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def _entity_fn(entity):
    for v in entity.get("vcardArray", [[], []])[1]:
        if v[0] == "fn":
            return v[3]
    return None


def _rdap_org_name(ip):
    try:
        resp = requests.get(f"https://rdap.org/ip/{ip}", timeout=5)
        if not resp.ok:
            return None
        data = resp.json()
        entities = data.get("entities", [])
        registrants = [e for e in entities if "registrant" in e.get("roles", [])]

        # preferuj jméno, které vypadá jako skutečný název organizace
        # (obsahuje mezeru a neshoduje se s handle kódem typu "HOS-GUN")
        named_candidates = []
        for e in registrants:
            name = _entity_fn(e)
            if name and " " in name and name != e.get("handle"):
                named_candidates.append(name)
        if named_candidates:
            return max(named_candidates, key=len)

        for e in registrants:
            name = _entity_fn(e)
            if name:
                return name
        for e in entities:
            name = _entity_fn(e)
            if name:
                return name
    except Exception:
        return None
    return None


def _reverse_dns_name(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _external_ips_from_history(hours=24):
    try:
        rows = run_nfdump_aggregate("srcip", build_time_window(hours))
        rows += run_nfdump_aggregate("dstip", build_time_window(hours))
    except Exception as exc:
        print(f"Nepodařilo se načíst historii pro externí jména: {exc}", file=sys.stderr)
        return set()
    return {row.get("val") for row in rows if row.get("val")}


def refresh_external_names():
    ips = _external_ips_from_history(24)
    new_names = {}
    for ip in ips:
        if not ip or ip in STATIC_NAMES or not _is_public_ip(ip):
            continue
        with _external_lock:
            already_known = ip in _external_names
        if already_known:
            continue
        name = _rdap_org_name(ip) or _reverse_dns_name(ip)
        if name:
            new_names[ip] = name
        time.sleep(0.2)  # šetrné tempo dotazů na externí služby

    if new_names:
        with _external_lock:
            _external_names.update(new_names)
        print(f"Externí jména aktualizována: {len(new_names)} nových záznamů", file=sys.stderr)


def external_names_refresh_loop():
    while True:
        refresh_external_names()
        time.sleep(EXTERNAL_REFRESH_INTERVAL)


# ---------- Historie (nfdump) ----------

def run_nfdump_aggregate(field, time_window=None):
    cmd = ["nfdump", "-R", NETFLOW_DIR]
    if time_window:
        cmd += ["-t", time_window]
    cmd += ["-s", field, "-n", "20", "-o", "csv", "-O", "bytes"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "nfdump selhal")
    return list(csv.DictReader(io.StringIO(result.stdout)))


def build_time_window(hours):
    now = datetime.now()
    start = now - timedelta(hours=hours)
    fmt = "%Y/%m/%d.%H:%M:%S"
    return f"{start.strftime(fmt)}-{now.strftime(fmt)}"


@app.route("/api/traffic/history")
def api_traffic_history():
    hours_param = request.args.get("hours", "24")
    try:
        hours = float(hours_param)
        if hours <= 0:
            raise ValueError
    except ValueError:
        return jsonify({"error": "parametr hours musí být kladné číslo"}), 400
    time_window = build_time_window(hours)

    try:
        src_rows = run_nfdump_aggregate("srcip", time_window)
        dst_rows = run_nfdump_aggregate("dstip", time_window)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    devices = {}
    for row in src_rows:
        ip = row.get("val")
        if not ip:
            continue
        d = devices.setdefault(ip, {"bytes_out": 0, "bytes_in": 0, "flows": 0})
        d["bytes_out"] += int(row.get("ibyt", 0) or 0)
        d["flows"] += int(row.get("fl", 0) or 0)

    for row in dst_rows:
        ip = row.get("val")
        if not ip:
            continue
        d = devices.setdefault(ip, {"bytes_out": 0, "bytes_in": 0, "flows": 0})
        d["bytes_in"] += int(row.get("ibyt", 0) or 0)
        d["flows"] += int(row.get("fl", 0) or 0)

    result = [
        {
            "name": resolve_name(ip),
            "ip": ip,
            "bytes_in": d["bytes_in"],
            "bytes_out": d["bytes_out"],
            "flows": d["flows"],
        }
        for ip, d in devices.items()
    ]
    result.sort(key=lambda x: x["bytes_in"] + x["bytes_out"], reverse=True)
    return jsonify(result)


# ---------- Live (routeros connection tracking) ----------

LIVE_IDLE_TIMEOUT = 10  # sekund bez dotazu na snapshot => live polling routeru se pozastaví

_live_lock = threading.Lock()
_live_latest = {"timestamp": None, "devices": []}
_last_snapshot_request = 0.0  # 0 => appka po startu nepolluje router, dokud nikdo neotevře Live


def _connection_bytes(conn):
    for key in ("orig-bytes", "orig_bytes"):
        if key in conn:
            orig = conn.get(key)
            break
    else:
        orig = "0"
    for key in ("repl-bytes", "reply-bytes", "repl_bytes"):
        if key in conn:
            repl = conn.get(key)
            break
    else:
        repl = "0"
    try:
        return int(orig or 0) + int(repl or 0)
    except ValueError:
        return 0


def live_poll_loop():
    import routeros_api

    prev_totals = {}
    prev_time = None
    connection = None

    while True:
        idle = (time.time() - _last_snapshot_request) > LIVE_IDLE_TIMEOUT
        if idle:
            if connection is not None:
                try:
                    connection.disconnect()
                except Exception:
                    pass
                connection = None
            prev_totals = {}
            prev_time = None
            time.sleep(LIVE_POLL_INTERVAL)
            continue

        password = os.environ.get("ROUTEROS_PASS")
        if not password:
            time.sleep(LIVE_POLL_INTERVAL)
            continue
        try:
            if connection is None:
                connection = routeros_api.RouterOsApiPool(
                    ROUTEROS_HOST, username=ROUTEROS_USER, password=password, plaintext_login=True,
                )
            api = connection.get_api()
            conns = api.get_resource("/ip/firewall/connection").get()

            now = time.time()
            totals = {}
            for c in conns:
                src = c.get("src-address", "")
                ip = src.split(":")[0] if src else None
                if not ip:
                    continue
                totals[ip] = totals.get(ip, 0) + _connection_bytes(c)

            devices = []
            if prev_time is not None:
                dt = max(now - prev_time, 0.001)
                for ip, total in totals.items():
                    prev = prev_totals.get(ip, total)
                    delta = max(total - prev, 0)
                    bps = (delta * 8) / dt
                    devices.append({"ip": ip, "name": resolve_name(ip), "bps": round(bps, 1)})
                devices.sort(key=lambda d: d["bps"], reverse=True)

            prev_totals = totals
            prev_time = now

            with _live_lock:
                _live_latest["timestamp"] = datetime.now().isoformat()
                _live_latest["devices"] = devices

        except Exception as exc:
            print(f"Chyba live pollingu: {exc}", file=sys.stderr)
            try:
                if connection:
                    connection.disconnect()
            except Exception:
                pass
            connection = None
            prev_totals = {}
            prev_time = None

        time.sleep(LIVE_POLL_INTERVAL)


@app.route("/api/traffic/snapshot")
def api_traffic_snapshot():
    global _last_snapshot_request
    _last_snapshot_request = time.time()
    with _live_lock:
        payload = dict(_live_latest)
    return jsonify(payload)


# ---------- Kvalita linky (latence, packet loss, rychlost) ----------

def _parse_iso(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _read_csv_rows(filename):
    path = os.path.join(NETQUALITY_DIR, filename)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except Exception as exc:
        print(f"Nepodařilo se přečíst {filename}: {exc}", file=sys.stderr)
        return []


@app.route("/api/quality/latency")
def api_quality_latency():
    try:
        hours = float(request.args.get("hours", "24"))
    except ValueError:
        return jsonify({"error": "parametr hours musí být číslo"}), 400
    target_filter = request.args.get("target")

    cutoff = datetime.now() - timedelta(hours=hours)
    result = []
    for row in _read_csv_rows("latency.csv"):
        ts = _parse_iso(row.get("timestamp_iso", ""))
        if ts is None or ts < cutoff:
            continue
        target = row.get("target", "")
        if target_filter and target != target_filter:
            continue
        avg_raw = (row.get("avg_ms") or "").strip()
        loss_raw = (row.get("loss_pct") or "").strip()
        result.append({
            "timestamp": row.get("timestamp_iso"),
            "target": target,
            "avg_ms": float(avg_raw) if avg_raw else None,
            "loss_pct": float(loss_raw) if loss_raw else None,
        })
    result.sort(key=lambda x: x["timestamp"] or "")
    return jsonify(result)


@app.route("/api/quality/speed")
def api_quality_speed():
    try:
        days = float(request.args.get("days", "7"))
    except ValueError:
        return jsonify({"error": "parametr days musí být číslo"}), 400

    cutoff = datetime.now() - timedelta(days=days)
    result = []
    for row in _read_csv_rows("speed.csv"):
        ts = _parse_iso(row.get("timestamp_iso", ""))
        if ts is None or ts < cutoff:
            continue
        try:
            result.append({
                "timestamp": row.get("timestamp_iso"),
                "download_mbps": float(row.get("download_mbps") or 0),
                "upload_mbps": float(row.get("upload_mbps") or 0),
                "ping_ms": float(row.get("ping_ms") or 0),
            })
        except ValueError:
            continue
    result.sort(key=lambda x: x["timestamp"] or "")
    return jsonify(result)


@app.route("/api/quality/outages")
def api_quality_outages():
    try:
        days = float(request.args.get("days", "7"))
    except ValueError:
        return jsonify({"error": "parametr days musí být číslo"}), 400

    cutoff = datetime.now() - timedelta(days=days)
    result = []
    for row in _read_csv_rows("outages.csv"):
        ts = _parse_iso(row.get("timestamp_iso", ""))
        if ts is None or ts < cutoff:
            continue
        try:
            duration = int(float(row.get("duration_s") or 0))
        except ValueError:
            duration = 0
        result.append({
            "timestamp": row.get("timestamp_iso"),
            "target": row.get("target", ""),
            "duration_s": duration,
        })
    result.sort(key=lambda x: x["timestamp"] or "")
    return jsonify(result)


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    threading.Thread(target=dhcp_refresh_loop, daemon=True).start()
    threading.Thread(target=live_poll_loop, daemon=True).start()
    threading.Thread(target=external_names_refresh_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5001, threaded=True)
