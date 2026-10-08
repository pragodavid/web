import csv
import io
import ipaddress
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import Flask, Response, jsonify, render_template, request

NETFLOW_DIR = "/home/dejvaval/netflow"
NETQUALITY_DIR = "/home/dejvaval/netquality"
ANTENNA_SIGNAL_LOG = "/home/dejvaval/antenna_signal.log"
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
                "o2_download_mbps": float(row.get("o2_download_mbps") or 0),
                "o2_upload_mbps": float(row.get("o2_upload_mbps") or 0),
                "o2_ping_ms": float(row.get("o2_ping_ms") or 0),
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


# ---------- Kvalita linky v2 (SQLite z netquality-probe) ----------

NETQUALITY_DB = os.path.join(NETQUALITY_DIR, "netquality.db")
THRESHOLDS_PATH = os.path.join(NETQUALITY_DIR, "thresholds.json")
NQ_TARGETS = ["router", "isp-gateway", "1.1.1.1", "8.8.8.8"]
NQ_PUBLIC = ["1.1.1.1", "8.8.8.8"]
NQ_RANGES = {"1h": (3600, 60), "6h": (21600, 60), "24h": (86400, 300), "7d": (604800, 3600)}
STATUS_WINDOW = 300     # s — stav se hodnotí z posledních 5 minut
STALE_AFTER = 180       # s bez heartbeatu sběrače => červená
COLOR_RANK = {"green": 0, "yellow": 1, "red": 2}
COLOR_LABEL = {"green": "OK", "yellow": "Zhoršené", "red": "Výpadek"}
CAUSE_LABEL = {
    "lan": "domácí síť / router",
    "isp_access": "přípojka ISP",
    "isp_upstream": "internet za ISP",
    "target": "jen tento cíl",
    "unknown": "neurčeno",
}


def _nq_db():
    conn = sqlite3.connect(f"file:{NETQUALITY_DB}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _nq_thresholds():
    with open(THRESHOLDS_PATH) as f:
        return json.load(f)


def _nq_color(th, target, loss, avg, jitter):
    t = th["targets"]["public" if target in NQ_PUBLIC else target]
    if loss is None:
        return "red"
    if loss >= th["loss"]["red"] or (avg is not None and avg >= t["rtt"]["red"]) \
            or (jitter is not None and jitter >= t["jitter"]["red"]):
        return "red"
    if loss >= th["loss"]["yellow"] or (avg is not None and avg >= t["rtt"]["yellow"]) \
            or (jitter is not None and jitter >= t["jitter"]["yellow"]):
        return "yellow"
    return "green"


def _nq_aggregate_sql(bucket_expr):
    return f"""
        SELECT {bucket_expr} AS t, target, SUM(sent) AS sent, SUM(recv) AS recv,
               MIN(rtt_min) AS rtt_min,
               SUM(rtt_avg * recv) / NULLIF(SUM(CASE WHEN rtt_avg IS NOT NULL THEN recv END), 0) AS rtt_avg,
               MAX(rtt_max) AS rtt_max, MAX(rtt_p95) AS rtt_p95, AVG(jitter) AS jitter,
               MAX(speedtest) AS speedtest
        FROM minute WHERE ts >= ? GROUP BY t, target"""


def _r(x, nd=2):
    return None if x is None else round(x, nd)


@app.route("/api/quality/series")
def api_quality_series():
    rng = request.args.get("range", "24h")
    if rng not in NQ_RANGES:
        return jsonify({"error": f"range musí být jedno z {', '.join(NQ_RANGES)}"}), 400
    span, bucket = NQ_RANGES[rng]
    now = int(time.time())
    since = (now - span) // bucket * bucket
    buckets = list(range(since, now // bucket * bucket + 1, bucket))
    index = {t: i for i, t in enumerate(buckets)}
    fields = ["loss", "min", "avg", "max", "p95", "jitter"]
    series = {t: {f: [None] * len(buckets) for f in fields} for t in NQ_TARGETS}
    speedtest = [0] * len(buckets)
    try:
        with _nq_db() as conn:
            rows = conn.execute(_nq_aggregate_sql(f"ts / {bucket} * {bucket}"), (since,)).fetchall()
            events = conn.execute(
                "SELECT type, target, start, end, cause FROM events WHERE end IS NULL OR end >= ? ORDER BY start",
                (since,)).fetchall()
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc)}), 500
    for row in rows:
        i = index.get(row["t"])
        if i is None or row["target"] not in series:
            continue
        s = series[row["target"]]
        s["loss"][i] = _r(100.0 * (row["sent"] - row["recv"]) / row["sent"]) if row["sent"] else None
        s["min"][i], s["avg"][i], s["max"][i] = _r(row["rtt_min"]), _r(row["rtt_avg"]), _r(row["rtt_max"])
        s["p95"][i], s["jitter"][i] = _r(row["rtt_p95"]), _r(row["jitter"])
        speedtest[i] = max(speedtest[i], row["speedtest"] or 0)
    return jsonify({
        "range": rng, "bucket_s": bucket, "buckets": buckets, "targets": series, "speedtest": speedtest,
        "events": [dict(e) for e in events],
    })


@app.route("/api/quality/status")
def api_quality_status():
    now = time.time()
    try:
        th = _nq_thresholds()
        with _nq_db() as conn:
            meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
            rows = conn.execute(_nq_aggregate_sql("0"), (int(now // 60 * 60) - STATUS_WINDOW,)).fetchall()
            open_events = [dict(r) for r in conn.execute(
                "SELECT type, target, start, cause FROM events WHERE end IS NULL ORDER BY start")]
    except (OSError, ValueError, sqlite3.Error) as exc:
        return jsonify({"color": "red", "label": "Bez dat", "reason": f"Chyba čtení dat: {exc}",
                        "targets": {}}), 200
    heartbeat = float(meta.get("heartbeat") or 0)
    live = json.loads(meta.get("live") or "{}")
    agg = {r["target"]: r for r in rows}

    targets = {}
    for name in NQ_TARGETS:
        r = agg.get(name)
        loss = 100.0 * (r["sent"] - r["recv"]) / r["sent"] if r and r["sent"] else None
        avg, jitter = (r["rtt_avg"], r["jitter"]) if r else (None, None)
        lv = live.get(name, {})
        color = "red" if lv.get("down") else _nq_color(th, name, loss, avg, jitter)
        targets[name] = {"color": color, "loss": _r(loss), "avg": _r(avg), "jitter": _r(jitter),
                         "down": bool(lv.get("down")), "last_rtt": _r(lv.get("last_rtt"))}

    best_public = min((targets[t]["color"] for t in NQ_PUBLIC), key=COLOR_RANK.get)
    color = max([targets["router"]["color"], targets["isp-gateway"]["color"], best_public], key=COLOR_RANK.get)
    if color == "green" and any(targets[t]["color"] == "red" for t in NQ_PUBLIC):
        color = "yellow"

    outages = [e for e in open_events if e["type"] == "outage"]
    if now - heartbeat > STALE_AFTER:
        color, reason = "red", f"Sběrač neposílá data {int(now - heartbeat)} s"
    elif outages:
        e = min(outages, key=lambda e: list(CAUSE_LABEL).index(e["cause"] or "unknown"))
        reason = f"Výpadek: {CAUSE_LABEL.get(e['cause'], e['cause'])} ({e['target']}, {int(now - e['start'])} s)"
    elif color != "green":
        worst = max(NQ_TARGETS, key=lambda t: COLOR_RANK[targets[t]["color"]])
        t = targets[worst]
        reason = f"{worst}: loss {t['loss']} %, RTT {t['avg']} ms, jitter {t['jitter']} ms (5 min)"
    else:
        reason = "Všechny cíle v normě (5 min)"
    return jsonify({
        "color": color, "label": COLOR_LABEL[color], "reason": reason, "updated": heartbeat,
        "gateway": live.get("gateway"), "targets": targets, "open_events": open_events, "thresholds": th,
    })


def _union_seconds(intervals, lo, hi):
    total, cur_s, cur_e = 0.0, None, None
    for s, e in sorted((max(s, lo), min(e, hi)) for s, e in intervals):
        if e <= s:
            continue
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                total += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        total += cur_e - cur_s
    return total


@app.route("/api/quality/events")
def api_quality_events():
    try:
        days = float(request.args.get("days", "7"))
    except ValueError:
        return jsonify({"error": "parametr days musí být číslo"}), 400
    now = time.time()
    since = now - max(days, 7) * 86400
    try:
        with _nq_db() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT id, type, target, start, end, cause, source FROM events"
                " WHERE end IS NULL OR end >= ? ORDER BY start DESC", (since,))]
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc)}), 500
    for r in rows:
        r["ongoing"] = r["end"] is None
        r["duration_s"] = int((r["end"] or now) - r["start"])
        r["cause_label"] = CAUSE_LABEL.get(r["cause"], r["cause"])

    # dostupnost internetu: výpadky kromě těch, které se týkají jen jednoho veřejného cíle
    link_down = [(r["start"], r["end"] or now) for r in rows if r["type"] == "outage" and r["cause"] != "target"]
    summary = {}
    for label, span in (("24h", 86400), ("7d", 604800)):
        lo = now - span
        down = _union_seconds(link_down, lo, now)
        in_window = [r for r in rows if (r["end"] or now) >= lo]
        summary[label] = {
            "availability_pct": round(100 * (1 - down / span), 3),
            "downtime_s": int(down),
            "outages": sum(1 for r in in_window if r["type"] == "outage" and r["cause"] != "target"),
            "degraded": sum(1 for r in in_window if r["type"] == "degraded"),
        }
    cutoff = now - days * 86400
    return jsonify({"summary": summary, "events": [r for r in rows if (r["end"] or now) >= cutoff]})


# ---------- Export CSV (stejný formát jako ~/vyvadky_o2_log.csv) ----------

CSV_COLUMNS = ["datum", "čas začátek", "čas konec", "typ", "délka", "cíle", "příčina",
               "packet loss", "latence", "jitter", "rychlost internetu", "5G signál", "4G signál"]
CSV_TARGET_NAMES = {"router": "domácí router", "isp-gateway": "brána O2",
                    "1.1.1.1": "1.1.1.1 (Cloudflare)", "8.8.8.8": "8.8.8.8 (Google)"}
# výměna hlavního routeru na doporučení podpory O2 (není součástí reklamace)
CSV_INTERVENTION = (datetime(2026, 9, 23, 23, 0).timestamp(), datetime(2026, 9, 24, 0, 0).timestamp())
# ručně ověřené příčiny konkrétních výpadků (začátek incidentu v intervalu => příčina), viz ~/netquality/notes.md
CSV_CAUSE_OVERRIDES = [
    (datetime(2026, 10, 2, 14, 19).timestamp(), datetime(2026, 10, 2, 14, 20).timestamp(),
     "O2 přenastavilo anténu – konflikt IP adres (WAN 192.168.0.x vs LAN)"),
]
CSV_QUALITY_SQL = """
    SELECT SUM(sent), SUM(recv), SUM(rtt_avg * recv), SUM(CASE WHEN rtt_avg IS NOT NULL THEN recv END), AVG(jitter)
    FROM minute WHERE target IN ('1.1.1.1', '8.8.8.8')"""


def _csv_num(v, unit):
    return f"{v:.1f}".replace(".", ",") + unit


def _csv_quality(sent, recv, rtt_sum, rtt_n, jitter):
    if not sent:
        return ["", "", ""]
    return [_csv_num(100 * (sent - recv) / sent, " %"),
            _csv_num(rtt_sum / rtt_n, " ms") if rtt_n else "",
            _csv_num(jitter, " ms") if jitter is not None else ""]


def _csv_hms(sec):
    sec = int(round(sec))
    return f"{sec // 3600}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


def _csv_speeds():
    path = os.path.join(NETQUALITY_DIR, "speed.csv")
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return [(datetime.fromisoformat(r["timestamp_iso"]).timestamp(), r) for r in csv.DictReader(f)]


def _csv_antenna_signal():
    """Řádky z ~/antenna_signal.log: "[YYYY-MM-DD HH:MM:SS] 5G: ... | 4G: ..." -> (ts, 5G, 4G)."""
    if not os.path.exists(ANTENNA_SIGNAL_LOG):
        return []
    out = []
    with open(ANTENNA_SIGNAL_LOG, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                stamp, rest = line.strip()[1:].split("] ", 1)
                g5, g4 = (part.strip() for part in rest.split("|", 1))
                ts = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                continue
            out.append((ts, g5.removeprefix("5G:").strip(), g4.removeprefix("4G:").strip()))
    return out


def build_quality_csv_rows():
    """Výpadky (sloučené incidenty), měření rychlosti a hodinová kvalita linky, seřazené podle času."""
    speeds = _csv_speeds()
    rows = []
    with _nq_db() as conn:
        def quality(t0, t1):
            return _csv_quality(*conn.execute(CSV_QUALITY_SQL + " AND ts >= ? AND ts <= ?",
                                              (int(t0 // 60 * 60), int(t1))).fetchone())

        incidents = []
        for t, s, e, cause in conn.execute(
                "SELECT target, start, end, cause FROM events WHERE type = 'outage' AND end IS NOT NULL ORDER BY start"):
            if incidents and s <= incidents[-1]["end"] + 10:
                x = incidents[-1]
                x["end"] = max(x["end"], e)
                x["causes"].add(cause)
                x["targets"].add(t)
            else:
                incidents.append({"start": s, "end": e, "causes": {cause}, "targets": {t}})

        for x in incidents:
            cs = x["causes"]
            if "lan" in cs:
                why = "nedostupný domácí router – pravděpodobně výpadek el. energie (není součástí reklamace)"
            elif "isp_access" in cs:
                why = "nedostupná brána poskytovatele (O2)"
            elif "isp_upstream" in cs:
                why = "nedostupný internet"
            else:
                why = "nedostupný jen jeden veřejný server – není výpadek připojení (není součástí reklamace)"
            override = next((c for lo, hi, c in CSV_CAUSE_OVERRIDES if lo <= x["start"] < hi), None)
            if override:
                why = override
            if CSV_INTERVENTION[0] <= x["start"] < CSV_INTERVENTION[1]:
                why += " – výměna hlavního routeru na doporučení podpory O2 (není součástí reklamace)"
            if "lan" not in cs and not override and any(-5 <= x["start"] - t <= 150 for t, _ in speeds):
                why += " – začal během měření rychlosti"
            a, b = datetime.fromtimestamp(x["start"]), datetime.fromtimestamp(x["end"])
            end = b.strftime("%H:%M:%S") if b.date() == a.date() else b.strftime("%d.%m.%Y %H:%M:%S")
            rows.append((x["start"], [a.strftime("%d.%m.%Y"), a.strftime("%H:%M:%S"), end, "výpadek",
                                      _csv_hms(x["end"] - x["start"]),
                                      ", ".join(CSV_TARGET_NAMES[t] for t in NQ_TARGETS if t in x["targets"]), why]
                         + quality(x["start"], x["end"]) + [""]))

        for ts, r in speeds:
            a = datetime.fromtimestamp(ts)
            parts = []
            for prefix, name in (("", ""), ("o2_", "server O2 Praha: ")):
                if r.get(prefix + "download_mbps"):
                    parts.append(f"{name}stahování {r[prefix + 'download_mbps'].replace('.', ',')} Mbit/s, "
                                 f"odesílání {r[prefix + 'upload_mbps'].replace('.', ',')} Mbit/s, "
                                 f"odezva {r[prefix + 'ping_ms'].replace('.', ',')} ms")
            val = "; ".join(parts) or "měření se nezdařilo"
            rows.append((ts, [a.strftime("%d.%m.%Y"), a.strftime("%H:%M:%S"), "", "měření", "", "", ""]
                         + quality(ts, ts + 120) + [val]))

        # hodinová kvalita linky; poslední (neúplná) hodina se vynechává
        current_hour = int(time.time()) // 3600 * 3600
        for h, *q in conn.execute(
                "SELECT ts / 3600 * 3600 AS h, SUM(sent), SUM(recv), SUM(rtt_avg * recv),"
                " SUM(CASE WHEN rtt_avg IS NOT NULL THEN recv END), AVG(jitter)"
                " FROM minute WHERE target IN ('1.1.1.1', '8.8.8.8') AND speedtest = 0 AND ts < ?"
                " GROUP BY h ORDER BY h", (current_hour,)):
            if not q[0]:
                continue
            a, b = datetime.fromtimestamp(h), datetime.fromtimestamp(h + 3600)
            rows.append((h - 0.5, [a.strftime("%d.%m.%Y"), a.strftime("%H:%M:%S"), b.strftime("%H:%M:%S"),
                                   "kvalita linky", "1:00:00", "1.1.1.1 (Cloudflare), 8.8.8.8 (Google)", ""]
                         + _csv_quality(*q) + [""]))

    for ts, g5, g4 in _csv_antenna_signal():
        a = datetime.fromtimestamp(ts)
        rows.append((ts, [a.strftime("%d.%m.%Y"), a.strftime("%H:%M:%S"), "", "signál antény",
                          "", "", "", "", "", "", "", g5, g4]))
    rows.sort(key=lambda r: r[0])
    return [r + [""] * (len(CSV_COLUMNS) - len(r)) for _, r in rows]


@app.route("/download/csv")
def download_csv():
    try:
        rows = build_quality_csv_rows()
    except (OSError, ValueError, sqlite3.Error) as exc:
        return jsonify({"error": str(exc)}), 500
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(CSV_COLUMNS)
    w.writerows(rows)
    filename = f"netquality_export_{datetime.now():%Y-%m-%d}.csv"
    return Response("\ufeff" + buf.getvalue(), content_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "Cache-Control": "no-store"})


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    threading.Thread(target=dhcp_refresh_loop, daemon=True).start()
    threading.Thread(target=live_poll_loop, daemon=True).start()
    threading.Thread(target=external_names_refresh_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5001, threaded=True)
