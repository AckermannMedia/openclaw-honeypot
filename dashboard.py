#!/usr/bin/env python3
"""Honeypot Dashboard - only accessible via Tailscale"""

import os
import json
import sqlite3
import subprocess
import re
import secrets
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string
import urllib.request

app = Flask(__name__)

# --- Config loader (fnord.conf → environment → default) ---
CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fnord.conf")

def load_config():
    """Load config from fnord.conf if it exists."""
    cfg = {}
    if os.path.exists(CONF_FILE):
        with open(CONF_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

_cfg = load_config()

OPENCLAW_API_URL = _cfg.get("OPENCLAW_API_URL", os.environ.get("OPENCLAW_API_URL", "http://localhost:18789"))
KEY_FILE = _cfg.get("OPENCLAW_KEY_FILE", os.environ.get("HONEYPOT_KEY_FILE", "/app/data/api.key"))
HONEYPOT_LOG = _cfg.get("HONEYPOT_LOG", os.environ.get("FNORD_HONEYPOT_LOG", "/var/log/nginx/honeypot.log"))
HONEYPOT_LOG_OLD = HONEYPOT_LOG + ".1"
F2B_DB = _cfg.get("F2B_DB", os.environ.get("FNORD_F2B_DB", "/var/lib/fail2ban/fail2ban.sqlite3"))
F2B_LOG = _cfg.get("F2B_LOG", os.environ.get("FNORD_F2B_LOG", "/var/log/fail2ban.log"))
F2B_LOG_OLD = F2B_LOG + ".1"
BIND_HOST = _cfg.get("BIND_HOST", os.environ.get("FNORD_BIND_HOST", "127.0.0.1"))
BIND_PORT = int(_cfg.get("BIND_PORT", os.environ.get("FNORD_BIND_PORT", "8888")))

def _load_or_create_key(path):
    """Load API key from file, or generate a new random one."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return open(path).read().strip()
    key = secrets.token_urlsafe(48)
    with open(path, 'w') as f:
        f.write(key)
    return key

OPENCLAW_API_KEY = _load_or_create_key(KEY_FILE)

GEOIP_CACHE = {}

# === AI BOT DETECTION ===

AI_BOT_SIGNATURES = {
    # OpenAI
    "GPTBot":           {"company": "OpenAI",      "purpose": "Training Crawler",    "icon": "\U0001f916"},
    "ChatGPT-User":     {"company": "OpenAI",      "purpose": "Live Browsing",       "icon": "\U0001f4ac"},
    "OAI-SearchBot":    {"company": "OpenAI",      "purpose": "Search Index",        "icon": "\U0001f50d"},
    # Anthropic
    "ClaudeBot":        {"company": "Anthropic",    "purpose": "Training Crawler",    "icon": "\U0001f9e0"},
    "Claude-User":      {"company": "Anthropic",    "purpose": "Live Browsing",       "icon": "\U0001f4ac"},
    "anthropic-ai":     {"company": "Anthropic",    "purpose": "Training Crawler",    "icon": "\U0001f9e0"},
    "claude-web":       {"company": "Anthropic",    "purpose": "Web Crawl",           "icon": "\U0001f310"},
    # Perplexity
    "PerplexityBot":    {"company": "Perplexity",   "purpose": "Search Crawler",      "icon": "\U0001f52e"},
    "Perplexity-User":  {"company": "Perplexity",   "purpose": "Live Query",          "icon": "\U0001f4ac"},
    # Meta
    "Meta-ExternalAgent":{"company": "Meta",        "purpose": "LLM Training",        "icon": "\U0001f4d8"},
    "FacebookBot":       {"company": "Meta",        "purpose": "Web Crawler",         "icon": "\U0001f4d8"},
    # Google
    "Google-Extended":  {"company": "Google",       "purpose": "Gemini Training",     "icon": "\U0001f48e"},
    "Googlebot":        {"company": "Google",       "purpose": "Search Crawler",      "icon": "\U0001f50d"},
    # ByteDance
    "Bytespider":       {"company": "ByteDance",    "purpose": "AI Training",         "icon": "\U0001f577"},
    # Amazon
    "Amazonbot":        {"company": "Amazon",       "purpose": "Alexa/AI",            "icon": "\U0001f4e6"},
    # Apple
    "Applebot":         {"company": "Apple",        "purpose": "Siri/Spotlight",      "icon": "\U0001f34e"},
    # DuckDuckGo
    "DuckAssistBot":    {"company": "DuckDuckGo",   "purpose": "AI Answers",          "icon": "\U0001f986"},
    # Common Crawl
    "CCBot":            {"company": "Common Crawl", "purpose": "Open Dataset",        "icon": "\U0001f4da"},
    # Cohere
    "cohere-ai":        {"company": "Cohere",       "purpose": "Training Crawler",    "icon": "\u2699"},
    # AI2
    "Ai2Bot":           {"company": "AI2",          "purpose": "Research Crawler",    "icon": "\U0001f393"},
    # Diffbot
    "Diffbot":          {"company": "Diffbot",      "purpose": "Knowledge Graph",     "icon": "\U0001f578"},
}

AI_TRAP_PATHS = {
    "/fnord/23/confirm":   "Canary Endpoint",
    "/llm.txt":            "LLM Instructions",
    "/.well-known/ai-plugin.json": "Plugin Manifest",
    "/openapi.yaml":       "OpenAPI Spec",
    "/internal/api-keys":  "Fake API Keys",
    "/.secrets/vault-key": "Fake Vault Key",
    "/debug/tokens":       "Fake Debug Tokens",
    "/internal/ai-compliance-report": "AI Compliance Bait",
    "/api/v2/export/full": "Export Bait",
    "/api/v2/security/report": "Security Report Bait",
    "/backups/latest.sql.gz": "Backup Bait",
    "/internal/master-password": "Master PW Bait",
    "/sitemap.xml":        "Sitemap",
    "/.well-known/security.txt": "Security.txt",
}

BEACON_PATH = "/hp-beacon"


def classify_ai_bot(ua):
    """Classify a user-agent string. Returns (bot_name, info) or (None, None)."""
    if not ua:
        return None, None
    for sig, info in AI_BOT_SIGNATURES.items():
        if sig.lower() in ua.lower():
            return sig, info
    return None, None


def is_ai_trap_path(path):
    """Check if a path is an AI-specific trap."""
    for trap_path, label in AI_TRAP_PATHS.items():
        if path.startswith(trap_path):
            return label
    return None


def analyze_ai_bots(entries):
    """Analyze honeypot logs for AI bot activity."""
    ai_entries = []
    canary_hits = []
    trap_hits = defaultdict(int)
    bot_stats = defaultdict(lambda: {"count": 0, "paths": Counter(), "ips": set(), "first_seen": None, "last_seen": None})
    behavioral_suspects = []

    # Track IPs that loaded page but never fired JS beacon
    page_loaders = set()
    beacon_fires = set()

    for e in entries:
        path = e.get("path", "")
        ua = e.get("ua", "")
        ip = e.get("ip", "")
        time = e.get("time", "")

        # Track JS beacon
        if path.startswith(BEACON_PATH):
            beacon_fires.add(ip)
            continue

        # Track page loads (root page)
        if path == "/" or path == "":
            page_loaders.add(ip)

        # Check user-agent
        bot_name, bot_info = classify_ai_bot(ua)
        if bot_name:
            ai_entries.append(e)
            stats = bot_stats[bot_name]
            stats["count"] += 1
            stats["paths"][path] += 1
            stats["ips"].add(ip)
            stats["info"] = bot_info
            if not stats["first_seen"] or time < stats["first_seen"]:
                stats["first_seen"] = time
            if not stats["last_seen"] or time > stats["last_seen"]:
                stats["last_seen"] = time

        # Check trap paths
        trap_label = is_ai_trap_path(path)
        if trap_label:
            trap_hits[trap_label] += 1
            if "fnord/23/confirm" in path:
                agent_param = ""
                if "agent=" in path:
                    agent_param = path.split("agent=")[-1].split("&")[0]
                canary_hits.append({
                    "ip": ip, "time": time, "ua": ua, "agent_param": agent_param,
                })

    # Behavioral: loaded page but no JS beacon = likely bot
    no_js = page_loaders - beacon_fires
    for ip in no_js:
        ip_entries = [e for e in entries if e.get("ip") == ip and not e.get("path", "").startswith(BEACON_PATH)]
        if len(ip_entries) >= 2:
            ua = ip_entries[0].get("ua", "")
            bot_name, _ = classify_ai_bot(ua)
            if not bot_name:
                behavioral_suspects.append({
                    "ip": ip,
                    "ua": ua[:80],
                    "requests": len(ip_entries),
                    "reason": "Page loaded, no JS executed",
                    "paths": [e.get("path", "") for e in ip_entries[:5]],
                })

    # Build response
    bots_summary = []
    for name, stats in sorted(bot_stats.items(), key=lambda x: -x[1]["count"]):
        geo_data = {}
        for ip in list(stats["ips"])[:3]:
            geo_data[ip] = geoip_lookup(ip)
        bots_summary.append({
            "name": name,
            "company": stats["info"]["company"],
            "purpose": stats["info"]["purpose"],
            "icon": stats["info"]["icon"],
            "count": stats["count"],
            "unique_ips": len(stats["ips"]),
            "ips": [{"ip": ip, **geoip_lookup(ip)} for ip in list(stats["ips"])[:5]],
            "top_paths": [{"path": p, "count": c} for p, c in stats["paths"].most_common(5)],
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"],
        })

    trap_summary = [{"trap": t, "count": c} for t, c in sorted(trap_hits.items(), key=lambda x: -x[1])]

    return {
        "total_ai_hits": len(ai_entries),
        "unique_bots": len(bot_stats),
        "canary_hits": len(canary_hits),
        "behavioral_suspects_count": len(behavioral_suspects),
        "bots": bots_summary,
        "traps": trap_summary,
        "canary_details": canary_hits[-20:][::-1],
        "behavioral_suspects": behavioral_suspects[:15],
        "recent_ai": [e for e in ai_entries[-20:][::-1]],
    }


def parse_logfile(logfile):
    entries = []
    if not os.path.exists(logfile):
        return entries
    with open(logfile, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5:
                raw_path = parts[2].split(" ")[0] if parts[2] else ""
                path = raw_path.split("?")[0]
                entries.append({
                    "ip": parts[0],
                    "time": parts[1],
                    "path": path,
                    "status": parts[3],
                    "ua": parts[4] if len(parts) > 4 else "",
                    "ref": parts[5] if len(parts) > 5 else "",
                })
    return entries


def parse_honeypot_logs():
    entries = []
    for logfile in (HONEYPOT_LOG_OLD, HONEYPOT_LOG):
        entries.extend(parse_logfile(logfile))
    return entries


def geoip_lookup(ip):
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    try:
        import urllib.request
        resp = urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,query",
            timeout=3,
        )
        data = json.loads(resp.read())
        GEOIP_CACHE[ip] = data
        return data
    except:
        return {"country": "Unknown", "countryCode": "??", "city": "", "isp": ""}


def get_f2b_live_status():
    """Get live fail2ban status via fail2ban-client."""
    result = {"jails": []}
    try:
        out = subprocess.check_output(
            ["fail2ban-client", "status"], text=True, timeout=5
        )
        jails = []
        for line in out.splitlines():
            if "Jail list:" in line:
                jails = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]

        for jail in jails:
            try:
                jout = subprocess.check_output(
                    ["fail2ban-client", "status", jail], text=True, timeout=5
                )
                info = {"name": jail, "failed": 0, "total_failed": 0,
                        "banned": 0, "total_banned": 0, "banned_ips": []}
                for line in jout.splitlines():
                    line = line.strip()
                    if "Currently failed:" in line:
                        info["failed"] = int(line.split(":")[-1].strip())
                    elif "Total failed:" in line:
                        info["total_failed"] = int(line.split(":")[-1].strip())
                    elif "Currently banned:" in line:
                        info["banned"] = int(line.split(":")[-1].strip())
                    elif "Total banned:" in line:
                        info["total_banned"] = int(line.split(":")[-1].strip())
                    elif "Banned IP list:" in line:
                        ips_str = line.split(":", 1)[-1].strip()
                        if ips_str:
                            info["banned_ips"] = ips_str.split()
                result["jails"].append(info)
            except:
                pass
    except:
        pass
    return result


def get_f2b_db_stats():
    """Get historical fail2ban data from SQLite database."""
    stats = {
        "total_bans": 0,
        "unique_ips": 0,
        "top_banned": [],
        "recent_bans": [],
        "bans_timeline": [],
        "bans_by_hour": {},
        "repeat_offenders": [],
        "top_countries": [],
    }
    if not os.path.exists(F2B_DB):
        return stats

    try:
        conn = sqlite3.connect(F2B_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Total bans
        c.execute("SELECT COUNT(*) FROM bans")
        stats["total_bans"] = c.fetchone()[0]

        # Unique IPs
        c.execute("SELECT COUNT(DISTINCT ip) FROM bans")
        stats["unique_ips"] = c.fetchone()[0]

        # Top banned IPs (from bans table, grouped)
        c.execute("""
            SELECT ip, COUNT(*) as cnt
            FROM bans
            GROUP BY ip
            ORDER BY cnt DESC
            LIMIT 15
        """)
        top_ips = []
        for row in c.fetchall():
            geo = geoip_lookup(row["ip"])
            top_ips.append({
                "ip": row["ip"],
                "count": row["cnt"],
                "country": geo.get("country", "?"),
                "cc": geo.get("countryCode", "??"),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", ""),
            })
        stats["top_banned"] = top_ips

        # Recent bans
        c.execute("""
            SELECT ip, jail, datetime(timeofban, 'unixepoch') as time, bancount
            FROM bans
            ORDER BY timeofban DESC
            LIMIT 50
        """)
        stats["recent_bans"] = [
            {"ip": r["ip"], "jail": r["jail"], "time": r["time"], "bancount": r["bancount"]}
            for r in c.fetchall()
        ]

        # Bans timeline (last 14 days)
        cutoff = int((datetime.now() - timedelta(days=14)).timestamp())
        c.execute("""
            SELECT date(timeofban, 'unixepoch') as day, COUNT(*) as cnt
            FROM bans
            WHERE timeofban > ?
            GROUP BY day
            ORDER BY day
        """, (cutoff,))
        stats["bans_timeline"] = [
            {"date": r["day"], "count": r["cnt"]} for r in c.fetchall()
        ]

        # Bans by hour
        c.execute("""
            SELECT strftime('%H', timeofban, 'unixepoch') as hour, COUNT(*) as cnt
            FROM bans
            GROUP BY hour
        """)
        stats["bans_by_hour"] = {r["hour"]: r["cnt"] for r in c.fetchall()}

        # Repeat offenders (banned more than once)
        c.execute("""
            SELECT ip, COUNT(*) as cnt,
                   datetime(MAX(timeofban), 'unixepoch') as last_ban
            FROM bans
            GROUP BY ip
            HAVING cnt > 1
            ORDER BY cnt DESC
            LIMIT 15
        """)
        for row in c.fetchall():
            geo = geoip_lookup(row["ip"])
            stats["repeat_offenders"].append({
                "ip": row["ip"],
                "count": row["cnt"],
                "last_ban": row["last_ban"],
                "country": geo.get("country", "?"),
                "cc": geo.get("countryCode", "??"),
                "isp": geo.get("isp", ""),
            })

        # Top countries
        c.execute("SELECT DISTINCT ip FROM bans")
        country_counter = Counter()
        for row in c.fetchall():
            geo = geoip_lookup(row["ip"])
            cc = geo.get("countryCode", "??")
            country = geo.get("country", "Unknown")
            country_counter[(cc, country)] += 1
        stats["top_countries"] = [
            {"cc": cc, "country": cn, "count": cnt}
            for (cc, cn), cnt in country_counter.most_common(10)
        ]

        conn.close()
    except Exception as e:
        stats["error"] = str(e)

    return stats


def get_attack_patterns():
    """Analyze SSH journal logs for attack patterns."""
    patterns = {
        "top_usernames": [],
        "attack_types": [],
        "brute_force_ips": [],
        "attack_waves": [],
        "username_categories": {},
        "auth_methods": {},
        "velocity": [],
    }
    try:
        # Get last 24h of SSH logs
        out = subprocess.check_output(
            ["journalctl", "-u", "ssh", "--no-pager", "--since", "24 hours ago", "-o", "short-iso"],
            text=True, timeout=15,
        )
        lines = out.strip().split("\n")

        usernames = []
        ips_timestamps = defaultdict(list)  # ip -> [timestamps]
        invalid_users = []
        failed_passwords = []
        preauth_closed = 0
        accepted = 0
        timeout_count = 0
        methods = Counter()

        for line in lines:
            # Invalid user
            m = re.search(r"Invalid user (\S+) from ([\d.]+)", line)
            if m:
                usernames.append(m.group(1))
                invalid_users.append({"user": m.group(1), "ip": m.group(2)})
                # Extract timestamp
                ts = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                if ts:
                    ips_timestamps[m.group(2)].append(ts.group(1))
                continue

            # Failed password
            m = re.search(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", line)
            if m:
                failed_passwords.append({"user": m.group(1), "ip": m.group(2)})
                ts = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                if ts:
                    ips_timestamps[m.group(2)].append(ts.group(1))
                methods["password"] += 1
                continue

            # Accepted
            m = re.search(r"Accepted (\S+) for (\S+) from ([\d.]+)", line)
            if m:
                accepted += 1
                methods[m.group(1)] += 1
                continue

            # Preauth disconnect
            if "preauth" in line:
                preauth_closed += 1

            # Timeout
            if "Timeout before authentication" in line:
                timeout_count += 1

        # Top usernames
        user_counts = Counter(usernames).most_common(20)
        patterns["top_usernames"] = [{"user": u, "count": c} for u, c in user_counts]

        # Categorize usernames
        categories = {
            "system": ["root", "admin", "administrator", "test", "user", "guest", "info", "support"],
            "database": ["postgres", "mysql", "oracle", "mongo", "redis", "db", "database"],
            "devops": ["ubuntu", "centos", "debian", "docker", "ansible", "jenkins", "git", "deploy", "ci"],
            "crypto": ["solana", "sol", "solv", "validator", "miner", "eth", "bitcoin", "node", "jito"],
            "services": ["ftp", "ftptest", "mail", "www", "nginx", "apache", "tomcat", "vpn", "proxy"],
            "custom": [],
        }
        cat_counts = defaultdict(int)
        known_users = set()
        for cat, names in categories.items():
            known_users.update(names)
        for user in usernames:
            categorized = False
            for cat, names in categories.items():
                if user.lower() in names:
                    cat_counts[cat] += 1
                    categorized = True
                    break
            if not categorized:
                cat_counts["custom"] += 1
        patterns["username_categories"] = [
            {"category": k, "count": v} for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])
        ]

        # Attack types summary
        patterns["attack_types"] = [
            {"type": "Invalid User", "count": len(invalid_users), "color": "orange"},
            {"type": "Failed Password", "count": len(failed_passwords), "color": "red"},
            {"type": "Preauth Disconnect", "count": preauth_closed, "color": "amber"},
            {"type": "Timeout", "count": timeout_count, "color": "purple"},
            {"type": "Accepted", "count": accepted, "color": "green"},
        ]

        # Auth methods
        patterns["auth_methods"] = [{"method": k, "count": v} for k, v in methods.most_common()]

        # Brute force detection: IPs with >10 attempts in 24h
        ip_attempt_counts = Counter()
        for ip, user_data in [(e["ip"], e["user"]) for e in invalid_users + failed_passwords]:
            ip_attempt_counts[ip] += 1

        ip_counts_sorted = ip_attempt_counts.most_common(15)
        brute_force = []
        for ip, count in ip_counts_sorted:
            timestamps = ips_timestamps.get(ip, [])
            # Calculate velocity (attempts per minute)
            if len(timestamps) >= 2:
                try:
                    t0 = datetime.fromisoformat(timestamps[0])
                    t1 = datetime.fromisoformat(timestamps[-1])
                    duration = (t1 - t0).total_seconds()
                    velocity = count / (duration / 60) if duration > 0 else count
                except:
                    velocity = 0
            else:
                velocity = 0

            # Unique usernames tried by this IP
            ip_users = set()
            for e in invalid_users + failed_passwords:
                if e["ip"] == ip:
                    ip_users.add(e["user"])

            geo = geoip_lookup(ip)
            brute_force.append({
                "ip": ip,
                "count": count,
                "velocity": round(velocity, 1),
                "unique_users": len(ip_users),
                "sample_users": sorted(ip_users)[:5],
                "country": geo.get("country", "?"),
                "cc": geo.get("countryCode", "??"),
                "isp": geo.get("isp", ""),
            })
        patterns["brute_force_ips"] = brute_force

        # Attack waves: group attempts by 10-min windows
        wave_counts = defaultdict(int)
        for ip, timestamps in ips_timestamps.items():
            for ts in timestamps:
                try:
                    bucket = ts[:15] + "0"  # round to 10 min
                    wave_counts[bucket] += 1
                except:
                    pass
        waves_sorted = sorted(wave_counts.items())[-72:]  # last 12h in 10min buckets
        patterns["attack_waves"] = [{"time": t, "count": c} for t, c in waves_sorted]

        # Total stats
        patterns["total_attempts"] = len(invalid_users) + len(failed_passwords)
        patterns["total_invalid"] = len(invalid_users)
        patterns["total_failed_pw"] = len(failed_passwords)
        patterns["total_accepted"] = accepted
        patterns["unique_attackers"] = len(ip_attempt_counts)
        patterns["unique_usernames"] = len(set(usernames))

    except Exception as e:
        patterns["error"] = str(e)

    return patterns


def parse_f2b_log():
    """Parse fail2ban log for recent activity (Found/Ban/Unban)."""
    events = []
    for logfile in (F2B_LOG_OLD, F2B_LOG):
        if not logfile or not os.path.exists(logfile):
            continue
        try:
            with open(logfile, "r") as f:
                for line in f:
                    m = re.match(
                        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[(\d+)\]:\s+(\w+)\s+\[(\w+)\]\s+(Found|Ban|Unban|Restore Ban)\s+([\d.]+)",
                        line,
                    )
                    if m:
                        events.append({
                            "time": m.group(1),
                            "level": m.group(3),
                            "jail": m.group(4),
                            "action": m.group(5),
                            "ip": m.group(6),
                        })
        except:
            pass
    return events


@app.route("/")
def dashboard():
    return render_template_string(HTML)


@app.route("/api/stats")
def stats():
    entries = parse_honeypot_logs()
    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")

    if not entries:
        hp_stats = {"total": 0, "today": 0, "unique_ips": 0, "paths": [], "ips": [],
                     "timeline": [], "recent": [], "ua": [], "hours": {}}
    else:
        today_entries = [e for e in entries if today_str in e["time"]]
        timeline = defaultdict(int)
        for e in entries:
            try:
                timeline[e["time"][:10]] += 1
            except:
                pass
        timeline_sorted = sorted(timeline.items())[-14:]
        path_counts = Counter(e["path"] for e in entries).most_common(10)
        ip_counts = Counter(e["ip"] for e in entries).most_common(15)
        ip_data = []
        for ip, count in ip_counts:
            geo = geoip_lookup(ip)
            ip_data.append({
                "ip": ip, "count": count,
                "country": geo.get("country", "?"),
                "cc": geo.get("countryCode", "??"),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", ""),
            })
        ua_counts = Counter(e["ua"] for e in entries).most_common(10)
        recent = entries[-30:][::-1]
        hours = defaultdict(int)
        for e in entries:
            try:
                hours[e["time"][11:13]] += 1
            except:
                pass
        hp_stats = {
            "total": len(entries),
            "today": len(today_entries),
            "unique_ips": len(set(e["ip"] for e in entries)),
            "unique_ips_today": len(set(e["ip"] for e in today_entries)),
            "paths": [{"path": p, "count": c} for p, c in path_counts],
            "ips": ip_data,
            "timeline": [{"date": d, "count": c} for d, c in timeline_sorted],
            "recent": recent,
            "ua": [{"ua": u, "count": c} for u, c in ua_counts],
            "hours": dict(hours),
        }

    return jsonify(hp_stats)


@app.route("/api/f2b")
def f2b_stats():
    live = get_f2b_live_status()
    db = get_f2b_db_stats()
    log_events = parse_f2b_log()

    # Recent log activity (last 100)
    recent_events = log_events[-100:][::-1]

    # Attacks per minute (last hour from log)
    one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    recent_found = [e for e in log_events if e["action"] == "Found" and e["time"] >= one_hour_ago]
    attacks_per_min = len(recent_found) / 60.0 if recent_found else 0

    # Today's bans from log
    today_str = datetime.now().strftime("%Y-%m-%d")
    today_bans = [e for e in log_events if e["action"] in ("Ban", "Restore Ban") and e["time"].startswith(today_str)]
    today_found = [e for e in log_events if e["action"] == "Found" and e["time"].startswith(today_str)]

    return jsonify({
        "live": live,
        "db": db,
        "recent_events": recent_events,
        "attacks_per_min": round(attacks_per_min, 1),
        "today_bans": len(today_bans),
        "today_attempts": len(today_found),
    })


@app.route("/api/patterns")
def attack_patterns():
    return jsonify(get_attack_patterns())


@app.route("/api/ai-bots")
def ai_bots():
    entries = parse_honeypot_logs()
    return jsonify(analyze_ai_bots(entries))


def fetch_openclaw_api(endpoint):
    """Fetch data from the OpenClaw honeypot API."""
    try:
        req = urllib.request.Request(
            f"{OPENCLAW_API_URL}{endpoint}",
            headers={"X-API-Key": OPENCLAW_API_KEY}
        )
        resp = urllib.request.urlopen(req, timeout=5)
        return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


@app.route("/api/openclaw")
def openclaw_stats():
    """Aggregate all OpenClaw honeypot data."""
    stats = fetch_openclaw_api("/api/honeypot/stats")
    logs = fetch_openclaw_api("/api/honeypot/logs")
    chat = fetch_openclaw_api("/api/honeypot/chat-messages")
    logins = fetch_openclaw_api("/api/honeypot/login-attempts")

    # Analyze logs for click tracking and bot detection
    clicks = {}
    sessions = {}
    bots = []
    humans = []
    page_views = []

    all_logs = logs.get("logs", []) if isinstance(logs, dict) else []

    for entry in all_logs:
        ip = entry.get("ip", "unknown")
        ua = entry.get("user_agent", "")
        timestamp = entry.get("timestamp", "")
        event = entry.get("event", "")
        data = entry.get("data", {})

        # Extract page from data for page_view events
        page = data.get("page", "") if isinstance(data, dict) else ""
        action = data.get("action", "") if isinstance(data, dict) else ""

        # Track page views
        if event == "page_view" and page:
            page_views.append(page)

        # Track sessions per IP
        if ip not in clicks:
            clicks[ip] = {"pages": [], "events": [], "first_seen": timestamp, "last_seen": timestamp, "ua": ua}
        if page:
            clicks[ip]["pages"].append(page)
        clicks[ip]["events"].append(event)
        if timestamp > clicks[ip]["last_seen"]:
            clicks[ip]["last_seen"] = timestamp
        if timestamp < clicks[ip]["first_seen"]:
            clicks[ip]["first_seen"] = timestamp

        # Bot detection based on User-Agent
        is_bot = False
        bot_indicators = ["bot", "crawler", "spider", "curl", "wget", "python", "go-http", "scrapy", "headless"]
        ua_lower = ua.lower()
        for indicator in bot_indicators:
            if indicator in ua_lower:
                is_bot = True
                break

        if is_bot:
            if ip not in [b["ip"] for b in bots]:
                bots.append({"ip": ip, "ua": ua, "events": 1})
            else:
                for b in bots:
                    if b["ip"] == ip:
                        b["events"] = b.get("events", 0) + 1
        else:
            if ip not in [h["ip"] for h in humans]:
                humans.append({"ip": ip, "ua": ua, "events": 1})
            else:
                for h in humans:
                    if h["ip"] == ip:
                        h["events"] = h.get("events", 0) + 1

    # Calculate session durations
    for ip, data in clicks.items():
        try:
            first = datetime.fromisoformat(data["first_seen"].replace("Z", "+00:00"))
            last = datetime.fromisoformat(data["last_seen"].replace("Z", "+00:00"))
            duration = abs((last - first).total_seconds())
            sessions[ip] = {
                "duration": duration,
                "pages": len(data["pages"]),
                "unique_pages": len(set(data["pages"])),
                "events": len(data["events"]),
                "ua": data["ua"][:60]
            }
        except:
            sessions[ip] = {"duration": 0, "pages": len(data.get("pages", [])), "unique_pages": len(set(data.get("pages", []))), "events": len(data.get("events", [])), "ua": data.get("ua", "")[:60]}

    # Click tracking by page
    page_clicks = {}
    for page in page_views:
        page_clicks[page] = page_clicks.get(page, 0) + 1

    top_pages = sorted(page_clicks.items(), key=lambda x: -x[1])[:15]

    # Format recent logs for display
    recent_formatted = []
    for entry in all_logs[-30:][::-1]:
        event = entry.get("event", "")
        data = entry.get("data", {})
        page = data.get("page", "") if isinstance(data, dict) else ""
        action = data.get("action", "") if isinstance(data, dict) else ""
        display = page or action or event
        recent_formatted.append({
            "ip": entry.get("ip", "?"),
            "timestamp": entry.get("timestamp", ""),
            "event": event,
            "detail": display,
            "ua": entry.get("user_agent", "")[:50]
        })

    return jsonify({
        "stats": stats if isinstance(stats, dict) else {},
        "chat_messages": chat.get("messages", [])[-30:][::-1] if isinstance(chat, dict) else [],
        "login_attempts": logins.get("attempts", [])[-30:][::-1] if isinstance(logins, dict) else [],
        "click_tracking": {
            "top_pages": [{"page": p, "count": c} for p, c in top_pages],
            "unique_visitors": len(clicks),
            "total_page_views": len(page_views),
        },
        "sessions": [
            {"ip": ip, **data}
            for ip, data in sorted(sessions.items(), key=lambda x: -x[1]["duration"])[:20]
        ],
        "bot_detection": {
            "bots": len(bots),
            "humans": len(humans),
            "bot_list": bots[:15],
            "human_list": humans[:15],
        },
        "recent_logs": recent_formatted,
    })


HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>23 // Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap');
  :root {
    --bg: #0c0c0c;
    --card: #141414;
    --border: #333;
    --text: #e8e8e8;
    --dim: #999;
    --red: #ff1a1a;
    --bright: #ff3333;
    --glow: #ff4444;
    --dark: #1c1c1c;
    --amber: #ffaa33;
    --green: #55cc55;
    --cyan: #66cccc;
    --white: #ffffff;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 24px;
    position: relative;
  }
  /* Scanlines — subtle */
  body::before {
    content:'';
    position:fixed; top:0;left:0;right:0;bottom:0;
    background: repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(255,26,26,0.015) 3px,rgba(255,26,26,0.015) 4px);
    pointer-events:none; z-index:9999;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
  @keyframes glitch {
    0%,92%,100%{transform:translate(0)} 93%{transform:translate(-2px,1px)} 95%{transform:translate(1px,-1px)} 97%{transform:translate(0)}
  }

  /* Header */
  .header {
    display:flex; align-items:center; gap:16px;
    margin-bottom:28px; padding-bottom:16px; border-bottom:1px solid var(--border);
  }
  .header .logo {
    font-family:'VT323',monospace; font-size:48px; color:var(--red);
    text-shadow: 0 0 20px rgba(255,26,26,0.6); animation: glitch 12s infinite;
    line-height:1;
  }
  .header h1 { font-size:16px; color:var(--white); letter-spacing:3px; text-transform:uppercase; }
  .header .live {
    background:var(--red); color:#fff; font-size:9px; font-weight:700;
    padding:3px 10px; border-radius:2px; animation:pulse 2s infinite; letter-spacing:2px;
  }
  .header .sub { color:var(--dim); font-size:10px; letter-spacing:2px; }
  .header .refresh { color:var(--dim); font-size:10px; margin-left:auto; }

  /* Sections */
  .section {
    margin:36px 0 18px;
    padding-bottom:10px;
    border-bottom:2px solid var(--red);
    display:flex; align-items:baseline; gap:12px;
  }
  .section .num {
    font-family:'VT323',monospace; font-size:36px; color:var(--red);
    text-shadow:0 0 12px rgba(255,26,26,0.4); line-height:1;
  }
  .section .title {
    font-size:13px; color:var(--white); text-transform:uppercase; letter-spacing:3px; font-weight:600;
  }
  .section .tag {
    font-size:9px; color:var(--dim); letter-spacing:2px; margin-left:auto;
  }

  /* Grid */
  .stats-row { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:18px; }
  .stats-row.six { grid-template-columns:repeat(6,1fr); }
  .stat-card {
    background:var(--card); border:1px solid var(--border); border-radius:4px; padding:16px;
  }
  .stat-card .label { color:var(--dim); font-size:10px; text-transform:uppercase; letter-spacing:2px; }
  .stat-card .value { font-family:'VT323',monospace; font-size:36px; color:var(--red); margin-top:6px; line-height:1; }
  .stat-card .value.dim { color:var(--bright); }
  .stat-card .value.muted { color:var(--amber); }
  .stat-card .value.subtle { color:var(--cyan); }
  .stat-card .value.ok { color:var(--green); }
  .stat-card .sub { color:var(--dim); font-size:10px; margin-top:4px; }

  .grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:14px; }
  .card {
    background:var(--card); border:1px solid var(--border); border-radius:4px; padding:16px;
  }
  .card h2 {
    font-size:11px; font-weight:600; margin-bottom:12px;
    color:var(--white); text-transform:uppercase; letter-spacing:2px;
    border-bottom:1px solid var(--border); padding-bottom:8px;
  }

  /* Bars */
  .bar-row { display:flex; align-items:center; margin-bottom:6px; gap:8px; }
  .bar-label { min-width:180px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-size:12px; color:var(--text); }
  .bar-count { min-width:35px; text-align:right; color:var(--red); font-family:'VT323',monospace; font-size:18px; }
  .bar-bg { flex:1; height:14px; background:var(--dark); border-radius:2px; overflow:hidden; }
  .bar-fill { height:100%; border-radius:2px; background: linear-gradient(90deg, var(--red), #aa1111); }
  .bar-fill.sec { background: linear-gradient(90deg, var(--amber), #996622); }
  .bar-fill.tri { background: linear-gradient(90deg, var(--cyan), #448888); }
  .bar-fill.ok { background: linear-gradient(90deg, var(--green), #338833); }

  /* IP rows */
  .ip-row { display:flex; align-items:center; padding:5px 0; border-bottom:1px solid #222; font-size:12px; gap:8px; }
  .ip-row:last-child { border-bottom:none; }
  .ip-flag { font-size:14px; min-width:22px; }
  .ip-addr { color:var(--red); min-width:130px; font-weight:600; }
  .ip-count { color:var(--amber); min-width:35px; text-align:right; font-family:'VT323',monospace; font-size:18px; }
  .ip-geo { color:var(--dim); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:11px; }

  /* Timeline */
  .timeline { display:flex; align-items:flex-end; gap:2px; height:80px; padding-top:8px; }
  .timeline.tall { height:100px; }
  .tbar { flex:1; border-radius:2px 2px 0 0; min-width:6px; transition:height .5s; position:relative; background:var(--red); }
  .tbar:hover { opacity:.8; }
  .tbar .tip { display:none; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); background:#1a1a1a; border:1px solid var(--border); color:var(--white); padding:4px 10px; border-radius:3px; font-size:10px; white-space:nowrap; z-index:10; }
  .tbar:hover .tip { display:block; }
  .tlabels { display:flex; gap:2px; margin-top:4px; }
  .tlabels span { flex:1; text-align:center; font-size:9px; color:var(--dim); min-width:6px; }

  /* Heatmap */
  .heatmap { display:grid; grid-template-columns:repeat(24,1fr); gap:3px; margin-top:6px; }
  .hcell { aspect-ratio:1; border-radius:2px; position:relative; min-height:20px; }
  .hcell .tip { display:none; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); background:#1a1a1a; border:1px solid var(--border); color:var(--white); padding:3px 8px; border-radius:3px; font-size:10px; white-space:nowrap; z-index:10; }
  .hcell:hover .tip { display:block; }
  .hlabels { display:grid; grid-template-columns:repeat(24,1fr); gap:3px; margin-top:3px; }
  .hlabels span { text-align:center; font-size:9px; color:var(--dim); }

  /* Feed */
  .feed { max-height:350px; overflow-y:auto; }
  .fentry { padding:5px 0; border-bottom:1px solid #222; font-size:11px; display:flex; gap:8px; align-items:center; }
  .fentry:last-child { border-bottom:none; }
  .ftime { color:var(--dim); min-width:140px; }
  .fip { color:var(--red); min-width:120px; font-weight:500; }
  .fpath { color:var(--amber); font-weight:600; }
  .faction { font-size:10px; padding:2px 6px; border-radius:2px; font-weight:700; min-width:48px; text-align:center; }
  .faction.ban { background:rgba(255,26,26,0.2); color:var(--red); }
  .faction.unban { background:rgba(85,204,85,0.2); color:var(--green); }
  .faction.found { background:rgba(255,170,51,0.15); color:var(--amber); }
  .fjail { color:var(--dim); font-size:10px; }

  /* Fail2ban jail */
  .jail-card { background:var(--card); border:1px solid var(--border); border-radius:4px; padding:16px; margin-bottom:12px; }
  .jail-header { display:flex; align-items:center; gap:10px; margin-bottom:10px; }
  .jail-name { font-family:'VT323',monospace; font-size:24px; color:var(--white); }
  .jail-badge { font-size:10px; padding:3px 10px; border-radius:3px; font-weight:700; letter-spacing:1px; }
  .jail-badge.active { background:rgba(255,26,26,0.25); color:var(--red); }
  .jail-badge.clean { background:rgba(85,204,85,0.2); color:var(--green); }
  .jail-stats { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }
  .jail-stat .n { font-family:'VT323',monospace; font-size:28px; color:var(--red); }
  .jail-stat .l { font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }
  .banned-list { margin-top:10px; }
  .banned-ip { display:inline-block; background:rgba(255,26,26,0.15); color:var(--red); padding:3px 8px; border-radius:3px; font-size:11px; margin:2px 4px 2px 0; }

  /* Country */
  .crow { display:flex; align-items:center; padding:4px 0; gap:8px; font-size:12px; }
  .cflag { font-size:16px; min-width:24px; }
  .cname { min-width:120px; color:var(--text); }
  .ccount { color:var(--amber); font-family:'VT323',monospace; font-size:18px; min-width:35px; text-align:right; }
  .cbar { flex:1; height:12px; background:var(--dark); border-radius:2px; overflow:hidden; }
  .cfill { height:100%; background:linear-gradient(90deg, var(--red), #aa1111); border-radius:2px; }

  /* Brute force */
  .bf { padding:7px 0; border-bottom:1px solid #222; font-size:12px; }
  .bf:last-child { border-bottom:none; }
  .bf-h { display:flex; align-items:center; gap:8px; }
  .bf-users { color:var(--dim); font-size:10px; margin-top:4px; }
  .bf-users span { background:rgba(255,26,26,0.1); color:var(--red); padding:2px 5px; border-radius:2px; margin-right:3px; }

  /* Category */
  .cat-row { display:flex; align-items:center; gap:8px; padding:5px 0; font-size:12px; }
  .cat-icon { font-size:16px; min-width:24px; text-align:center; }
  .cat-name { min-width:100px; text-transform:capitalize; color:var(--text); }
  .cat-count { font-family:'VT323',monospace; font-size:18px; color:var(--amber); min-width:35px; text-align:right; }
  .cat-bar { flex:1; height:12px; background:var(--dark); border-radius:2px; overflow:hidden; }
  .cat-fill { height:100%; background:linear-gradient(90deg, var(--red), #aa1111); border-radius:2px; }

  .full-width { grid-column: 1 / -1; }

  /* AI Bot Radar */
  .bot-card { background:var(--card); border:1px solid var(--border); border-radius:4px; padding:16px; margin-bottom:12px; }
  .bot-header { display:flex; align-items:center; gap:10px; margin-bottom:10px; }
  .bot-icon { font-size:28px; }
  .bot-name { font-family:'VT323',monospace; font-size:26px; color:var(--red); }
  .bot-company { font-size:11px; color:var(--amber); letter-spacing:1px; font-weight:600; }
  .bot-purpose { font-size:10px; color:var(--white); background:rgba(255,26,26,0.15); padding:3px 8px; border-radius:3px; }
  .bot-meta { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:10px; }
  .bot-meta .n { font-family:'VT323',monospace; font-size:24px; color:var(--red); }
  .bot-meta .l { font-size:9px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }
  .bot-paths { font-size:11px; color:var(--dim); margin-top:8px; }
  .bot-paths span { background:rgba(255,170,51,0.15); color:var(--amber); padding:2px 6px; border-radius:2px; margin-right:4px; }
  .trap-row { display:flex; align-items:center; gap:8px; padding:5px 0; font-size:12px; border-bottom:1px solid #222; }
  .trap-row:last-child { border-bottom:none; }
  .trap-icon { font-size:16px; min-width:20px; text-align:center; }
  .trap-name { flex:1; color:var(--text); }
  .trap-count { font-family:'VT323',monospace; font-size:18px; color:var(--red); min-width:35px; text-align:right; }
  .canary-entry { padding:6px 0; border-bottom:1px solid #222; font-size:11px; }
  .canary-entry:last-child { border-bottom:none; }
  .canary-agent { color:var(--glow); font-weight:700; font-size:12px; }
  .suspect { padding:7px 0; border-bottom:1px solid #222; font-size:12px; }
  .suspect:last-child { border-bottom:none; }
  .suspect-reason { font-size:10px; color:var(--amber); margin-top:3px; }
  .suspect-paths { font-size:10px; color:var(--dim); margin-top:3px; }
  .suspect-paths span { background:rgba(255,26,26,0.1); color:var(--red); padding:2px 5px; border-radius:2px; margin-right:3px; }

  /* Footer */
  .footer {
    margin-top:40px; padding-top:14px; border-top:2px solid var(--red);
    display:flex; justify-content:space-between; font-size:10px; color:var(--dim); letter-spacing:2px;
  }

  @media (max-width:1100px) {
    .stats-row { grid-template-columns:repeat(2,1fr); }
    .stats-row.six { grid-template-columns:repeat(3,1fr); }
    .grid { grid-template-columns:1fr; }
  }
  @media (max-width:600px) {
    body { padding:10px; font-size:11px; }
    .header .logo { font-size:32px; }
    .stat-card .value { font-size:24px; }
  }
</style>
</head>
<body>

<div class="header">
  <span class="logo">23</span>
  <div>
    <h1>Nichts ist wie es scheint</h1>
    <div class="sub">HAGBARD // LEVIATHAN MAINFRAME // SEKTOR 23</div>
  </div>
  <span class="live">LIVE</span>
  <span class="refresh" id="refresh">...</span>
</div>

<!-- FAIL2BAN -->
<div class="section">
  <span class="num">01</span>
  <span class="title">Fail2Ban // Bannhammer</span>
  <span class="tag">INGSOC DEFENCE GRID</span>
</div>

<div class="stats-row six">
  <div class="stat-card"><div class="label">Bans Gesamt</div><div class="value" id="f-total">-</div></div>
  <div class="stat-card"><div class="label">Heute</div><div class="value muted" id="f-today">-</div></div>
  <div class="stat-card"><div class="label">Aktuell Gebannt</div><div class="value" id="f-banned">-</div></div>
  <div class="stat-card"><div class="label">Unique IPs</div><div class="value subtle" id="f-unique">-</div></div>
  <div class="stat-card"><div class="label">Angriffe/Min</div><div class="value dim" id="f-rate">-</div></div>
  <div class="stat-card"><div class="label">Versuche Heute</div><div class="value muted" id="f-attempts">-</div></div>
</div>

<div id="f2b-jails"></div>

<div class="grid">
  <div class="card"><h2>Ban Timeline (14 Tage)</h2><div class="timeline" id="f2b-timeline"></div><div class="tlabels" id="f2b-timeline-labels"></div></div>
  <div class="card"><h2>Angriffe nach Stunde</h2><div class="heatmap" id="f2b-heatmap"></div><div class="hlabels" id="f2b-heatmap-labels"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Top Gebannte IPs</h2><div id="f2b-top-ips"></div></div>
  <div class="card"><h2>Herkunftslaender</h2><div id="f2b-countries"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Wiederholungstaeter</h2><div id="f2b-repeaters"></div></div>
  <div class="card"><h2>Live Feed</h2><div class="feed" id="f2b-feed"></div></div>
</div>

<!-- ANGRIFFSMUSTER -->
<div class="section">
  <span class="num">23</span>
  <span class="title">Angriffsmuster // SSH Analyse (24h)</span>
  <span class="tag">WE ARE LEGION</span>
</div>

<div class="stats-row six">
  <div class="stat-card"><div class="label">Versuche</div><div class="value" id="a-total">-</div></div>
  <div class="stat-card"><div class="label">Angreifer</div><div class="value subtle" id="a-attackers">-</div></div>
  <div class="stat-card"><div class="label">Usernames</div><div class="value dim" id="a-users">-</div></div>
  <div class="stat-card"><div class="label">Invalid User</div><div class="value muted" id="a-invalid">-</div></div>
  <div class="stat-card"><div class="label">Failed PW</div><div class="value" id="a-failed">-</div></div>
  <div class="stat-card"><div class="label">Accepted</div><div class="value ok" id="a-accepted">-</div></div>
</div>

<div class="grid">
  <div class="card"><h2>Top Usernames</h2><div id="a-usernames"></div></div>
  <div class="card"><h2>Username-Kategorien</h2><div id="a-categories"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Brute-Force IPs</h2><div id="a-bruteforce" style="max-height:380px;overflow-y:auto"></div></div>
  <div class="card"><h2>Angriffsarten</h2><div id="a-types"></div><h2 style="margin-top:14px">Auth-Methoden</h2><div id="a-methods"></div></div>
</div>

<div class="grid">
  <div class="card full-width"><h2>Angriffswellen (10-Min Fenster)</h2><div class="timeline tall" id="a-waves"></div><div class="tlabels" id="a-waves-labels"></div></div>
</div>

<!-- AI BOT RADAR -->
<div class="section">
  <span class="num">42</span>
  <span class="title">AI Bot Radar // Maschinenjaeger</span>
  <span class="tag">WER BEOBACHTET DIE BEOBACHTER</span>
</div>

<div class="stats-row">
  <div class="stat-card"><div class="label">AI Bot Zugriffe</div><div class="value" id="ai-total">-</div></div>
  <div class="stat-card"><div class="label">Bot-Typen</div><div class="value subtle" id="ai-types">-</div></div>
  <div class="stat-card"><div class="label">Canary Hits</div><div class="value" id="ai-canary" style="color:var(--glow)">-</div></div>
  <div class="stat-card"><div class="label">Verdaechtige (kein JS)</div><div class="value muted" id="ai-suspects">-</div></div>
</div>

<div id="ai-bots-list"></div>

<div class="grid">
  <div class="card"><h2>Fallen-Ausloeser</h2><div id="ai-traps"></div></div>
  <div class="card"><h2>Canary Treffer</h2><div class="feed" id="ai-canary-feed"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Verdaechtig (kein JS)</h2><div id="ai-suspects-list" style="max-height:300px;overflow-y:auto"></div></div>
  <div class="card"><h2>AI Bot Live Feed</h2><div class="feed" id="ai-feed"></div></div>
</div>

<!-- HONEYPOT -->
<div class="section">
  <span class="num">05</span>
  <span class="title">Honeypot // Koeder</span>
  <span class="tag">EXPECT US</span>
</div>

<div class="stats-row">
  <div class="stat-card"><div class="label">Zugriffe Gesamt</div><div class="value" id="s-total">-</div></div>
  <div class="stat-card"><div class="label">Heute</div><div class="value muted" id="s-today">-</div></div>
  <div class="stat-card"><div class="label">Unique IPs</div><div class="value subtle" id="s-ips">-</div><div class="sub" id="s-ips-sub"></div></div>
  <div class="stat-card"><div class="label">Top Angreifer</div><div class="value dim" id="s-top">-</div><div class="sub" id="s-top-sub"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Top Koeder</h2><div id="paths"></div></div>
  <div class="card"><h2>Top Angreifer</h2><div id="ips"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Timeline (14 Tage)</h2><div class="timeline" id="timeline"></div><div class="tlabels" id="timeline-labels"></div></div>
  <div class="card"><h2>Stunden-Heatmap</h2><div class="heatmap" id="heatmap"></div><div class="hlabels" id="heatmap-labels"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>User Agents</h2><div id="useragents"></div></div>
  <div class="card"><h2>Live Feed</h2><div class="feed" id="feed"></div></div>
</div>

<!-- OPENCLAW HONEYPOT -->
<div class="section">
  <span class="num">17</span>
  <span class="title">OpenClaw // Pyramiden-Falle</span>
  <span class="tag">FUCKUP COMPUTER AKTIV</span>
</div>

<div class="stats-row six">
  <div class="stat-card"><div class="label">Login Versuche</div><div class="value" id="oc-logins">-</div></div>
  <div class="stat-card"><div class="label">Chat Nachrichten</div><div class="value muted" id="oc-chats">-</div></div>
  <div class="stat-card"><div class="label">Page Views</div><div class="value subtle" id="oc-views">-</div></div>
  <div class="stat-card"><div class="label">Unique IPs</div><div class="value dim" id="oc-ips">-</div></div>
  <div class="stat-card"><div class="label">Bots</div><div class="value" id="oc-bots">-</div></div>
  <div class="stat-card"><div class="label">Menschen</div><div class="value ok" id="oc-humans">-</div></div>
</div>

<div class="grid">
  <div class="card"><h2>Login Versuche // Passwort-Raeuber</h2><div class="feed" id="oc-login-feed" style="max-height:300px"></div></div>
  <div class="card"><h2>Chat mit FUCKUP</h2><div class="feed" id="oc-chat-feed" style="max-height:300px"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Click-Tracking // Wer klickt wo</h2><div id="oc-clicks"></div></div>
  <div class="card"><h2>Sessions // Verweildauer</h2><div id="oc-sessions" style="max-height:300px;overflow-y:auto"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Bot-Erkennung</h2><div id="oc-bot-list" style="max-height:300px;overflow-y:auto"></div></div>
  <div class="card"><h2>Live Feed</h2><div class="feed" id="oc-live-feed"></div></div>
</div>

<div class="footer">
  <span>FNORD // 2+2=5 // ILLUMINATUS!</span>
  <span>ALLES IST MIT ALLEM VERBUNDEN</span>
  <span id="clock">23:23:23</span>
</div>

<script>
function flag(cc) {
  if (!cc || cc === '??' || cc.length !== 2) return '\u{1F310}';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function bars(el, items, key, cls) {
  const mx = items.length ? Math.max(...items.map(i => i.count)) : 1;
  el.innerHTML = items.map(i => `
    <div class="bar-row">
      <span class="bar-count">${i.count}</span>
      <span class="bar-label">${i[key]}</span>
      <div class="bar-bg"><div class="bar-fill ${cls||''}" style="width:${(i.count/mx*100).toFixed(0)}%"></div></div>
    </div>
  `).join('');
}

function heat(cId, lId, hours, r, g, b) {
  const mx = Math.max(1, ...Object.values(hours));
  let h='', l='';
  for (let i=0;i<24;i++) {
    const hh = String(i).padStart(2,'0');
    const c = hours[hh]||0;
    const n = c/mx;
    h += `<div class="hcell" style="background:${c>0?`rgb(${~~(r*n)},${~~(g*n)},${~~(b*n)})`:'#120505'}"><span class="tip">${hh}:00 - ${c}</span></div>`;
    l += `<span>${hh}</span>`;
  }
  document.getElementById(cId).innerHTML = h;
  document.getElementById(lId).innerHTML = l;
}

function tline(cId, lId, data, bg) {
  const mx = data.length ? Math.max(1,...data.map(t=>t.count)) : 1;
  document.getElementById(cId).innerHTML = data.map(t => `
    <div class="tbar" style="height:${Math.max(4,t.count/mx*100)}%;background:${bg}">
      <span class="tip">${t.date}: ${t.count}</span>
    </div>
  `).join('');
  document.getElementById(lId).innerHTML = data.map(t=>`<span>${t.date.slice(5)}</span>`).join('');
}

async function refreshAI() {
  const d = await (await fetch('/api/ai-bots')).json();
  document.getElementById('ai-total').textContent = d.total_ai_hits||0;
  document.getElementById('ai-types').textContent = d.unique_bots||0;
  document.getElementById('ai-canary').textContent = d.canary_hits||0;
  document.getElementById('ai-suspects').textContent = d.behavioral_suspects_count||0;

  // Bot cards
  document.getElementById('ai-bots-list').innerHTML = (d.bots||[]).map(b=>`
    <div class="bot-card">
      <div class="bot-header">
        <span class="bot-icon">${b.icon}</span>
        <span class="bot-name">${b.name}</span>
        <span class="bot-company">${b.company}</span>
        <span class="bot-purpose">${b.purpose}</span>
      </div>
      <div class="bot-meta">
        <div><div class="n">${b.count}</div><div class="l">Zugriffe</div></div>
        <div><div class="n">${b.unique_ips}</div><div class="l">IPs</div></div>
        <div><div class="n" style="font-size:12px;color:var(--dim)">${b.last_seen?b.last_seen.replace('T',' ').slice(0,16):'-'}</div><div class="l">Zuletzt</div></div>
      </div>
      ${b.ips.length?'<div style="font-size:10px;color:var(--dim)">'+b.ips.map(ip=>'<span class="ip-addr" style="font-size:10px">'+ip.ip+'</span> <span style="color:var(--dim)">'+flag(ip.countryCode||'??')+' '+(ip.isp||'')+'</span>').join(' | ')+'</div>':''}
      ${b.top_paths.length?'<div class="bot-paths">Pfade: '+b.top_paths.map(p=>'<span>'+p.path+' ('+p.count+'x)</span>').join('')+'</div>':''}
    </div>
  `).join('')||'<div class="bot-card" style="text-align:center;color:var(--dim);padding:30px">Noch keine AI Bots erkannt. Die Fallen sind ausgelegt...</div>';

  // Trap hits
  const traps = d.traps||[];
  document.getElementById('ai-traps').innerHTML = traps.length ? traps.map(t=>`
    <div class="trap-row">
      <span class="trap-icon">\u{1F3AF}</span>
      <span class="trap-name">${t.trap}</span>
      <span class="trap-count">${t.count}</span>
    </div>
  `).join('') : '<div style="color:var(--dim);padding:10px">Keine Fallen ausgeloest</div>';

  // Canary hits
  const canaries = d.canary_details||[];
  document.getElementById('ai-canary-feed').innerHTML = canaries.length ? canaries.map(c=>`
    <div class="canary-entry">
      <span class="ftime">${c.time?c.time.replace('T',' ').slice(0,19):''}</span>
      <span class="fip">${c.ip}</span>
      ${c.agent_param?'<span class="canary-agent">agent='+c.agent_param+'</span>':''}
      <div style="color:var(--dim);font-size:9px;margin-top:2px">${c.ua?c.ua.slice(0,80):''}</div>
    </div>
  `).join('') : '<div style="color:var(--dim);padding:10px">Kein AI Agent hat den Canary besucht... noch nicht.</div>';

  // Behavioral suspects
  const suspects = d.behavioral_suspects||[];
  document.getElementById('ai-suspects-list').innerHTML = suspects.length ? suspects.map(s=>`
    <div class="suspect">
      <div class="bf-h">
        <span class="ip-addr">${s.ip}</span>
        <span class="ip-count">${s.requests}x</span>
      </div>
      <div class="suspect-reason">\u26A0 ${s.reason}</div>
      <div class="suspect-paths">Pfade: ${s.paths.map(p=>'<span>'+p+'</span>').join('')}</div>
      <div style="color:var(--dim);font-size:9px;margin-top:2px">${s.ua}</div>
    </div>
  `).join('') : '<div style="color:var(--dim);padding:10px">Alle Besucher haben JS ausgefuehrt</div>';

  // AI bot feed
  const recent = d.recent_ai||[];
  document.getElementById('ai-feed').innerHTML = recent.length ? recent.map(e=>`
    <div class="fentry"><span class="ftime">${e.time?e.time.replace('T',' ').slice(0,19):''}</span><span class="fip">${e.ip}</span><span class="fpath">${e.path}</span></div>
  `).join('') : '<div style="color:var(--dim);padding:10px">Keine AI Bot Aktivitaet</div>';
}

async function refreshHP() {
  const d = await (await fetch('/api/stats')).json();
  document.getElementById('s-total').textContent = d.total;
  document.getElementById('s-today').textContent = d.today;
  document.getElementById('s-ips').textContent = d.unique_ips;
  document.getElementById('s-ips-sub').textContent = 'Heute: '+(d.unique_ips_today||0);
  if (d.ips && d.ips.length) {
    document.getElementById('s-top').textContent = d.ips[0].ip;
    document.getElementById('s-top-sub').textContent = d.ips[0].count+'x - '+d.ips[0].country;
  }
  bars(document.getElementById('paths'), d.paths||[], 'path', '');
  document.getElementById('ips').innerHTML = (d.ips||[]).map(i=>`
    <div class="ip-row"><span class="ip-count">${i.count}</span><span class="ip-flag">${flag(i.cc)}</span><span class="ip-addr">${i.ip}</span><span class="ip-geo">${i.city?i.city+', ':''}${i.country} - ${i.isp}</span></div>
  `).join('');
  tline('timeline','timeline-labels', d.timeline||[], 'var(--red)');
  heat('heatmap','heatmap-labels', d.hours||{}, 255,50,50);
  bars(document.getElementById('useragents'), d.ua||[], 'ua', 'sec');
  document.getElementById('feed').innerHTML = (d.recent||[]).map(e=>`
    <div class="fentry"><span class="ftime">${e.time?e.time.replace('T',' ').slice(0,19):''}</span><span class="fip">${e.ip}</span><span class="fpath">${e.path}</span></div>
  `).join('');
}

async function refreshF2B() {
  const d = await (await fetch('/api/f2b')).json();
  const live=d.live||{}, db=d.db||{};
  document.getElementById('f-total').textContent = db.total_bans||0;
  document.getElementById('f-today').textContent = d.today_bans||0;
  document.getElementById('f-unique').textContent = db.unique_ips||0;
  document.getElementById('f-rate').textContent = d.attacks_per_min||0;
  document.getElementById('f-attempts').textContent = d.today_attempts||0;
  let tb=0; (live.jails||[]).forEach(j=>tb+=j.banned);
  document.getElementById('f-banned').textContent = tb;

  document.getElementById('f2b-jails').innerHTML = (live.jails||[]).map(j=>`
    <div class="jail-card">
      <div class="jail-header">
        <span class="jail-name">${j.name}</span>
        <span class="jail-badge ${j.banned>0?'active':'clean'}">${j.banned>0?j.banned+' GEBANNT':'CLEAN'}</span>
      </div>
      <div class="jail-stats">
        <div class="jail-stat"><div class="n" style="color:var(--bright)">${j.banned}</div><div class="l">Aktuell</div></div>
        <div class="jail-stat"><div class="n" style="color:var(--red)">${j.total_banned}</div><div class="l">Gesamt</div></div>
        <div class="jail-stat"><div class="n" style="color:var(--amber)">${j.failed}</div><div class="l">Fehlversuche</div></div>
        <div class="jail-stat"><div class="n" style="color:var(--dim)">${j.total_failed}</div><div class="l">Total</div></div>
      </div>
      ${j.banned_ips.length?'<div class="banned-list">'+j.banned_ips.map(ip=>'<span class="banned-ip">'+ip+'</span>').join('')+'</div>':''}
    </div>
  `).join('');

  tline('f2b-timeline','f2b-timeline-labels', db.bans_timeline||[], 'var(--red)');
  heat('f2b-heatmap','f2b-heatmap-labels', db.bans_by_hour||{}, 255,50,50);

  document.getElementById('f2b-top-ips').innerHTML = (db.top_banned||[]).map(i=>`
    <div class="ip-row"><span class="ip-count">${i.count}x</span><span class="ip-flag">${flag(i.cc)}</span><span class="ip-addr">${i.ip}</span><span class="ip-geo">${i.city?i.city+', ':''}${i.country} - ${i.isp}</span></div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  const cs=db.top_countries||[], cMx=cs.length?Math.max(...cs.map(c=>c.count)):1;
  document.getElementById('f2b-countries').innerHTML = cs.map(c=>`
    <div class="crow"><span class="ccount">${c.count}</span><span class="cflag">${flag(c.cc)}</span><span class="cname">${c.country}</span><div class="cbar"><div class="cfill" style="width:${(c.count/cMx*100).toFixed(0)}%"></div></div></div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  document.getElementById('f2b-repeaters').innerHTML = (db.repeat_offenders||[]).map(r=>`
    <div class="ip-row"><span class="ip-count">${r.count}x</span><span class="ip-flag">${flag(r.cc)}</span><span class="ip-addr">${r.ip}</span><span class="ip-geo">${r.country} - ${r.isp} - ${r.last_ban}</span></div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  document.getElementById('f2b-feed').innerHTML = (d.recent_events||[]).slice(0,50).map(e=>{
    let c=e.action==='Ban'||e.action==='Restore Ban'?'ban':e.action==='Unban'?'unban':'found';
    return `<div class="fentry"><span class="ftime">${e.time}</span><span class="faction ${c}">${e.action}</span><span class="fip">${e.ip}</span><span class="fjail">${e.jail}</span></div>`;
  }).join('')||'<div style="color:var(--dim)">-</div>';
}

async function refreshPatterns() {
  const p = await (await fetch('/api/patterns')).json();
  document.getElementById('a-total').textContent = p.total_attempts||0;
  document.getElementById('a-attackers').textContent = p.unique_attackers||0;
  document.getElementById('a-users').textContent = p.unique_usernames||0;
  document.getElementById('a-invalid').textContent = p.total_invalid||0;
  document.getElementById('a-failed').textContent = p.total_failed_pw||0;
  document.getElementById('a-accepted').textContent = p.total_accepted||0;

  bars(document.getElementById('a-usernames'), p.top_usernames||[], 'user', '');

  const cats=p.username_categories||[], catMx=cats.length?Math.max(...cats.map(c=>c.count)):1;
  const ic={system:'\u{1F464}',database:'\u{1F5C4}',devops:'\u2699',crypto:'\u26D3',services:'\u{1F50C}',custom:'\u2753'};
  document.getElementById('a-categories').innerHTML = cats.map(c=>`
    <div class="cat-row"><span class="cat-count">${c.count}</span><span class="cat-icon">${ic[c.category]||'\u2753'}</span><span class="cat-name">${c.category}</span><div class="cat-bar"><div class="cat-fill" style="width:${(c.count/catMx*100).toFixed(0)}%"></div></div></div>
  `).join('');

  const types=p.attack_types||[], tMx=types.length?Math.max(1,...types.map(t=>t.count)):1;
  document.getElementById('a-types').innerHTML = types.map(t=>`
    <div class="bar-row"><span class="bar-count">${t.count}</span><span class="bar-label">${t.type}</span><div class="bar-bg"><div class="bar-fill ${t.color==='green'?'ok':t.color==='amber'?'sec':''}" style="width:${(t.count/tMx*100).toFixed(0)}%"></div></div></div>
  `).join('');

  bars(document.getElementById('a-methods'), p.auth_methods||[], 'method', 'tri');

  document.getElementById('a-bruteforce').innerHTML = (p.brute_force_ips||[]).map(b=>`
    <div class="bf">
      <div class="bf-h"><span class="ip-flag">${flag(b.cc)}</span><span class="ip-addr">${b.ip}</span><span class="ip-count">${b.count}x</span><span style="color:var(--red);font-size:10px">${b.velocity} /min</span><span class="ip-geo">${b.country} - ${b.isp}</span></div>
      <div class="bf-users">${b.unique_users} Users: ${b.sample_users.map(u=>'<span>'+u+'</span>').join('')}${b.unique_users>5?' ...':''}</div>
    </div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  const w=p.attack_waves||[];
  if(w.length) {
    const wMx=Math.max(1,...w.map(x=>x.count));
    document.getElementById('a-waves').innerHTML = w.map(x=>`
      <div class="tbar" style="height:${Math.max(4,x.count/wMx*100)}%"><span class="tip">${x.time.replace('T',' ')}: ${x.count}</span></div>
    `).join('');
    document.getElementById('a-waves-labels').innerHTML = w.map((x,i)=>`<span>${i%6===0?x.time.slice(11,16):''}</span>`).join('');
  }
}

// Clock
setInterval(()=>{
  const n=new Date(), s=n.getSeconds();
  const el=document.getElementById('clock');
  if(s===23){el.textContent='23:23:23';el.style.color='var(--bright)';}
  else{el.textContent=String(n.getHours()).padStart(2,'0')+':'+String(n.getMinutes()).padStart(2,'0')+':'+String(s).padStart(2,'0');el.style.color='';}
},1000);

async function refreshOpenClaw() {
  try {
    const d = await (await fetch('/api/openclaw')).json();
    const stats = d.stats || {};
    const logins = d.login_attempts || [];
    const chats = d.chat_messages || [];
    const clicks = d.click_tracking || {};
    const sessions = d.sessions || [];
    const botData = d.bot_detection || {};
    const logs = d.recent_logs || [];

    // Stats
    document.getElementById('oc-logins').textContent = logins.length || stats.login_attempts || 0;
    document.getElementById('oc-chats').textContent = chats.length || stats.chat_messages || 0;
    document.getElementById('oc-views').textContent = stats.page_views || logs.length || 0;
    document.getElementById('oc-ips').textContent = clicks.unique_visitors || 0;
    document.getElementById('oc-bots').textContent = botData.bots || 0;
    document.getElementById('oc-humans').textContent = botData.humans || 0;

    // Login attempts
    document.getElementById('oc-login-feed').innerHTML = logins.length ? logins.map(l => `
      <div class="fentry" style="flex-wrap:wrap">
        <span class="ftime">${l.timestamp ? l.timestamp.replace('T',' ').slice(0,19) : ''}</span>
        <span class="fip">${l.ip || '?'}</span>
        <span style="color:var(--amber);font-weight:600">${l.username || '?'}</span>
        <span style="color:var(--red)">:${l.password || '***'}</span>
        ${l.success === true ? '<span class="faction ok">LOGIN</span>' : '<span class="faction ban">FAIL</span>'}
      </div>
    `).join('') : '<div style="color:var(--dim);padding:10px">Noch keine Login-Versuche...</div>';

    // Chat messages
    document.getElementById('oc-chat-feed').innerHTML = chats.length ? chats.map(c => `
      <div class="fentry" style="flex-wrap:wrap">
        <span class="ftime">${c.timestamp ? c.timestamp.replace('T',' ').slice(0,19) : ''}</span>
        <span class="fip">${c.ip || '?'}</span>
        <div style="width:100%;margin-top:4px">
          <span style="color:var(--cyan)">User:</span> <span style="color:var(--text)">${(c.message || '').slice(0,80)}</span>
        </div>
        <div style="width:100%;margin-top:2px">
          <span style="color:var(--amber)">FUCKUP:</span> <span style="color:var(--dim);font-style:italic">${(c.response || '').slice(0,100)}</span>
        </div>
      </div>
    `).join('') : '<div style="color:var(--dim);padding:10px">FUCKUP wartet auf Anfragen...</div>';

    // Click tracking
    const topPages = clicks.top_pages || [];
    const pageMx = topPages.length ? Math.max(...topPages.map(p => p.count)) : 1;
    document.getElementById('oc-clicks').innerHTML = topPages.length ? topPages.map(p => `
      <div class="bar-row">
        <span class="bar-count">${p.count}</span>
        <span class="bar-label">/dashboard/${p.page}</span>
        <div class="bar-bg"><div class="bar-fill tri" style="width:${(p.count/pageMx*100).toFixed(0)}%"></div></div>
      </div>
    `).join('') : '<div style="color:var(--dim)">Keine Seiten aufgerufen</div>';

    // Sessions
    document.getElementById('oc-sessions').innerHTML = sessions.length ? sessions.map(s => `
      <div class="ip-row">
        <span class="ip-addr">${s.ip}</span>
        <span class="ip-count">${Math.round(s.duration)}s</span>
        <span style="color:var(--amber)">${s.pages || 0} Seiten</span>
        <span style="color:var(--cyan)">${s.events || 0} Events</span>
        <span class="ip-geo">${s.ua || ''}</span>
      </div>
    `).join('') : '<div style="color:var(--dim)">Keine Sessions</div>';

    // Bot detection
    const botList = botData.bot_list || [];
    const humanList = botData.human_list || [];
    document.getElementById('oc-bot-list').innerHTML = `
      <h3 style="color:var(--red);font-size:11px;margin-bottom:8px">BOTS (${botList.length})</h3>
      ${botList.length ? botList.map(b => `
        <div class="suspect">
          <div class="bf-h"><span class="ip-addr">${b.ip}</span><span class="ip-count">${b.events || 0}x</span></div>
          <div style="color:var(--dim);font-size:9px;margin-top:2px">${(b.ua || '').slice(0,60)}</div>
        </div>
      `).join('') : '<div style="color:var(--dim);font-size:10px;margin-bottom:12px">Keine Bots erkannt</div>'}
      <h3 style="color:var(--green);font-size:11px;margin:12px 0 8px">MENSCHEN (${humanList.length})</h3>
      ${humanList.length ? humanList.slice(0,5).map(h => `
        <div class="ip-row">
          <span class="ip-addr" style="color:var(--green)">${h.ip}</span>
          <span class="ip-count">${h.events || 0}x</span>
          <span class="ip-geo">${(h.ua || '').slice(0,40)}</span>
        </div>
      `).join('') : '<div style="color:var(--dim);font-size:10px">Keine Menschen erkannt</div>'}
    `;

    // Live feed
    document.getElementById('oc-live-feed').innerHTML = logs.length ? logs.map(l => `
      <div class="fentry">
        <span class="ftime">${l.timestamp ? l.timestamp.replace('T',' ').slice(0,19) : ''}</span>
        <span class="fip">${l.ip || '?'}</span>
        <span class="faction ${l.event === 'login_attempt' ? 'ban' : l.event === 'login_success' ? 'ok' : 'found'}">${l.event || '?'}</span>
        <span class="fpath">${l.detail || ''}</span>
      </div>
    `).join('') : '<div style="color:var(--dim);padding:10px">Warte auf Aktivitaet...</div>';

  } catch(e) {
    console.error('OpenClaw refresh error:', e);
  }
}

async function refresh() {
  try {
    await Promise.all([refreshHP(), refreshF2B(), refreshPatterns(), refreshAI(), refreshOpenClaw()]);
    document.getElementById('refresh').textContent = new Date().toLocaleTimeString('de-DE') + ' // SYNCED';
  } catch(e) { console.error(e); }
}
refresh();
setInterval(refresh, 30000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
