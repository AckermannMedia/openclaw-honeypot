```
  ██████╗ ██████╗
  ╚═══██╗╚════██╗
   ████╔╝  █████╔╝
  ██╔═══╝  ╚═══██╗
  ███████╗██████╔╝
  ╚══════╝╚═════╝
  FNORD-PROXY + OPENCLAW
```

# FNORD-PROXY — Honeypot Reverse Proxy + Fake Admin Panel with Real-Time Dashboard

A drop-in **nginx honeypot reverse proxy** that sits in front of your web services, catches attackers probing for common vulnerabilities, auto-bans them via fail2ban, and gives you a **live analytics dashboard** to monitor everything in real time. Now combined with **OpenClaw** — a fake admin panel honeypot that captures login attempts, chat messages, and attacker behavior.

Themed after the movie **"23 - Nichts ist wie es scheint"** (Karl Koch / Chaos Computer Club), **Anonymous**, and George Orwell's **1984** — styled in **RAL 3000 Feuerrot** with CRT scanlines, glitch effects, and retro terminal aesthetics.

---

## Why This Exists

Every server connected to the internet is under constant, automated attack. Within minutes of going online, bots start probing for `.env` files, WordPress logins, exposed Git repositories, phpMyAdmin instances, and dozens of other common misconfigurations. This isn't targeted — it's industrial-scale scanning by botnets that don't care what your server actually runs. They just spray requests at every IP and see what sticks.

The numbers are staggering. A single VPS with nothing but SSH and nginx will see **hundreds to thousands of brute force attempts per day**. Credential stuffing bots cycle through leaked username/password lists. Vulnerability scanners probe for every CVE published in the last decade. Most of this traffic comes from compromised machines in massive botnets — your server is just one of millions being hit simultaneously.

**The traditional response is passive:** fail2ban watches logs, bans IPs after failed attempts, and that's it. You know you're being attacked, but you don't see the patterns. You don't know which traps are being triggered, which countries the attacks come from, whether it's a coordinated wave or background noise, or what usernames the bots are currently trying.

**FNORD-PROXY takes an active approach:**

1. **Turn their scanning against them.** Instead of just blocking probes, serve fake but realistic responses. An attacker hitting `/.env` gets back what looks like real AWS credentials. This wastes their time — they'll try to use the fake keys, maybe probe deeper, and every additional request gets logged and accelerates their ban.

2. **Lure them into a fake admin panel.** OpenClaw presents an authentic-looking admin interface with login forms, a chatbot, and interactive elements. Every click, every login attempt, every chat message is captured and analyzed.

3. **See everything in real time.** The dashboard doesn't just count attacks — it categorizes them across 5 sections. You can see that the current bot wave is trying crypto-related usernames, that attacks peak at 3 AM UTC, which AI crawlers are ignoring your robots.txt, and who fell for the fake admin panel.

4. **Protect real services transparently.** The honeypot sits as an nginx layer in front of your actual application. Legitimate API calls, web requests, and client connections pass through untouched. Attackers get trapped before they ever reach your service.

---

## Features

### Honeypot Reverse Proxy (nginx)
- **30+ trap locations** that mimic real vulnerabilities — `.env` files, WordPress login, admin panels, phpMyAdmin, `.git/config`, `backup.sql`, GraphQL endpoints, debug pages, and more
- **Realistic fake responses** that keep scanners engaged (fake database credentials, fake WordPress forms, fake API responses)
- **Transparent proxy** — legitimate traffic passes through untouched to your real backend service
- **Works with any service** — Vaultwarden, Nextcloud, Gitea, any web application behind nginx

### OpenClaw Fake Admin Panel (Docker)
- **Authentic admin UI clone** with Illuminatus! theme
- **Login capture** — tracks every login attempt (success/fail), `admin:admin` intentionally works
- **FUCKUP chatbot** — 20 cryptic Illuminatus! responses, logs every user message
- **Click tracking** — monitors navigation, field focus, button clicks
- **Session monitoring** — tracks visitor sessions with bot vs. human detection
- **REST API** for programmatic access to all captured data

### Automatic Banning
- **fail2ban integration** with custom filter and jail
- Auto-bans IPs after 3 honeypot hits (configurable)
- 24-hour ban duration (configurable)
- Blocks on all HTTP/HTTPS ports via iptables

### AI Bot Radar
- **20+ known AI crawler signatures** — GPTBot, ClaudeBot, PerplexityBot, Bytespider, Googlebot, and more
- **AI-specific trap paths** — `/llm.txt`, `/.well-known/ai-plugin.json`, `/fnord/23/confirm`, `/internal/api-keys`, `/backups/latest.sql.gz`
- **Canary endpoint** — `/fnord/23/confirm` tracks which AI agents confirm they read the page
- **JS beacon detection** — IPs that load pages but never fire the JavaScript beacon are flagged as behavioral bot suspects

### Live Analytics Dashboard
Five sections with real-time data, auto-refreshing every 30 seconds:

| Section | # | Tag | What it shows |
|---------|---|-----|---------------|
| **Fail2Ban** | 01 | INGSOC DEFENCE GRID | Total bans, currently banned, bans/day timeline, hourly heatmap, top banned IPs with GeoIP, country breakdown, repeat offenders, live ban/unban feed |
| **Attack Patterns** | 23 | WE ARE LEGION | SSH brute force analysis (24h window), top attempted usernames, username categorization (system/database/devops/crypto/services), per-IP attack velocity, attack wave visualization |
| **AI Bot Radar** | 42 | WER BEOBACHTET DIE BEOBACHTER | AI bot detection by user agent, trap path hits, canary confirmations, JS-beacon behavioral suspects, company breakdown |
| **Honeypot** | 05 | EXPECT US | Total honeypot hits, top triggered paths, top attacker IPs with GeoIP, user agent analysis, 14-day timeline, hourly heatmap, live access feed |
| **OpenClaw** | 17 | FUCKUP COMPUTER AKTIV | Login attempts (success/fail), chat messages, click tracking, session analysis, bot vs. human detection |

### Dashboard Features
- **GeoIP lookup** for all IPs (country, city, ISP) via ip-api.com with caching
- **SSH journal analysis** — parses `journalctl -u ssh` for brute force detection
- **Brute force velocity** — calculates attempts/minute per attacker IP
- **Username categorization** — groups attempted usernames into system, database, devops, crypto, services, custom
- **Attack wave detection** — buckets attempts into 10-minute windows to visualize coordinated attacks

### 23 Theme
- **RAL 3000 Feuerrot** (#AF2B1E) color scheme throughout
- **VT323 + Share Tech Mono** retro terminal fonts
- **CRT scanline overlay** with subtle flicker animation
- **Glitch effects** on the "23" logo
- **Clock** that shows 23:23:23 every 23rd second
- Footer: *FNORD // 2+2=5 // ILLUMINATUS!*

---

## Quick Start

```bash
git clone https://github.com/AckermannMedia/openclaw-honeypot.git
cd openclaw-honeypot
sudo ./install.sh -d example.com -b http://127.0.0.1:8080
```

The installer will:
1. Check and install dependencies (Python 3, Flask, Docker)
2. Deploy the dashboard to `/opt/fnord-proxy/`
3. Generate the nginx site config with all honeypot locations
4. Install the fail2ban filter and jail
5. Deploy the OpenClaw Docker container
6. Create and enable a systemd service
7. Start the dashboard

---

## Installation Options

```
Usage: sudo ./install.sh [OPTIONS]

Options:
  -d, --domain DOMAIN      Domain name (required)
  -b, --backend URL        Backend service URL to proxy to
  -h, --bind-host HOST     Dashboard bind address (default: 127.0.0.1)
  -p, --bind-port PORT     Dashboard port (default: 8888)
  --skip-nginx             Skip nginx configuration
  --skip-fail2ban          Skip fail2ban configuration
  --skip-landing           Skip landing page installation
  --skip-openclaw          Skip OpenClaw Docker container deployment
  --help                   Show help
```

### Examples

**Full install — honeypot proxy + OpenClaw + dashboard:**
```bash
sudo ./install.sh -d vault.example.com -b http://127.0.0.1:8080
```

**Without OpenClaw (proxy + dashboard only):**
```bash
sudo ./install.sh -d vault.example.com -b http://127.0.0.1:8080 --skip-openclaw
```

**Standalone honeypot with landing page (no backend):**
```bash
sudo ./install.sh -d honeypot.example.com
```

**Dashboard accessible via Tailscale:**
```bash
sudo ./install.sh -d example.com -b http://127.0.0.1:8080 \
  --bind-host 100.x.y.z --bind-port 8888
```

---

## Architecture

```
                         Internet
                            │
                            ▼
                    ┌───────────────┐
                    │  nginx (443)  │
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────────┐
        │ Honeypot │ │ AI Traps │ │  proxy_pass   │
        │  /.env   │ │ /llm.txt │ │  location /   │
        │  /wp-*   │ │ /fnord/* │ │               │
        └────┬─────┘ └────┬─────┘ └──────┬───────┘
             │             │              │
             ▼             ▼              ▼
      ┌─────────────────────┐    ┌──────────────┐
      │  honeypot.log       │    │ Your Backend │
      │  (nginx log file)   │    │  Service     │
      └──────────┬──────────┘    └──────────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
  ┌───────────┐    ┌──────────────────────────────┐
  │ fail2ban  │    │  Dashboard (systemd :8888)   │
  │ (auto-ban │    │  dashboard.py                │
  │  after 3  │    │                              │
  │  hits)    │    │  Reads:                      │
  └───────────┘    │  ├─ honeypot.log             │
                   │  ├─ fail2ban DB + log         │
                   │  ├─ journalctl (SSH)          │
                   │  └─ OpenClaw API ─────┐       │
                   └──────────────────────┬┘       │
                                          │        │
                                          ▼        │
                                ┌─────────────────┐│
                                │ OpenClaw        ││
                                │ (Docker :18789) ││
                                │                 ││
                                │ Fake admin panel││
                                │ Login capture   ││
                                │ FUCKUP chatbot  ││
                                └─────────────────┘│
```

### How it works

**nginx** uses exact-match locations (`location =`) for honeypot paths, which take priority over the general `location /` prefix match:

- `GET /.env` → hits the honeypot, gets logged, attacker gets a fake `.env` file
- `GET /wp-login.php` → hits the honeypot, gets logged, attacker sees a fake WordPress login
- `GET /api/real-endpoint` → passes through to your backend service normally

**OpenClaw** runs as a Docker container on port 18789. It serves a convincing fake admin panel — attackers who find it can "log in" with `admin:admin`, chat with the FUCKUP bot, and click around. Everything is logged.

**The dashboard** (systemd service on port 8888) aggregates data from all sources: nginx honeypot log, fail2ban database/log, SSH journal, and the OpenClaw API. It presents everything in a single 23-themed interface.

---

## Honeypot Locations

The following paths are trapped by default:

| Category | Paths | Fake Response |
|----------|-------|---------------|
| **Environment files** | `/.env`, `/.env.backup` | Fake credentials, API keys |
| **WordPress** | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`, `/wp-includes/*`, `/wp-content/*` | Fake login form, XML-RPC response |
| **Admin panels** | `/admin`, `/admin/login`, `/administrator` | Fake login form |
| **phpMyAdmin** | `/phpmyadmin`, `/phpmyadmin/index.php` | Fake phpMyAdmin login |
| **Git** | `/.git/config`, `/.git/HEAD`, `/.git/*` | Fake repo config with SSH URL |
| **Config/Backup** | `/config.php`, `/backup.sql` | Fake DB credentials, SQL dump |
| **Debug/Status** | `/debug`, `/server-status` | Fake debug info, Apache status |
| **APIs** | `/api/v1/users`, `/graphql` | Fake user data, GraphQL schema |
| **Scanners** | `/cgi-bin/*`, `/shell`, `/eval`, `/setup`, `/install`, `/console`, `/actuator`, `/solr` | 404 |

All responses contain **realistic but completely fake data** designed to waste attacker time and trigger further probing (which gets them banned faster).

### Adding Custom Honeypot Paths

Edit your nginx site config (`/etc/nginx/sites-available/fnord-*`) and add:

```nginx
location = /your-custom-trap {
    access_log /var/log/nginx/honeypot.log honeypot_log;
    default_type text/html;
    return 200 "your fake response here";
}
```

Reload nginx: `sudo systemctl reload nginx`

---

## Dashboard Sections

### 01 — Fail2Ban (INGSOC DEFENCE GRID)

| Metric | Description |
|--------|-------------|
| Bans Total | All-time ban count from fail2ban SQLite DB |
| Today | Bans today from fail2ban log |
| Currently Banned | IPs currently in the ban list (live from `fail2ban-client`) |
| Unique IPs | Distinct IPs ever banned |
| Attacks/Min | Found events per minute in the last hour |
| Attempts Today | Total "Found" events today |

**Charts:** 14-day ban timeline, 24-hour heatmap, top banned IPs with GeoIP, country breakdown with bar chart, repeat offenders list, live ban/unban/found event feed.

### 23 — Attack Patterns / SSH Analysis (WE ARE LEGION)

Parses the last 24 hours of SSH logs from `journalctl -u ssh` and analyzes:

| Metric | Description |
|--------|-------------|
| Attempts | Total invalid user + failed password events |
| Attackers | Unique source IPs |
| Usernames | Unique usernames tried |
| Invalid User | Attempts with non-existent usernames |
| Failed PW | Attempts with wrong passwords for existing users |
| Accepted | Successful logins (should be low / only yours) |

**Username categorization** groups attempted usernames into system, database, devops, crypto, services, and custom.

**Brute force detection** shows top attacker IPs with total attempts, attack velocity (attempts/minute), unique usernames tried, and GeoIP data.

**Attack waves** visualize attempt density in 10-minute buckets over the last 12 hours.

### 42 — AI Bot Radar (WER BEOBACHTET DIE BEOBACHTER)

Detects AI crawlers and classifies their behavior:

- **Known signatures**: GPTBot, ClaudeBot, PerplexityBot, Bytespider, Googlebot, Meta-ExternalAgent, CCBot, and more
- **Trap path analysis**: Which AI-specific lure paths get hit
- **Canary tracking**: Which bots confirm they read `/fnord/23/confirm`
- **Behavioral detection**: IPs that load pages but never execute JavaScript (no beacon fire)
- **Company breakdown**: Aggregated stats per AI company

### 05 — Honeypot (EXPECT US)

| Metric | Description |
|--------|-------------|
| Total Hits | All-time honeypot access count |
| Today | Hits today |
| Unique IPs | Distinct attacker IPs |
| Top Attacker | Most active IP with country |

**Charts:** Top triggered paths, top attacker IPs with GeoIP, 14-day timeline, 24-hour heatmap, user agent analysis, live access feed.

### 17 — OpenClaw (FUCKUP COMPUTER AKTIV)

| Metric | Description |
|--------|-------------|
| Login Attempts | Total login attempts (success + fail ratio) |
| Chat Messages | Messages sent to FUCKUP chatbot |
| Sessions | Unique visitor sessions |
| Bot Detection | Bot vs. human classification |

**Details:** Recent login attempts with credentials and IP, chat message log, click/navigation tracking, session timeline.

---

## Configuration

After installation, the config file is at `/opt/fnord-proxy/fnord.conf`:

```ini
# Dashboard bind address
BIND_HOST=127.0.0.1
BIND_PORT=8888

# Log and database paths
HONEYPOT_LOG=/var/log/nginx/honeypot.log
F2B_DB=/var/lib/fail2ban/fail2ban.sqlite3
F2B_LOG=/var/log/fail2ban.log

# OpenClaw integration
OPENCLAW_API_URL=http://localhost:18789
OPENCLAW_KEY_FILE=/opt/fnord-proxy/data/api.key
```

Configuration priority: `fnord.conf` > environment variables (`FNORD_*` prefix) > hardcoded defaults.

Environment variables can also be used:
```bash
FNORD_BIND_HOST=0.0.0.0 FNORD_BIND_PORT=9999 python3 dashboard.py
```

### fail2ban Tuning

Edit `/etc/fail2ban/jail.d/fnord-honeypot.conf`:

```ini
[fnord-honeypot]
enabled = true
filter = fnord-honeypot
logpath = /var/log/nginx/honeypot.log
maxretry = 3        # Ban after this many honeypot hits
findtime = 3600     # Within this window (seconds)
bantime = 86400     # Ban duration (seconds) — default 24h
```

---

## OpenClaw API Endpoints

The OpenClaw container exposes a REST API on port 18789.

Header: `X-API-Key: YOUR_KEY` (key is auto-generated in `data/api.key`)

| Endpoint | Description |
|----------|-------------|
| `GET /api/honeypot/stats` | Aggregated statistics |
| `GET /api/honeypot/logs` | All events (filterable by type) |
| `GET /api/honeypot/chat-messages` | Chat message log |
| `GET /api/honeypot/login-attempts` | Login attempts with success field |

---

## Project Structure

```
openclaw-honeypot/
├── dashboard.py                    # Analytics dashboard (systemd service, port 8888)
├── app.py                          # OpenClaw fake admin panel (Docker, port 18789)
├── install.sh                      # Interactive installer (nginx + fail2ban + Docker + systemd)
├── fnord.conf.example              # Configuration template
├── fnord-proxy.service             # systemd service unit for dashboard
├── docker-compose.yml              # Docker Compose for OpenClaw container
├── Dockerfile                      # OpenClaw container build
├── requirements.txt                # Python deps for OpenClaw (flask, gunicorn)
├── templates/                      # OpenClaw HTML templates (14 files)
│   ├── base.html                   #   Base layout
│   ├── login.html                  #   Fake login page
│   ├── dashboard.html              #   Fake admin dashboard
│   ├── chat.html                   #   FUCKUP chatbot interface
│   └── ...                         #   config, cron, nodes, skills, etc.
├── nginx/
│   ├── honeypot-log-format.conf    # Custom nginx log format
│   └── fnord-proxy.conf.template   # Full nginx site config with 30+ honeypot locations
├── fail2ban/
│   ├── fnord-honeypot.conf         # fail2ban filter definition
│   └── jail-fnord.conf             # fail2ban jail configuration
├── landing/
│   └── index.html                  # 23-themed decoy landing page
├── static/                         # Static assets
├── logs/                           # OpenClaw event logs (NDJSON)
└── LICENSE                         # MIT License
```

---

## Requirements

| Dependency | Purpose | Install |
|------------|---------|---------|
| **nginx** | Reverse proxy + honeypot locations | `apt install nginx` |
| **fail2ban** | Automatic IP banning | `apt install fail2ban` |
| **Python 3** | Dashboard backend | `apt install python3` |
| **Flask** | Web framework for dashboard | `pip3 install flask` |
| **Docker** | OpenClaw container | [docs.docker.com](https://docs.docker.com/engine/install/) |
| **SSL certificates** | HTTPS for the proxy | [Let's Encrypt](https://letsencrypt.org/) / `certbot` |

Tested on Debian 12 and Ubuntu 22.04/24.04. Should work on any systemd-based Linux distribution with nginx and Docker.

---

## Log Format

The honeypot uses a custom nginx log format:

```
$remote_addr|$time_iso8601|$request_uri|$status|$http_user_agent|$http_referer
```

Example entry:
```
203.0.113.42|2026-02-16T14:23:05+00:00|/.env|200|Mozilla/5.0 (compatible; scanner)|
```

Pipe-delimited for easy parsing. The dashboard reads this format directly.

---

## Security Notes

- The dashboard **only binds to localhost by default** — it is not exposed to the internet
- Access it via **SSH tunnel** or bind to a **VPN/Tailscale IP**
- OpenClaw runs in Docker with **read-only rootfs**, memory limit (256MB), CPU limit (0.5), no-new-privileges
- The honeypot responses contain **only fake data** — no real credentials or information
- fail2ban bans are applied via **iptables** and affect all HTTP/HTTPS ports
- The API key for OpenClaw is auto-generated and shared between dashboard and container via `data/api.key`
- GeoIP lookups use the free **ip-api.com** service (rate limited, results are cached in memory)

---

## Built with AI

This project was built interactively with **Claude Code** (Anthropic's CLI tool) as part of a homelab security setup. The entire codebase — nginx honeypot configs with 30+ realistic trap locations, a Flask dashboard with five separate analytics engines, a fake admin panel with login capture and chatbot, fail2ban integration, Docker deployment, a systemd service, an interactive install script, themed landing page, and the full 23-themed dashboard UI with CRT effects — was developed through conversation.

## License

[MIT](LICENSE)

---

*FNORD // 2+2=5 // ILLUMINATUS!*

*"Everything is connected. Nothing is what it seems. Everything is possible."*
