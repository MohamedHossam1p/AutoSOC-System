# AutoSOC System

<div align="center">

![AutoSOC](https://img.shields.io/badge/AutoSOC-Automated%20SOC%20Pipeline-ff4444?style=for-the-badge&logo=shield&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7+-00a0e0?style=flat-square&logo=wazuh&logoColor=white)](https://wazuh.com)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=flat-square&logo=elasticsearch&logoColor=white)](https://elastic.co)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-47A248?style=flat-square&logo=mongodb&logoColor=white)](https://mongodb.com)
[![n8n](https://img.shields.io/badge/n8n-SOAR-ea4b71?style=flat-square&logo=n8n&logoColor=white)](https://n8n.io)
[![License](https://img.shields.io/badge/License-Academic-yellow?style=flat-square)]()

**An automated, AI-powered Security Operations Center pipeline — from threat detection to autonomous response.**

[Overview](#overview) · [Architecture](#architecture) · [Quick Start](#quick-start) · [Dashboard](#dashboard) · [API Reference](#api-reference) · [Configuration](#configuration)

</div>

---

## Overview

AutoSOC is a fully automated SOC pipeline that eliminates manual alert triage by integrating open-source security tools with AI-driven analysis. It detects threats via Wazuh, enriches indicators through multiple threat intelligence sources, calculates a composite risk score, and autonomously responds — all within seconds of detection.

**Key capabilities:**

- Real-time threat detection with custom Wazuh rules mapped to MITRE ATT&CK
- Automated IP enrichment via AbuseIPDB, VirusTotal, and IPGeolocation
- Weighted risk scoring engine (0–100) with automatic blocking above a configurable threshold
- AI-generated alert summaries via Google Gemini
- Interactive SOC dashboard with live Elasticsearch data and a geospatial threat map
- Persistent case management backed by MongoDB
- Conversational firewall control via a Telegram AI chatbot (Groq LLM)

> Built as a Computer Science graduation project — Arab Open University, 2025/2026.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       DETECTION LAYER                         │
│   Endpoint Agent → Wazuh Manager → Custom Rules (MITRE-mapped)│
└───────────────────────────────┬────────────────────────────────┘
                                │ Webhook
┌───────────────────────────────▼────────────────────────────────┐
│                     AUTOMATION LAYER (n8n)                     │
│                                                                 │
│  Parse Alert → AbuseIPDB → IPGeolocation → VirusTotal           │
│                          │                                      │
│                  Risk Score Engine (0–100)                      │
│                          │                                      │
│        ┌─────────────────┼─────────────────┐                   │
│   Score ≥ threshold   Save to ES        Gemini AI                │
│   Auto-block (iptables) soc-live-alerts  Summary                 │
│        └─────────────────┼─────────────────┘                   │
│                          │                                      │
│                   Telegram Notification                         │
└───────────────────────────────┬────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────┐
│                     PRESENTATION LAYER                         │
│  SOC Dashboard (Browser)                                        │
│  ├── Live Monitoring  → elastic_proxy (Elasticsearch)            │
│  ├── Case Management  → cases_api → MongoDB                      │
│  ├── MITRE ATT&CK      → elastic_proxy                           │
│  ├── Alert History    → elastic_proxy                            │
│  └── Threat Hunting   → elastic_proxy                            │
└───────────────────────────────┬────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────┐
│                  AI CHATBOT LAYER (Telegram)                   │
│  Analyst Message → Groq LLM → soc_action_server → iptables       │
│                          (block / unblock / check / list)        │
└──────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
AutoSOC/
│
├── README.md
├── .gitignore
├── .env.example
│
├── backend/
│   ├── elastic_proxy.py          # Elasticsearch CORS bridge
│   ├── soc_action_server.py      # Firewall control REST API
│   └── cases_api.py              # MongoDB case management API
│
├── frontend/
│   ├── index.html                # Dashboard markup
│   ├── css/
│   │   └── styles.css
│   └── js/
│       ├── config.js             # API endpoints & constants
│       ├── utils.js              # Shared helpers (risk colors, time format)
│       ├── auth.js               # Login / logout / analyst management
│       ├── map.js                # Leaflet map initialization
│       ├── alerts.js             # Live alert fetching, grouping, sorting
│       ├── cases.js              # Case CRUD against MongoDB API
│       ├── analytics.js          # Charts: countries, ISPs, risk, timeline
│       ├── mitre.js              # MITRE ATT&CK live coverage map
│       ├── search.js             # Historical alert search
│       ├── hunting.js            # Pre-built + custom threat hunting queries
│       └── main.js               # Entry point
│
└── configs/
    ├── wazuh-rules/
    │   └── local_rules.xml       # Custom detection rules
    └── n8n-workflows/
        ├── AutoSOC_Main_Workflow.json
        └── Actions_Subworkflow.json
```

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Ubuntu | 22.04 LTS | Server OS |
| Python | 3.10+ | For microservices |
| Wazuh Manager | 4.7+ | SIEM/EDR |
| Elasticsearch | 8.x | Alert storage |
| MongoDB | 7.0 | Case management |
| n8n | Latest | SOAR automation |

### 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AutoSOC-System.git
cd AutoSOC-System
```

### 2 — Configure environment variables

```bash
cp .env.example .env
# Edit .env with your actual server IP, credentials, and API keys
```

### 3 — Install MongoDB

```bash
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc \
  | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
  https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
  | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

sudo apt update && sudo apt install -y mongodb-org
sudo systemctl enable --now mongod
```

### 4 — Install Python dependencies

```bash
pip install pymongo --break-system-packages
```

### 5 — Deploy backend microservices

```bash
sudo cp backend/elastic_proxy.py     /opt/autosoc/
sudo cp backend/soc_action_server.py /opt/autosoc/
sudo cp backend/cases_api.py         /opt/autosoc/
```

### 6 — Register systemd services

**SOC Action Server**

```bash
sudo tee /etc/systemd/system/soc-action.service > /dev/null << 'EOF'
[Unit]
Description=AutoSOC Firewall Action API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/autosoc/soc_action_server.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
```

**Cases API**

```bash
sudo tee /etc/systemd/system/soc-cases.service > /dev/null << 'EOF'
[Unit]
Description=AutoSOC Cases API
After=mongod.service network.target

[Service]
ExecStart=/usr/bin/python3 /opt/autosoc/cases_api.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-action soc-cases
```

**Elastic Proxy** (runs on reboot via crontab):

```bash
(crontab -l 2>/dev/null; echo "@reboot python3 /opt/autosoc/elastic_proxy.py &") | crontab -
python3 /opt/autosoc/elastic_proxy.py &
```

### 7 — Install custom Wazuh rules

```bash
sudo cp configs/wazuh-rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

### 8 — Import n8n workflows

1. Open n8n at `http://YOUR_SERVER:5678`
2. **+** → **Import from file** → select `AutoSOC_Main_Workflow.json`
3. Repeat for `Actions_Subworkflow.json`
4. Add your API credentials under **Settings → Credentials**

### 9 — Verify deployment

```bash
sudo systemctl status wazuh-manager mongod soc-action soc-cases

curl -s http://YOUR_SERVER:9202/_cluster/health
curl -s http://YOUR_SERVER:9205/cases
```

A healthy `cases` endpoint returns `[]` on a fresh install.

---

## Dashboard

Open `frontend/index.html` in a browser, or serve it over HTTP:

```bash
cd frontend && python3 -m http.server 8081
# → http://YOUR_SERVER_IP:8081
```

> Update `frontend/js/config.js` with your server's IP before first use:
> ```javascript
> const PROXY_URL = "http://YOUR_IP:9202";
> const LIVE_URL  = "http://YOUR_IP:9202";
> const CASES_API = "http://YOUR_IP:9205";
> ```

### Dashboard Tabs

| Tab | Data Source | Description |
|---|---|---|
| Live Monitoring | Elasticsearch `soc-live-alerts` | Real-time grouped alerts with geospatial map |
| Case Management | MongoDB via Cases API | Create, update, and track incidents |
| Analytics | Elasticsearch | Country, ISP, risk, and timeline charts |
| MITRE ATT&CK | Elasticsearch | Live tactic/technique coverage heatmap |
| Alert History | Elasticsearch `wazuh-alerts-4.x-*` | Full-text search across historical alerts |
| Threat Hunting | Elasticsearch | Pre-built hunting queries + custom DSL |

---

## Services & Ports

| Service | Port | Description |
|---|---|---|
| Wazuh Manager API | 55000 | Active Response + Auth |
| Elasticsearch | 9200 | Internal (localhost only) |
| Elastic Proxy — Read | 9202 | Dashboard → Elasticsearch bridge |
| Elastic Proxy — Write | 9203 | n8n → Elasticsearch ingest |
| SOC Action Server | 9204 | Firewall REST API (Bearer auth) |
| Cases API | 9205 | MongoDB CRUD interface |
| MongoDB | 27017 | Database (localhost only) |
| Dashboard | 8081 | Web UI |
| n8n | 5678 | SOAR engine |

---

## API Reference

### Cases API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/cases` | List all cases |
| `POST` | `/cases` | Create new case |
| `PUT` | `/cases/{id}` | Update case fields |
| `DELETE` | `/cases/{id}` | Delete case |
| `POST` | `/cases/{id}/notes` | Append note to case |

### SOC Action Server

All requests require: `Authorization: Bearer <SOC_ACTION_TOKEN>`

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `POST` | `/block` | `{"ip": "1.2.3.4"}` | Add iptables DROP rule |
| `POST` | `/unblock` | `{"ip": "1.2.3.4"}` | Remove iptables rule |
| `POST` | `/check` | `{"ip": "1.2.3.4"}` | Check if IP is blocked |
| `POST` | `/list-blocked` | `{}` | List all blocked IPs |
| `POST` | `/flush` | `{}` | Clear all rules |

---

## Risk Score Algorithm

```
score = (abuseScore × 0.35)
      + (vtMalicious × 3.5)
      + (vtSuspicious × 1.5)
      + (isTor ? 15 : 0)
      + min(distinctUsers × 0.3, 10)
      + attackTypeBonus
      + freshnessBonus
      + usageBonus

Capped at [0, 100]
```

| Score | Level | Automatic Action |
|---|---|---|
| 76 – 100 | Critical | Auto-block + alert |
| 51 – 75 | High | Alert, manual investigation |
| 26 – 50 | Medium | Logged and monitored |
| 0 – 25 | Low | Logged only |

---

## Telegram Chatbot

```
"block 185.224.128.83"          → blocks IP on firewall
"unblock 185.224.128.83"        → removes block
"is 185.224.128.83 blocked?"    → checks status
"list all blocked IPs"          → returns full list
"flush all rules"               → clears iptables
```

---

## Configuration

All sensitive values are loaded from environment variables — see `.env.example` for the full list. Never commit a populated `.env` file.

| Variable | Used By | Purpose |
|---|---|---|
| `ES_HOST` | elastic_proxy.py | Elasticsearch connection |
| `ELASTIC_USER` / `ELASTIC_PASS` | elastic_proxy.py | Elasticsearch auth |
| `MONGO_URI` / `MONGO_DB` | cases_api.py | MongoDB connection |
| `SECRET_KEY` | backend services | Token signing |
| `SOC_ACTION_TOKEN` | soc_action_server.py | Firewall API auth |
| `ABUSEIPDB_API_KEY` | n8n workflow | IP reputation lookup |
| `VIRUSTOTAL_API_KEY` | n8n workflow | Malware/IOC analysis |
| `IPGEOLOCATION_API_KEY` | n8n workflow | Geo enrichment |
| `GOOGLE_GEMINI_API_KEY` | n8n workflow | AI alert summaries |
| `GROQ_API_KEY` | n8n workflow | Telegram chatbot LLM |
| `TELEGRAM_BOT_TOKEN` | n8n workflow | Notifications & chatbot |

---

## Troubleshooting

**Dashboard shows "Connection Error — Retrying"**
```bash
curl http://YOUR_SERVER:9202/soc-live-alerts/_count
```

**Cases not loading or saving**
```bash
sudo systemctl status soc-cases
curl http://YOUR_SERVER:9205/cases
```

**Firewall commands returning 401**
```bash
sudo journalctl -u soc-action -n 30 --no-pager
# Verify the Bearer token matches SOC_ACTION_TOKEN in your .env
```

**n8n workflow not triggering**
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A 10 integration
```

---

## License

Developed for academic purposes as a graduation project — Arab Open University, Faculty of Computer Science, 2025/2026.

---

<div align="center">

Built with Wazuh · Elasticsearch · n8n · MongoDB · Google Gemini · Groq · Telegram

</div>
