# 🛡️ SecOps Agent
### Autonomous Security Operations Agent
**Google Cloud Rapid Agent Hackathon 2026** — Built with Gemini 3 + Google Cloud Agent Builder

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![Cloud Run](https://img.shields.io/badge/Deploy-Cloud_Run-4285F4.svg)](https://cloud.google.com/run)
[![Elastic](https://img.shields.io/badge/Partner-Elastic-FEC514.svg)](https://elastic.co)

> **From repository to incident report in under 20 seconds — fully autonomous, zero human intervention.**

---

## What is SecOps Agent?

SecOps Agent is an autonomous security agent that covers the **full security operations cycle** — from prevention to incident response — in a single pipeline run.

Most security tools work in silos: one for code scanning, another for log analysis, another for runtime monitoring. SecOps Agent breaks those silos by orchestrating **three partner integrations** into a single coherent workflow, powered by Gemini 3 and Google Cloud Agent Builder.

```
GitLab (Prevention) → Elastic (Detection) → Dynatrace (Response) → Incident Report
```

---

## Why Elastic is the Core Partner

SecOps Agent is submitted under the **Elastic track** — and for good reason.

Elastic is the heart of the pipeline. While GitLab provides the raw vulnerability data and Dynatrace confirms runtime impact, **Elastic is where the intelligence happens**:

- Ingests all vulnerability findings from GitLab into structured Elasticsearch indices
- Runs real-time detection queries for brute force, lateral movement, and data exfiltration
- Correlates events across time to **build the kill chain** — the sequence of events that form the attack
- Produces a prioritized risk dashboard with severity classification
- Powers the threat intelligence that feeds into Dynatrace for runtime correlation

Without Elastic, the agent has a list of vulnerabilities. With Elastic, the agent has a **story of an attack**.

---

## Live Demo

🌐 **[https://secops-agent-975832649259.us-central1.run.app](https://secops-agent-975832649259.us-central1.run.app)**

Try it with the demo repository:
```
secops-demo/vulnerable-app
```

---

## Pipeline Overview

### Phase 2 — Prevention (GitLab MCP)
Scans any GitLab repository for:
- **Exposed secrets** — AWS keys, Stripe keys, GitHub tokens, MongoDB URIs, JWT secrets, hardcoded passwords
- **Vulnerable dependencies** — cross-references `requirements.txt` against a curated CVE database
- **Misconfigurations** — curl-to-bash in CI/CD, `shell=True` in subprocess, SSH without host verification, auto-deploy without approval

### Phase 3 — Detection (Elastic MCP)
The intelligence layer:
- Ingests GitLab findings into Elasticsearch (`logs-secops.*` indices, ECS-compatible)
- Generates realistic attack scenarios based on discovered vulnerabilities
- Runs detection queries for brute force, lateral movement, and exfiltration patterns
- Builds the **MITRE ATT&CK kill chain** from correlated events
- Produces a risk score (0–100) and prioritized risk dashboard

### Phase 4 — Response (Dynatrace MCP)
Confirms real-world impact:
- Queries Dynatrace for active problems and security vulnerabilities
- Correlates runtime anomalies (CPU spikes, memory usage, outbound traffic) with kill chain stages
- Identifies exploited services with evidence
- Generates an automated **remediation playbook** with 12 prioritized actions (immediate / short-term / long-term)

### Phase 5 — Incident Report
Consolidates everything:
- Executive summary in plain language (for management)
- Full attack timeline sorted chronologically
- Top critical vulnerabilities with evidence
- Affected services with exploitation confirmation
- Downloadable report in **Markdown** and **JSON** formats

---

## Tech Stack

| Component | Technology |
|---|---|
| Agent Orchestration | Google Cloud Agent Builder |
| AI Model | Gemini 3 |
| Primary Partner | **Elastic MCP** (SIEM, threat detection, kill chain) |
| Partner 2 | GitLab MCP (repository scanning) |
| Partner 3 | Dynatrace MCP (runtime correlation) |
| Backend | FastAPI + Python 3.11 |
| Frontend | Single-file HTML/CSS/JS with real-time SSE |
| Hosting | Google Cloud Run |
| License | Apache 2.0 |

---

## Repository Structure

```
secops-agent/
├── agent/
│   ├── main.py              # FastAPI web UI + SSE streaming
│   ├── orchestrator.py      # Full pipeline orchestrator
│   ├── tools/
│   │   ├── gitlab_mcp.py    # Phase 2: GitLab repository scanner
│   │   ├── elastic_mcp.py   # Phase 3: Elastic threat detection
│   │   └── dynatrace_mcp.py # Phase 4: Dynatrace runtime correlation
│   └── report/
│       └── generator.py     # Phase 5: Incident Report generator
├── Dockerfile               # Cloud Run deployment
├── requirements.txt         # Python dependencies
└── LICENSE                  # Apache 2.0
```

---

## Running Locally

### Prerequisites
- Python 3.11+
- GitLab Personal Access Token (with `api` scope)
- Elastic Cloud account (Serverless, Security tier)
- Dynatrace account (trial works)

### Setup

```bash
git clone https://github.com/Bernardo-R-O-Carvalho/SecOps.git
cd SecOps
pip install -r requirements.txt
```

### Configure environment variables

```bash
export GITLAB_TOKEN="your-gitlab-token"
export ELASTIC_URL="https://your-cluster.es.us-central1.gcp.elastic.cloud"
export ELASTIC_API_KEY="your-elastic-api-key"
export DYNATRACE_URL="https://your-env.apps.dynatrace.com"
export DYNATRACE_TOKEN="your-dynatrace-token"
```

### Run the web UI

```bash
python -m uvicorn agent.main:app --host 0.0.0.0 --port 8080
```

Open **http://localhost:8080**, enter a GitLab repository, and click **RUN AGENT**.

### Run the CLI pipeline

```bash
python agent/orchestrator.py secops-demo/vulnerable-app
```

---

## Demo Repository

The agent is designed to scan any public GitLab repository. For the demo, use the intentionally vulnerable repository:

**`secops-demo/vulnerable-app`** — contains:
- AWS Access Key hardcoded in `app.py`
- MongoDB URI with credentials
- Stripe Live Secret Key
- 12 dependencies with known CVEs (pymongo, pyyaml, paramiko, jinja2, celery...)
- CI/CD with curl-to-bash, auto-deploy without approval, SSH without host verification

This produces a **Risk Score of 100/100 CRITICAL** with a full 8-stage MITRE ATT&CK kill chain.

---

## MITRE ATT&CK Coverage

The agent detects and maps attacks across 8 stages:

| Stage | Technique | Description |
|---|---|---|
| Reconnaissance | T1595 | Automated repository discovery |
| Credential Access | T1552.001 | Hardcoded secrets extraction |
| Initial Access | T1078.004 | Cloud exploitation via stolen credentials |
| Initial Access | T1190 | Vulnerable dependency exploitation |
| Execution | T1059.004 | Command injection via shell=True |
| Lateral Movement | T1021.004 | SSH movement to internal systems |
| Collection | T1213 | Database dump via exposed credentials |
| Exfiltration | T1041 | Data exfiltration over HTTPS |
| Supply Chain | T1195.002 | CI/CD pipeline compromise |

---

## Roadmap

- [ ] Expand CVE database with OSV/NVD API integration for all languages
- [ ] Add support for `package-lock.json` and `yarn.lock` (Node.js projects)
- [ ] GitHub and Bitbucket repository support
- [ ] Slack/email webhook for automated report delivery
- [ ] Historical trend analysis across multiple scans

---

## Author

**Bernardo Carvalho** — [github.com/Bernardo-R-O-Carvalho](https://github.com/Bernardo-R-O-Carvalho)

Built for the **Google Cloud Rapid Agent Hackathon 2026**

---

*Apache 2.0 License — See [LICENSE](LICENSE) for details*
