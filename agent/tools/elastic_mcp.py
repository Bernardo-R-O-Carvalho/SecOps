"""
elastic_mcp.py
SecOps Agent — Phase 3: Threat Detection via Elasticsearch REST API

Receives vulnerability findings from Phase 2 (GitLab scanner) and:
- Ingests findings into Elasticsearch as structured security events
- Generates simulated attack logs based on discovered vulnerabilities
- Runs detection queries for brute force, lateral movement, and exfiltration
- Correlates events into a kill chain
- Returns a prioritized risk dashboard

Design decisions:
- Uses Elasticsearch REST API directly (not MCP client protocol) because
  the Elastic MCP server is designed for IDE clients (Cursor, VS Code),
  not for programmatic Python integration.
- Simulates realistic attack logs based on the actual vulnerabilities found
  by gitlab_mcp.py, making the demo scenario coherent and reproducible.
- Kill chain follows the MITRE ATT&CK framework stages for credibility.
- Index names follow Elastic's ECS (Elastic Common Schema) conventions
  (logs-secops.*) for compatibility with built-in Kibana dashboards.
"""

import os
import json
import httpx
import random
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

ELASTIC_URL     = os.getenv("ELASTIC_URL", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

FINDINGS_INDEX  = "logs-secops.findings-default"
EVENTS_INDEX    = "logs-secops.events-default"
ALERTS_INDEX    = "logs-secops.alerts-default"


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class AttackEvent:
    timestamp:   str
    stage:       str        # MITRE ATT&CK stage
    technique:   str        # MITRE technique ID
    source_ip:   str
    destination: str
    action:      str
    outcome:     str        # success / failure
    severity:    str
    description: str
    related_cve: Optional[str] = None


@dataclass
class KillChain:
    attack_id:      str
    target_project: str
    started_at:     str
    stages:         list[AttackEvent] = field(default_factory=list)
    risk_score:     int = 0
    summary:        str = ""

    def to_dict(self) -> dict:
        return {
            "attack_id":      self.attack_id,
            "target_project": self.target_project,
            "started_at":     self.started_at,
            "risk_score":     self.risk_score,
            "summary":        self.summary,
            "stage_count":    len(self.stages),
            "stages": [
                {
                    "timestamp":   e.timestamp,
                    "stage":       e.stage,
                    "technique":   e.technique,
                    "source_ip":   e.source_ip,
                    "destination": e.destination,
                    "action":      e.action,
                    "outcome":     e.outcome,
                    "severity":    e.severity,
                    "description": e.description,
                    "related_cve": e.related_cve,
                }
                for e in self.stages
            ]
        }


# ─── Elasticsearch client ─────────────────────────────────────────────────────

class ElasticClient:
    def __init__(self, url: str, api_key: str):
        self.url     = url.rstrip("/")
        self.headers = {
            "Authorization": f"ApiKey {api_key}",
            "Content-Type":  "application/json",
        }

    def _request(self, method: str, path: str, body: dict = None) -> dict:
        url      = f"{self.url}/{path.lstrip('/')}"
        response = httpx.request(
            method, url,
            headers=self.headers,
            json=body,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def index(self, index: str, document: dict) -> dict:
        return self._request("POST", f"{index}/_doc", document)

    def bulk_index(self, index: str, documents: list[dict]) -> dict:
        lines = []
        for doc in documents:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(doc))
        body = "\n".join(lines) + "\n"

        url      = f"{self.url}/_bulk"
        response = httpx.post(
            url,
            headers={**self.headers, "Content-Type": "application/x-ndjson"},
            content=body.encode(),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def search(self, index: str, query: dict) -> dict:
        return self._request("GET", f"{index}/_search", query)

    def create_index(self, index: str, mappings: dict) -> dict:
        try:
            return self._request("PUT", index, mappings)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                return {"acknowledged": True, "existing": True}
            raise

    def count(self, index: str) -> int:
        try:
            result = self._request("GET", f"{index}/_count")
            return result.get("count", 0)
        except Exception:
            return 0


# ─── Index setup ──────────────────────────────────────────────────────────────

def setup_indices(client: ElasticClient) -> None:
    base_mapping = {
        "mappings": {
            "properties": {
                "@timestamp":  {"type": "date"},
                "severity":    {"type": "keyword"},
                "source_ip":   {"type": "ip"},
                "destination": {"type": "keyword"},
                "outcome":     {"type": "keyword"},
                "stage":       {"type": "keyword"},
                "technique":   {"type": "keyword"},
                "related_cve": {"type": "keyword"},
            }
        }
    }

    for index in [FINDINGS_INDEX, EVENTS_INDEX, ALERTS_INDEX]:
        result = client.create_index(index, base_mapping)
        status = "already exists" if result.get("existing") else "created"
        print(f"   Index {index}: {status}")


# ─── Log simulation ───────────────────────────────────────────────────────────

def generate_attack_logs(findings: list[dict]) -> list[AttackEvent]:
    attacker_ips = [
        "185.220.101.47",
        "194.165.16.11",
        "45.142.212.100",
    ]

    now    = datetime.now(timezone.utc)
    events = []

    secrets   = [f for f in findings if f["type"] == "SECRET_EXPOSED"]
    cves      = [f for f in findings if f["type"] == "VULNERABLE_DEPENDENCY"]
    misconfig = [f for f in findings if f["type"] == "MISCONFIGURATION"]

    # ── Stage 1: Reconnaissance ───────────────────────────────────────────────
    events.append(AttackEvent(
        timestamp   = (now - timedelta(hours=6)).isoformat(),
        stage       = "Reconnaissance",
        technique   = "T1595",
        source_ip   = attacker_ips[1],
        destination = "gitlab.com/secops-demo/vulnerable-app",
        action      = "repository_scan",
        outcome     = "success",
        severity    = "LOW",
        description = "Automated scanner discovered public repository with sensitive files",
    ))

    # ── Stage 2: Credential Access ────────────────────────────────────────────
    aws_secrets = [s for s in secrets if "AWS" in s.get("description", "")]
    if aws_secrets:
        events.append(AttackEvent(
            timestamp   = (now - timedelta(hours=5, minutes=30)).isoformat(),
            stage       = "Credential Access",
            technique   = "T1552.001",
            source_ip   = attacker_ips[0],
            destination = "amazonaws.com",
            action      = "credential_extraction",
            outcome     = "success",
            severity    = "CRITICAL",
            description = "AWS credentials extracted from hardcoded secrets in repository",
        ))

        events.append(AttackEvent(
            timestamp   = (now - timedelta(hours=5)).isoformat(),
            stage       = "Initial Access",
            technique   = "T1078.004",
            source_ip   = attacker_ips[0],
            destination = "s3.amazonaws.com",
            action      = "api_call_ListBuckets",
            outcome     = "success",
            severity    = "CRITICAL",
            description = "Attacker authenticated to AWS using exposed access key and enumerated S3 buckets",
        ))

    # ── Stage 4: Initial Access via vulnerable dependency ─────────────────────
    critical_cves = [c for c in cves if c["severity"] == "CRITICAL"]
    if critical_cves:
        cve = critical_cves[0]
        events.append(AttackEvent(
            timestamp   = (now - timedelta(hours=4)).isoformat(),
            stage       = "Initial Access",
            technique   = "T1190",
            source_ip   = attacker_ips[2],
            destination = "prod-server.example.com:5000",
            action      = "exploit_attempt",
            outcome     = "success",
            severity    = "CRITICAL",
            description = f"Exploitation of {cve['evidence']} — {cve['description']}",
            related_cve = cve["description"].split("—")[0].strip().split("==")[0] + " CVE",
        ))

    # ── Stage 5: Execution via command injection ───────────────────────────────
    cmd_injection = [m for m in misconfig if "command injection" in m.get("description", "").lower()]
    if cmd_injection:
        events.append(AttackEvent(
            timestamp   = (now - timedelta(hours=3, minutes=30)).isoformat(),
            stage       = "Execution",
            technique   = "T1059.004",
            source_ip   = attacker_ips[2],
            destination = "prod-server.example.com:5000",
            action      = "command_injection",
            outcome     = "success",
            severity    = "CRITICAL",
            description = "Remote command execution via /ping endpoint with shell=True subprocess",
        ))

    # ── Stage 6: Lateral Movement ─────────────────────────────────────────────
    events.append(AttackEvent(
        timestamp   = (now - timedelta(hours=3)).isoformat(),
        stage       = "Lateral Movement",
        technique   = "T1021.004",
        source_ip   = attacker_ips[2],
        destination = "internal-db.example.com:27017",
        action      = "ssh_connection",
        outcome     = "success",
        severity    = "HIGH",
        description = "Attacker moved laterally to internal MongoDB server using extracted credentials",
    ))

    # ── Stage 7: Collection / Exfiltration ────────────────────────────────────
    mongo_secrets = [s for s in secrets if "MongoDB" in s.get("description", "")]
    if mongo_secrets:
        events.append(AttackEvent(
            timestamp   = (now - timedelta(hours=2)).isoformat(),
            stage       = "Collection",
            technique   = "T1213",
            source_ip   = attacker_ips[2],
            destination = "internal-db.example.com:27017",
            action      = "database_dump",
            outcome     = "success",
            severity    = "CRITICAL",
            description = "Full production database dump using credentials from hardcoded MongoDB URI",
        ))

        events.append(AttackEvent(
            timestamp   = (now - timedelta(hours=1, minutes=30)).isoformat(),
            stage       = "Exfiltration",
            technique   = "T1041",
            source_ip   = attacker_ips[2],
            destination = "185.220.101.47:443",
            action      = "data_exfiltration",
            outcome     = "success",
            severity    = "CRITICAL",
            description = "Production database (2.3 GB) exfiltrated to attacker-controlled server over HTTPS",
        ))

    # ── Stage 8: Supply Chain via CI/CD ───────────────────────────────────────
    cicd_misconfig = [m for m in misconfig if "Curl piped" in m.get("description", "")]
    if cicd_misconfig:
        events.append(AttackEvent(
            timestamp   = (now - timedelta(minutes=45)).isoformat(),
            stage       = "Supply Chain",
            technique   = "T1195.002",
            source_ip   = attacker_ips[0],
            destination = "gitlab-ci.example.com",
            action      = "malicious_script_injection",
            outcome     = "success",
            severity    = "CRITICAL",
            description = "Malicious payload delivered via curl-to-bash in CI/CD pipeline — backdoor installed",
        ))

    return events


# ─── Detection queries ────────────────────────────────────────────────────────

def detect_brute_force(client: ElasticClient) -> list[dict]:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"outcome": "failure"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source_ip", "size": 10},
                "aggs":  {"attempt_count": {"value_count": {"field": "source_ip"}}}
            }
        },
        "size": 0
    }
    try:
        result  = client.search(EVENTS_INDEX, query)
        buckets = result.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
        return [{"ip": b["key"], "attempts": b["doc_count"]} for b in buckets if b["doc_count"] >= 3]
    except Exception:
        return []


def detect_lateral_movement(client: ElasticClient) -> list[dict]:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"stage": "Lateral Movement"}},
                    {"term":  {"outcome": "success"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        "size": 20
    }
    try:
        result = client.search(EVENTS_INDEX, query)
        hits   = result.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception:
        return []


def detect_exfiltration(client: ElasticClient) -> list[dict]:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"stage": "Exfiltration"}},
                    {"term":  {"outcome": "success"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        "size": 10
    }
    try:
        result = client.search(EVENTS_INDEX, query)
        hits   = result.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception:
        return []


# ─── Risk scoring ─────────────────────────────────────────────────────────────

def calculate_risk_score(findings: list[dict], kill_chain: "KillChain") -> int:
    """
    Continuous risk score 0-100 based on real findings + kill chain coverage.

    Components:
    - 60 pts: findings weight (severity × quantity, capped)
    - 40 pts: MITRE ATT&CK stages covered (proportional)
    """
    # Component 1: findings severity weight (max 60)
    weights = {"CRITICAL": 8, "HIGH": 4, "MEDIUM": 2, "LOW": 1}
    raw_findings = sum(weights.get(f.get("severity", "LOW"), 1) for f in findings)
    findings_score = min(raw_findings, 60)

    # Component 2: kill chain stage coverage (max 40)
    max_stages   = 8  # total mapped MITRE stages
    stages_hit   = len(set(e.stage for e in kill_chain.stages))
    chain_score  = int((stages_hit / max_stages) * 40)

    return findings_score + chain_score


def score_to_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


# ─── Kill chain builder ───────────────────────────────────────────────────────

def build_kill_chain(
    events: list[AttackEvent],
    project: str,
    findings: list[dict],
) -> KillChain:
    """
    Assembles the kill chain from detected events.
    Risk score uses continuous formula based on real findings + stage coverage.
    """
    stages_covered = list(dict.fromkeys(e.stage for e in events))

    # Build a temporary KillChain to pass to calculate_risk_score
    temp_chain = KillChain(
        attack_id      = "",
        target_project = project,
        started_at     = events[0].timestamp if events else datetime.now(timezone.utc).isoformat(),
        stages         = events,
        risk_score     = 0,
        summary        = "",
    )

    risk_score = calculate_risk_score(findings, temp_chain)

    summary = (
        f"Full attack chain detected across {len(stages_covered)} MITRE ATT&CK stages: "
        f"{' → '.join(stages_covered)}. "
        f"Attack originated from {events[0].source_ip if events else 'unknown'} "
        f"and progressed to data exfiltration. "
        f"Root cause: hardcoded credentials and vulnerable dependencies in source repository."
    )

    return KillChain(
        attack_id      = f"ATTACK-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        target_project = project,
        started_at     = events[0].timestamp if events else datetime.now(timezone.utc).isoformat(),
        stages         = events,
        risk_score     = risk_score,
        summary        = summary,
    )


# ─── Risk dashboard ───────────────────────────────────────────────────────────

def build_risk_dashboard(findings: list[dict], kill_chain: KillChain) -> dict:
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    attack_stages = list(dict.fromkeys(e.stage for e in kill_chain.stages))
    risk_score    = kill_chain.risk_score

    return {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "target_project":  kill_chain.target_project,
        "risk_score":      risk_score,
        "risk_level":      score_to_level(risk_score),
        "findings_summary": {
            "total":       len(findings),
            "by_severity": severity_counts,
        },
        "attack_summary": {
            "attack_id":     kill_chain.attack_id,
            "stages_count":  len(kill_chain.stages),
            "stages":        attack_stages,
            "started_at":    kill_chain.started_at,
            "kill_chain":    " → ".join(attack_stages),
        },
        "top_risks": [
            {
                "type":        f["type"],
                "severity":    f["severity"],
                "description": f["description"],
                "file":        f.get("file", ""),
            }
            for f in findings if f["severity"] == "CRITICAL"
        ][:5],
    }


# ─── Main orchestrator ────────────────────────────────────────────────────────

def run_elastic_pipeline(scan_summary: dict) -> dict:
    url     = ELASTIC_URL     or os.getenv("ELASTIC_URL")
    api_key = ELASTIC_API_KEY or os.getenv("ELASTIC_API_KEY")

    if not url or not api_key:
        raise ValueError("ELASTIC_URL and ELASTIC_API_KEY must be set as environment variables.")

    client   = ElasticClient(url, api_key)
    findings = scan_summary.get("findings", [])
    project  = scan_summary.get("project", "unknown")

    print(f"\n⚡ Starting Elastic pipeline for project: {project}")
    print(f"   Findings received from Phase 2: {len(findings)}")

    print("\n📦 Setting up Elasticsearch indices...")
    setup_indices(client)

    print(f"\n📥 Ingesting {len(findings)} vulnerability findings...")
    finding_docs = [
        {"@timestamp": datetime.now(timezone.utc).isoformat(), "source": "gitlab_scanner", "project": project, **f}
        for f in findings
    ]
    if finding_docs:
        client.bulk_index(FINDINGS_INDEX, finding_docs)
        print(f"   ✅ {len(finding_docs)} findings indexed in {FINDINGS_INDEX}")

    print("\n🎭 Generating attack scenario based on discovered vulnerabilities...")
    attack_events = generate_attack_logs(findings)
    print(f"   Generated {len(attack_events)} attack events across MITRE ATT&CK stages")

    event_docs = [
        {
            "@timestamp":  e.timestamp,
            "stage":       e.stage,
            "technique":   e.technique,
            "source_ip":   e.source_ip,
            "destination": e.destination,
            "action":      e.action,
            "outcome":     e.outcome,
            "severity":    e.severity,
            "description": e.description,
            "related_cve": e.related_cve,
        }
        for e in attack_events
    ]
    if event_docs:
        client.bulk_index(EVENTS_INDEX, event_docs)
        print(f"   ✅ {len(event_docs)} attack events indexed in {EVENTS_INDEX}")

    print("\n🔎 Running threat detection queries...")
    brute_force      = detect_brute_force(client)
    lateral_movement = detect_lateral_movement(client)
    exfiltration     = detect_exfiltration(client)

    print(f"   Brute force attempts detected:  {len(brute_force)}")
    print(f"   Lateral movement events:        {len(lateral_movement)}")
    print(f"   Exfiltration events:            {len(exfiltration)}")

    print("\n⛓️  Building kill chain...")
    kill_chain = build_kill_chain(attack_events, project, findings)
    print(f"   Attack ID:   {kill_chain.attack_id}")
    print(f"   Risk Score:  {kill_chain.risk_score}/100")
    print(f"   Stages:      {' → '.join(list(dict.fromkeys(e.stage for e in kill_chain.stages)))}")

    client.index(ALERTS_INDEX, {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "type":       "kill_chain",
        **kill_chain.to_dict(),
    })

    dashboard = build_risk_dashboard(findings, kill_chain)

    print("\n✅ Elastic pipeline complete")
    return {
        "kill_chain":     kill_chain.to_dict(),
        "risk_dashboard": dashboard,
        "detections": {
            "brute_force":      brute_force,
            "lateral_movement": lateral_movement,
            "exfiltration":     exfiltration,
        }
    }


# ─── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            scan_summary = json.load(f)
    else:
        print("Usage: python elastic_mcp.py <gitlab_scan_output.json>")
        print("\nRunning with built-in demo findings for testing...")

        scan_summary = {
            "project": "secops-demo/vulnerable-app",
            "total": 30,
            "by_severity": {"CRITICAL": 13, "HIGH": 14, "MEDIUM": 3, "LOW": 0},
            "findings": [
                {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",          "description": "AWS Access Key ID found hardcoded in source code",              "line": 10,   "evidence": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'},
                {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",          "description": "AWS Secret Access Key found hardcoded in source code",           "line": 11,   "evidence": "AWS_SECRET_ACCESS_KEY = ..."},
                {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",          "description": "MongoDB URI with credentials found hardcoded in source code",     "line": 15,   "evidence": "MONGO_URI = mongodb+srv://admin:SuperSecret123!@..."},
                {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",          "description": "Stripe Live Secret Key found hardcoded in source code",           "line": 20,   "evidence": "STRIPE_SECRET_KEY = sk_live_..."},
                {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt","description": "pymongo==2.8 — CVE-2015-1827: Query injection vulnerability",     "line": None, "evidence": "pymongo==2.8"},
                {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt","description": "pyyaml==3.12 — CVE-2017-18342: Arbitrary code execution",         "line": None, "evidence": "pyyaml==3.12"},
                {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt","description": "paramiko==1.16.0 — CVE-2018-7750: Authentication bypass",         "line": None, "evidence": "paramiko==1.16.0"},
                {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt","description": "jinja2==2.8 — CVE-2016-10745: Sandbox escape",                    "line": None, "evidence": "jinja2==2.8"},
                {"type": "MISCONFIGURATION",      "severity": "CRITICAL", "file": "app.py",          "description": "subprocess with shell=True — command injection risk",             "line": 36,   "evidence": "subprocess.run(..., shell=True)"},
                {"type": "MISCONFIGURATION",      "severity": "CRITICAL", "file": ".gitlab-ci.yml",  "description": "Curl piped to shell — unverified remote script execution",        "line": 31,   "evidence": "curl -s ... | bash"},
                {"type": "SECRET_EXPOSED",        "severity": "HIGH",     "file": ".gitlab-ci.yml",  "description": "PostgreSQL URI with credentials found hardcoded in source code",  "line": 5,    "evidence": "DATABASE_URL: postgresql://admin:password123@..."},
                {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": ".gitlab-ci.yml",  "description": "SSH without host verification — MITM vulnerability",              "line": 43,   "evidence": "StrictHostKeyChecking=no"},
                {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": ".gitlab-ci.yml",  "description": "Automatic production deploy without manual approval",             "line": 47,   "evidence": "when: on_success"},
            ]
        }

    result    = run_elastic_pipeline(scan_summary)
    dashboard = result["risk_dashboard"]
    chain     = result["kill_chain"]

    SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
    RISK_ICONS     = {"CRITICAL": "🚨", "HIGH": "⚠️",  "MEDIUM": "🟡", "LOW": "✅"}

    print("\n" + "=" * 60)
    print("📊 RISK DASHBOARD")
    print("=" * 60)
    print(f"Project     : {dashboard['target_project']}")
    print(f"Risk Level  : {RISK_ICONS.get(dashboard['risk_level'], '❓')} {dashboard['risk_level']} ({dashboard['risk_score']}/100)")
    print(f"Generated   : {dashboard['generated_at']}")

    print(f"\n🔍 Findings Summary")
    for sev, count in dashboard["findings_summary"]["by_severity"].items():
        if count > 0:
            print(f"  {SEVERITY_ICONS.get(sev, '⚪')} {sev}: {count}")

    print(f"\n⛓️  Kill Chain")
    print(f"  Attack ID : {chain['attack_id']}")
    print(f"  Started   : {chain['started_at']}")
    print(f"  Flow      : {dashboard['attack_summary']['kill_chain']}")

    print(f"\n🚨 Top Critical Risks")
    for risk in dashboard["top_risks"]:
        print(f"  🔴 [{risk['file']}] {risk['description'][:80]}")

    print()
    print(json.dumps(result, ensure_ascii=False, indent=2))
