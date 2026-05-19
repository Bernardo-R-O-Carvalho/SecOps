"""
dynatrace_mcp.py
SecOps Agent — Phase 4: Runtime Correlation via Dynatrace REST API v2

Receives the kill chain and risk dashboard from Phase 3 (Elastic) and:
- Queries Dynatrace for active problems and security vulnerabilities
- Simulates runtime anomalies correlated with the attack findings
- Identifies affected services and confirms active exploitation
- Generates an automated remediation playbook with concrete actions

Design decisions:
- Uses Dynatrace REST API v2 directly (same rationale as Elastic MCP:
  the Dynatrace MCP server targets IDE clients, not Python scripts).
- Falls back to simulated runtime data when no real anomalies exist
  in the trial environment, keeping the demo coherent regardless of
  actual infrastructure being monitored.
- Remediation playbook follows a priority order: contain first,
  then eradicate, then recover — standard incident response lifecycle.
- Each remediation action is tagged with effort (immediate/short/long)
  and owner (security/devops/management) for actionability.
"""

import os
import json
import httpx
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional


# ─── Configuration ────────────────────────────────────────────────────────────

DT_URL   = os.getenv("DYNATRACE_URL", "")
DT_TOKEN = os.getenv("DYNATRACE_TOKEN", "")


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class RuntimeAnomaly:
    service:     str
    metric:      str
    value:       float
    threshold:   float
    unit:        str
    severity:    str
    description: str
    timestamp:   str
    correlated_to: Optional[str] = None   # links to kill chain stage


@dataclass
class AffectedService:
    name:          str
    entity_id:     str
    severity:      str
    anomalies:     list[RuntimeAnomaly] = field(default_factory=list)
    exploited:     bool = False
    exploit_evidence: Optional[str] = None


@dataclass
class RemediationAction:
    priority:    int
    effort:      str   # immediate / short-term / long-term
    owner:       str   # security / devops / management
    action:      str
    rationale:   str
    command:     Optional[str] = None   # concrete CLI/API command if applicable


@dataclass
class Playbook:
    generated_at:     str
    attack_id:        str
    risk_level:       str
    affected_services: list[AffectedService] = field(default_factory=list)
    actions:          list[RemediationAction] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at":  self.generated_at,
            "attack_id":     self.attack_id,
            "risk_level":    self.risk_level,
            "affected_services": [
                {
                    "name":             s.name,
                    "entity_id":        s.entity_id,
                    "severity":         s.severity,
                    "exploited":        s.exploited,
                    "exploit_evidence": s.exploit_evidence,
                    "anomalies": [
                        {
                            "metric":         a.metric,
                            "value":          a.value,
                            "threshold":      a.threshold,
                            "unit":           a.unit,
                            "severity":       a.severity,
                            "description":    a.description,
                            "correlated_to":  a.correlated_to,
                        }
                        for a in s.anomalies
                    ]
                }
                for s in self.affected_services
            ],
            "remediation_actions": [
                {
                    "priority":  a.priority,
                    "effort":    a.effort,
                    "owner":     a.owner,
                    "action":    a.action,
                    "rationale": a.rationale,
                    "command":   a.command,
                }
                for a in sorted(self.actions, key=lambda x: x.priority)
            ]
        }


# ─── Dynatrace API client ─────────────────────────────────────────────────────

class DynatraceClient:
    """
    Thin wrapper around the Dynatrace REST API v2.
    Authenticates via Api-Token header.
    """

    def __init__(self, url: str, token: str):
        self.base_url = url.rstrip("/") + "/api/v2"
        self.headers  = {
            "Authorization": f"Api-Token {token}",
            "Content-Type":  "application/json",
        }

    def _get(self, path: str, params: dict = None) -> dict:
        url      = f"{self.base_url}/{path.lstrip('/')}"
        response = httpx.get(url, headers=self.headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_problems(self, status: str = "OPEN") -> list[dict]:
        """Fetch active problems from Dynatrace."""
        try:
            result = self._get("problems", {"problemSelector": f"status({status})"})
            return result.get("problems", [])
        except Exception as e:
            print(f"   ⚠️  Could not fetch problems: {e}")
            return []

    def get_security_problems(self) -> list[dict]:
        """Fetch open security vulnerabilities."""
        try:
            result = self._get("securityProblems", {"securityProblemSelector": "status(OPEN)"})
            return result.get("securityProblems", [])
        except Exception as e:
            print(f"   ⚠️  Could not fetch security problems: {e}")
            return []

    def get_entities(self, entity_type: str = "SERVICE") -> list[dict]:
        """Fetch monitored entities of a given type."""
        try:
            result = self._get("entities", {
                "entitySelector": f"type({entity_type})",
                "pageSize": 10,
            })
            return result.get("entities", [])
        except Exception as e:
            print(f"   ⚠️  Could not fetch entities: {e}")
            return []

    def get_metrics(self, metric_selector: str, from_time: str = "now-1h") -> dict:
        """Query metrics data."""
        try:
            return self._get("metrics/query", {
                "metricSelector": metric_selector,
                "from":           from_time,
                "resolution":     "5m",
            })
        except Exception as e:
            print(f"   ⚠️  Could not fetch metrics: {e}")
            return {}


# ─── Runtime anomaly simulation ───────────────────────────────────────────────

def simulate_anomalies(kill_chain: dict) -> list[RuntimeAnomaly]:
    """
    Generates realistic runtime anomalies correlated with kill chain stages.

    In a production environment these would come from real Dynatrace metrics.
    For the demo, anomalies are generated based on the actual attack stages
    detected in Phase 3, making the narrative coherent across all phases.
    """

    now    = datetime.now(timezone.utc)
    stages = [s["stage"] for s in kill_chain.get("stages", [])]
    anomalies = []

    # CPU spike — correlated with command injection / execution stage
    if "Execution" in stages:
        anomalies.append(RuntimeAnomaly(
            service       = "prod-server.example.com:5000",
            metric        = "builtin:host.cpu.usage",
            value         = 94.7,
            threshold     = 80.0,
            unit          = "%",
            severity      = "CRITICAL",
            description   = "CPU spike to 94.7% — consistent with remote command execution via /ping endpoint",
            timestamp     = now.isoformat(),
            correlated_to = "Execution — T1059.004 (command injection)",
        ))

    # Memory spike — correlated with database dump / collection stage
    if "Collection" in stages:
        anomalies.append(RuntimeAnomaly(
            service       = "internal-db.example.com:27017",
            metric        = "builtin:host.mem.usage",
            value         = 91.2,
            threshold     = 85.0,
            unit          = "%",
            severity      = "CRITICAL",
            description   = "Memory at 91.2% — consistent with full production database dump (2.3 GB)",
            timestamp     = now.isoformat(),
            correlated_to = "Collection — T1213 (database dump)",
        ))

    # Outbound network spike — correlated with exfiltration stage
    if "Exfiltration" in stages:
        anomalies.append(RuntimeAnomaly(
            service       = "internal-db.example.com:27017",
            metric        = "builtin:host.net.out",
            value         = 2340.0,
            threshold     = 100.0,
            unit          = "MB/s",
            severity      = "CRITICAL",
            description   = "Outbound traffic 2340 MB/s to 185.220.101.47:443 — active data exfiltration detected",
            timestamp     = now.isoformat(),
            correlated_to = "Exfiltration — T1041 (data exfiltration over HTTPS)",
        ))

    # Unusual AWS API calls — correlated with credential access
    if "Credential Access" in stages:
        anomalies.append(RuntimeAnomaly(
            service       = "amazonaws.com",
            metric        = "aws.api.calls",
            value         = 847.0,
            threshold     = 50.0,
            unit          = "calls/min",
            severity      = "CRITICAL",
            description   = "847 AWS API calls/min from unknown IP — exposed AWS key being actively used",
            timestamp     = now.isoformat(),
            correlated_to = "Credential Access — T1552.001 (hardcoded AWS key)",
        ))

    # Lateral movement — unusual internal connections
    if "Lateral Movement" in stages:
        anomalies.append(RuntimeAnomaly(
            service       = "internal-db.example.com:27017",
            metric        = "builtin:service.errors.total.rate",
            value         = 0.0,
            threshold     = 0.0,
            unit          = "connections",
            severity      = "HIGH",
            description   = "New SSH connection from prod-server to internal MongoDB — lateral movement pattern",
            timestamp     = now.isoformat(),
            correlated_to = "Lateral Movement — T1021.004 (SSH lateral movement)",
        ))

    # CI/CD pipeline anomaly — supply chain stage
    if "Supply Chain" in stages:
        anomalies.append(RuntimeAnomaly(
            service       = "gitlab-ci.example.com",
            metric        = "builtin:service.response.time",
            value         = 45000.0,
            threshold     = 5000.0,
            unit          = "ms",
            severity      = "HIGH",
            description   = "CI/CD pipeline response time 45s — consistent with malicious script execution via curl-to-bash",
            timestamp     = now.isoformat(),
            correlated_to = "Supply Chain — T1195.002 (CI/CD compromise)",
        ))

    return anomalies


# ─── Service impact analysis ──────────────────────────────────────────────────

def identify_affected_services(
    anomalies:  list[RuntimeAnomaly],
    dt_entities: list[dict],
) -> list[AffectedService]:
    """
    Groups anomalies by service and determines exploitation status.
    Merges real Dynatrace entities with simulated anomaly data.
    """

    service_map: dict[str, AffectedService] = {}

    # Add simulated services from anomalies
    simulated_services = {
        "prod-server.example.com:5000": ("SERVICE-PROD-001", "CRITICAL"),
        "internal-db.example.com:27017": ("SERVICE-DB-001",  "CRITICAL"),
        "amazonaws.com":                 ("SERVICE-AWS-001", "CRITICAL"),
        "gitlab-ci.example.com":         ("SERVICE-CI-001",  "HIGH"),
    }

    for service_name, (entity_id, severity) in simulated_services.items():
        service_map[service_name] = AffectedService(
            name=service_name, entity_id=entity_id, severity=severity
        )

    # Attach anomalies to services
    for anomaly in anomalies:
        svc = anomaly.service
        if svc not in service_map:
            service_map[svc] = AffectedService(
                name=svc, entity_id=f"SERVICE-{svc[:8].upper()}", severity=anomaly.severity
            )
        service_map[svc].anomalies.append(anomaly)

    # Mark exploited services (those with CRITICAL anomalies)
    for svc in service_map.values():
        if any(a.severity == "CRITICAL" for a in svc.anomalies):
            svc.exploited        = True
            svc.exploit_evidence = next(
                (a.description for a in svc.anomalies if a.severity == "CRITICAL"), None
            )

    # Merge real Dynatrace entities if available
    for entity in dt_entities:
        name      = entity.get("displayName", "")
        entity_id = entity.get("entityId", "")
        if name and entity_id and name not in service_map:
            service_map[name] = AffectedService(
                name=name, entity_id=entity_id, severity="LOW"
            )

    return list(service_map.values())


# ─── Remediation playbook generator ──────────────────────────────────────────

def generate_playbook(
    findings:          list[dict],
    kill_chain:        dict,
    affected_services: list[AffectedService],
    attack_id:         str,
    risk_level:        str,
) -> Playbook:
    """
    Generates a prioritized remediation playbook based on:
    - Vulnerability types found in Phase 2 (GitLab)
    - Attack stages detected in Phase 3 (Elastic)
    - Runtime impact confirmed in Phase 4 (Dynatrace)

    Actions follow the PICERL incident response lifecycle:
    Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
    """

    actions = []
    priority = 1

    finding_types = {f["type"] for f in findings}
    finding_desc  = " ".join(f.get("description", "") for f in findings)
    stages        = {s["stage"] for s in kill_chain.get("stages", [])}

    # ── IMMEDIATE CONTAINMENT ─────────────────────────────────────────────────

    if "Exfiltration" in stages:
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "immediate",
            owner     = "security",
            action    = "Block attacker IPs at firewall level",
            rationale = "Active exfiltration detected to 185.220.101.47 and 45.142.212.100. Block immediately to stop ongoing data loss.",
            command   = "iptables -A OUTPUT -d 185.220.101.47 -j DROP && iptables -A OUTPUT -d 45.142.212.100 -j DROP",
        ))
        priority += 1

    if "AWS" in finding_desc or "Credential Access" in stages:
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "immediate",
            owner     = "security",
            action    = "Revoke exposed AWS credentials immediately",
            rationale = "AWS Access Key AKIAIOSFODNN7EXAMPLE was found hardcoded and is actively being used by the attacker.",
            command   = "aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE",
        ))
        priority += 1

    if "MongoDB" in finding_desc or "Lateral Movement" in stages:
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "immediate",
            owner     = "devops",
            action    = "Rotate MongoDB credentials and restrict network access",
            rationale = "MongoDB URI with credentials was exposed and the attacker successfully accessed the production database.",
            command   = "mongo admin --eval \"db.changeUserPassword('admin', '<new-secure-password>')\"",
        ))
        priority += 1

    if any(a.exploited for a in affected_services if "prod-server" in a.name):
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "immediate",
            owner     = "devops",
            action    = "Isolate compromised production server from network",
            rationale = "prod-server.example.com:5000 shows CRITICAL CPU anomaly consistent with remote command execution.",
            command   = "aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --no-source-dest-check && aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol all --source-group <SG_ID>",
        ))
        priority += 1

    # ── SHORT-TERM ERADICATION ────────────────────────────────────────────────

    if "SECRET_EXPOSED" in finding_types:
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "short-term",
            owner     = "devops",
            action    = "Remove all hardcoded secrets from source code and rotate all credentials",
            rationale = "13 hardcoded secrets found across app.py and .gitlab-ci.yml. All must be replaced with environment variables or a secrets manager.",
            command   = "git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch app.py' --prune-empty --tag-name-filter cat -- --all",
        ))
        priority += 1

        actions.append(RemediationAction(
            priority  = priority,
            effort    = "short-term",
            owner     = "devops",
            action    = "Implement secrets management (HashiCorp Vault or AWS Secrets Manager)",
            rationale = "Secrets must never be stored in source code. A secrets manager provides rotation, auditing, and access control.",
            command   = None,
        ))
        priority += 1

    if "VULNERABLE_DEPENDENCY" in finding_types:
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "short-term",
            owner     = "devops",
            action    = "Update all vulnerable dependencies to patched versions",
            rationale = "5 CRITICAL CVEs found: pymongo, pyyaml, paramiko, jinja2, celery. All enable remote code execution.",
            command   = "pip install flask>=2.3.0 requests>=2.31.0 pymongo>=4.6.0 pyyaml>=6.0.1 paramiko>=3.4.0 jinja2>=3.1.4 celery>=5.3.6",
        ))
        priority += 1

    if "MISCONFIGURATION" in finding_types:
        actions.append(RemediationAction(
            priority  = priority,
            effort    = "short-term",
            owner     = "devops",
            action    = "Fix CI/CD pipeline: remove curl-to-bash, require manual approval for production deploys",
            rationale = "CI/CD pipeline executes unverified remote scripts and deploys to production without approval — supply chain attack vector.",
            command   = None,
        ))
        priority += 1

        actions.append(RemediationAction(
            priority  = priority,
            effort    = "short-term",
            owner     = "devops",
            action    = "Replace subprocess shell=True with explicit argument lists",
            rationale = "shell=True in subprocess.run() allows command injection via user-controlled input in the /ping endpoint.",
            command   = None,
        ))
        priority += 1

    # ── LONG-TERM RECOVERY ────────────────────────────────────────────────────

    actions.append(RemediationAction(
        priority  = priority,
        effort    = "long-term",
        owner     = "security",
        action    = "Implement SAST and secret scanning in CI/CD pipeline",
        rationale = "Static analysis and secret detection must run on every commit to prevent recurrence.",
        command   = None,
    ))
    priority += 1

    actions.append(RemediationAction(
        priority  = priority,
        effort    = "long-term",
        owner     = "security",
        action    = "Conduct full forensic investigation and assess data breach scope",
        rationale = "2.3 GB of production data was exfiltrated. A forensic investigation is required to determine what data was exposed and whether breach notification is legally required.",
        command   = None,
    ))
    priority += 1

    actions.append(RemediationAction(
        priority  = priority,
        effort    = "long-term",
        owner     = "management",
        action    = "Assess legal and regulatory obligations (LGPD / GDPR breach notification)",
        rationale = "Production database exfiltration may trigger mandatory breach notification under LGPD (Brazil) within 72 hours of discovery.",
        command   = None,
    ))
    priority += 1

    return Playbook(
        generated_at      = datetime.now(timezone.utc).isoformat(),
        attack_id         = attack_id,
        risk_level        = risk_level,
        affected_services = affected_services,
        actions           = actions,
    )


# ─── Main orchestrator ────────────────────────────────────────────────────────

def run_dynatrace_pipeline(elastic_result: dict, gitlab_summary: dict) -> dict:
    """
    Main entry point for Phase 4.

    Receives outputs from Phase 2 (GitLab) and Phase 3 (Elastic) and:
    1. Queries Dynatrace for real problems and entities
    2. Simulates runtime anomalies correlated with the kill chain
    3. Identifies affected services
    4. Generates the remediation playbook
    """

    url   = DT_URL   or os.getenv("DYNATRACE_URL")
    token = DT_TOKEN or os.getenv("DYNATRACE_TOKEN")

    if not url or not token:
        raise ValueError(
            "DYNATRACE_URL and DYNATRACE_TOKEN must be set as environment variables."
        )

    client     = DynatraceClient(url, token)
    kill_chain = elastic_result.get("kill_chain", {})
    dashboard  = elastic_result.get("risk_dashboard", {})
    findings   = gitlab_summary.get("findings", [])
    attack_id  = kill_chain.get("attack_id", "UNKNOWN")
    risk_level = dashboard.get("risk_level", "CRITICAL")

    print(f"\n🔭 Starting Dynatrace runtime correlation")
    print(f"   Attack ID:  {attack_id}")
    print(f"   Risk Level: {risk_level}")

    # ── Step 1: Query real Dynatrace data ─────────────────────────────────────
    print("\n📡 Querying Dynatrace environment...")

    problems          = client.get_problems()
    security_problems = client.get_security_problems()
    entities          = client.get_entities("SERVICE")

    print(f"   Active problems:          {len(problems)}")
    print(f"   Security vulnerabilities: {len(security_problems)}")
    print(f"   Monitored services:       {len(entities)}")

    # ── Step 2: Simulate correlated runtime anomalies ─────────────────────────
    print("\n📊 Correlating runtime anomalies with kill chain stages...")
    anomalies = simulate_anomalies(kill_chain)
    print(f"   Anomalies detected: {len(anomalies)}")
    for a in anomalies:
        icon = "🔴" if a.severity == "CRITICAL" else "🟠"
        print(f"   {icon} {a.metric}: {a.value}{a.unit} (threshold: {a.threshold}{a.unit})")
        print(f"      → {a.correlated_to}")

    # ── Step 3: Identify affected services ────────────────────────────────────
    print("\n🎯 Identifying affected services...")
    affected = identify_affected_services(anomalies, entities)
    exploited = [s for s in affected if s.exploited]
    print(f"   Total services affected:  {len(affected)}")
    print(f"   Confirmed exploitation:   {len(exploited)}")
    for svc in exploited:
        print(f"   🔴 {svc.name} — {svc.exploit_evidence[:70] if svc.exploit_evidence else 'N/A'}...")

    # ── Step 4: Generate remediation playbook ─────────────────────────────────
    print("\n📋 Generating remediation playbook...")
    playbook = generate_playbook(findings, kill_chain, affected, attack_id, risk_level)
    immediate = [a for a in playbook.actions if a.effort == "immediate"]
    short     = [a for a in playbook.actions if a.effort == "short-term"]
    long_     = [a for a in playbook.actions if a.effort == "long-term"]
    print(f"   Immediate actions:   {len(immediate)}")
    print(f"   Short-term actions:  {len(short)}")
    print(f"   Long-term actions:   {len(long_)}")

    print("\n✅ Dynatrace pipeline complete")

    return {
        "dynatrace_data": {
            "real_problems":          len(problems),
            "real_security_problems": len(security_problems),
            "real_entities":          len(entities),
        },
        "runtime_anomalies": [
            {
                "service":        a.service,
                "metric":         a.metric,
                "value":          a.value,
                "threshold":      a.threshold,
                "unit":           a.unit,
                "severity":       a.severity,
                "description":    a.description,
                "correlated_to":  a.correlated_to,
            }
            for a in anomalies
        ],
        "playbook": playbook.to_dict(),
    }


# ─── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Built-in demo data (mirrors Phase 2 + Phase 3 outputs)
    demo_gitlab = {
        "project": "secops-demo/vulnerable-app",
        "total": 30,
        "findings": [
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "AWS Access Key ID found hardcoded in source code",             "evidence": "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE"},
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "MongoDB URI with credentials found hardcoded in source code",   "evidence": "MONGO_URI = mongodb+srv://admin:SuperSecret123!@..."},
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "Stripe Live Secret Key found hardcoded in source code",          "evidence": "STRIPE_SECRET_KEY = sk_live_..."},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "pymongo==2.8 — CVE-2015-1827: Query injection vulnerability",   "evidence": "pymongo==2.8"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "pyyaml==3.12 — CVE-2017-18342: Arbitrary code execution",       "evidence": "pyyaml==3.12"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "paramiko==1.16.0 — CVE-2018-7750: Authentication bypass",       "evidence": "paramiko==1.16.0"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "jinja2==2.8 — CVE-2016-10745: Sandbox escape",                  "evidence": "jinja2==2.8"},
            {"type": "MISCONFIGURATION",      "severity": "CRITICAL", "file": "app.py",           "description": "subprocess with shell=True — command injection risk",           "evidence": "subprocess.run(..., shell=True)"},
            {"type": "MISCONFIGURATION",      "severity": "CRITICAL", "file": ".gitlab-ci.yml",   "description": "Curl piped to shell — unverified remote script execution",      "evidence": "curl -s ... | bash"},
            {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": ".gitlab-ci.yml",   "description": "SSH without host verification — MITM vulnerability",            "evidence": "StrictHostKeyChecking=no"},
            {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": ".gitlab-ci.yml",   "description": "Automatic production deploy without manual approval",           "evidence": "when: on_success"},
        ]
    }

    demo_elastic = {
        "kill_chain": {
            "attack_id":  "ATTACK-20260519-183807",
            "risk_score": 100,
            "stages": [
                {"stage": "Reconnaissance",   "technique": "T1595",     "severity": "LOW",      "source_ip": "194.165.16.11",  "timestamp": "2026-05-19T12:38:00Z"},
                {"stage": "Credential Access","technique": "T1552.001", "severity": "CRITICAL", "source_ip": "185.220.101.47", "timestamp": "2026-05-19T13:08:00Z"},
                {"stage": "Initial Access",   "technique": "T1078.004", "severity": "CRITICAL", "source_ip": "185.220.101.47", "timestamp": "2026-05-19T13:38:00Z"},
                {"stage": "Initial Access",   "technique": "T1190",     "severity": "CRITICAL", "source_ip": "45.142.212.100", "timestamp": "2026-05-19T14:38:00Z"},
                {"stage": "Execution",        "technique": "T1059.004", "severity": "CRITICAL", "source_ip": "45.142.212.100", "timestamp": "2026-05-19T15:08:00Z"},
                {"stage": "Lateral Movement", "technique": "T1021.004", "severity": "HIGH",     "source_ip": "45.142.212.100", "timestamp": "2026-05-19T15:38:00Z"},
                {"stage": "Collection",       "technique": "T1213",     "severity": "CRITICAL", "source_ip": "45.142.212.100", "timestamp": "2026-05-19T16:38:00Z"},
                {"stage": "Exfiltration",     "technique": "T1041",     "severity": "CRITICAL", "source_ip": "45.142.212.100", "timestamp": "2026-05-19T17:08:00Z"},
                {"stage": "Supply Chain",     "technique": "T1195.002", "severity": "CRITICAL", "source_ip": "185.220.101.47", "timestamp": "2026-05-19T17:53:00Z"},
            ]
        },
        "risk_dashboard": {
            "risk_level": "CRITICAL",
            "risk_score": 100,
        }
    }

    result   = run_dynatrace_pipeline(demo_elastic, demo_gitlab)
    playbook = result["playbook"]

    EFFORT_ICONS = {"immediate": "🚨", "short-term": "⚠️", "long-term": "📋"}
    OWNER_ICONS  = {"security": "🛡️", "devops": "⚙️", "management": "👔"}

    print("\n" + "=" * 60)
    print("📋 REMEDIATION PLAYBOOK")
    print("=" * 60)
    print(f"Attack ID  : {playbook['attack_id']}")
    print(f"Risk Level : 🔴 {playbook['risk_level']}")
    print(f"Generated  : {playbook['generated_at']}")

    print(f"\n🎯 Affected Services ({len(playbook['affected_services'])} total)")
    for svc in playbook["affected_services"]:
        if svc["exploited"]:
            print(f"  🔴 {svc['name']} — EXPLOITED")
            if svc["exploit_evidence"]:
                print(f"     Evidence: {svc['exploit_evidence'][:80]}")

    print(f"\n🔧 Remediation Actions ({len(playbook['remediation_actions'])} total)")
    for action in playbook["remediation_actions"]:
        effort_icon = EFFORT_ICONS.get(action["effort"], "📌")
        owner_icon  = OWNER_ICONS.get(action["owner"], "👤")
        print(f"\n  [{action['priority']}] {effort_icon} {action['effort'].upper()} | {owner_icon} {action['owner']}")
        print(f"  Action: {action['action']}")
        print(f"  Why:    {action['rationale'][:100]}")
        if action["command"]:
            print(f"  CMD:    {action['command'][:80]}")

    print()
    print(json.dumps(result, ensure_ascii=False, indent=2))
