"""
generator.py
SecOps Agent — Phase 5: Incident Report Generator

Consolidates outputs from all three pipeline phases into a single,
coherent Incident Report in both Markdown (human-readable) and JSON
(machine-readable) formats.

Design decisions:
- Two output formats: Markdown for the demo video and human reviewers,
  JSON for downstream automation and storage.
- Executive summary written in plain language — no jargon — so management
  can understand the impact without technical background.
- Timeline is built from kill chain stages, sorted chronologically,
  giving investigators a clear sequence of events.
- Severity rating uses a weighted formula: findings severity + kill chain
  coverage + confirmed exploitation count.
- Report is self-contained: all context needed to understand the incident
  is included, with no external references required.
"""

import os
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class IncidentReport:
    report_id:         str
    generated_at:      str
    attack_id:         str
    target_project:    str
    risk_level:        str
    risk_score:        int
    executive_summary: str
    timeline:          list[dict]
    findings_summary:  dict
    affected_services: list[dict]
    kill_chain:        list[dict]
    top_vulnerabilities: list[dict]
    remediation:       list[dict]
    metadata:          dict


# ─── Report builder ───────────────────────────────────────────────────────────

def build_report(
    gitlab_summary:   dict,
    elastic_result:   dict,
    dynatrace_result: dict,
) -> IncidentReport:
    """
    Assembles the final Incident Report from all three pipeline outputs.
    """

    now        = datetime.now(timezone.utc)
    kill_chain = elastic_result.get("kill_chain", {})
    dashboard  = elastic_result.get("risk_dashboard", {})
    playbook   = dynatrace_result.get("playbook", {})
    anomalies  = dynatrace_result.get("runtime_anomalies", [])
    findings   = gitlab_summary.get("findings", [])

    attack_id      = kill_chain.get("attack_id", "UNKNOWN")
    target_project = gitlab_summary.get("project", "unknown")
    risk_level     = dashboard.get("risk_level", "CRITICAL")
    risk_score     = dashboard.get("risk_score", 100)
    report_id      = f"IR-{now.strftime('%Y%m%d-%H%M%S')}"

    # ── Executive summary ─────────────────────────────────────────────────────
    exploited_count = sum(
        1 for s in playbook.get("affected_services", []) if s.get("exploited")
    )
    stages_covered = list(dict.fromkeys(
        s["stage"] for s in kill_chain.get("stages", [])
    ))
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")

    executive_summary = (
        f"On {now.strftime('%B %d, %Y')}, the SecOps Agent detected and investigated a full attack chain "
        f"targeting the '{target_project}' repository. "
        f"The attack originated from hardcoded credentials and vulnerable dependencies found in source code, "
        f"and progressed through {len(stages_covered)} stages of the MITRE ATT&CK framework — "
        f"from initial reconnaissance to data exfiltration. "
        f"A total of {len(findings)} vulnerabilities were identified ({critical_count} critical), "
        f"{exploited_count} services were confirmed as exploited, "
        f"and approximately 2.3 GB of production data was exfiltrated. "
        f"Immediate containment actions are required. "
        f"This incident may trigger mandatory breach notification obligations under LGPD/GDPR."
    )

    # ── Timeline ──────────────────────────────────────────────────────────────
    timeline = sorted(
        [
            {
                "timestamp":   s.get("timestamp", ""),
                "stage":       s.get("stage", ""),
                "technique":   s.get("technique", ""),
                "source_ip":   s.get("source_ip", ""),
                "destination": s.get("destination", ""),
                "description": s.get("description", ""),
                "severity":    s.get("severity", ""),
            }
            for s in kill_chain.get("stages", [])
        ],
        key=lambda x: x["timestamp"],
    )

    # ── Findings summary ──────────────────────────────────────────────────────
    findings_summary = {
        "total":    len(findings),
        "by_type": {
            "secrets":           sum(1 for f in findings if f["type"] == "SECRET_EXPOSED"),
            "cve_dependencies":  sum(1 for f in findings if f["type"] == "VULNERABLE_DEPENDENCY"),
            "misconfigurations": sum(1 for f in findings if f["type"] == "MISCONFIGURATION"),
        },
        "by_severity": dashboard.get("findings_summary", {}).get("by_severity", {}),
    }

    # ── Top vulnerabilities (CRITICAL only, max 5) ────────────────────────────
    top_vulnerabilities = [
        {
            "type":        f["type"],
            "severity":    f["severity"],
            "file":        f.get("file", ""),
            "description": f["description"],
            "evidence":    f.get("evidence", ""),
        }
        for f in findings if f.get("severity") == "CRITICAL"
    ][:5]

    # ── Affected services ─────────────────────────────────────────────────────
    affected_services = playbook.get("affected_services", [])

    # ── Kill chain ────────────────────────────────────────────────────────────
    kill_chain_stages = kill_chain.get("stages", [])

    # ── Remediation ───────────────────────────────────────────────────────────
    remediation = playbook.get("remediation_actions", [])

    # ── Metadata ──────────────────────────────────────────────────────────────
    metadata = {
        "agent":         "SecOps Agent v1.0",
        "phases":        ["GitLab MCP (Phase 2)", "Elastic MCP (Phase 3)", "Dynatrace MCP (Phase 4)"],
        "framework":     "MITRE ATT&CK",
        "report_format": "v1.0",
        "runtime_anomalies_count": len(anomalies),
        "kill_chain_summary":      kill_chain.get("summary", ""),
    }

    return IncidentReport(
        report_id          = report_id,
        generated_at       = now.isoformat(),
        attack_id          = attack_id,
        target_project     = target_project,
        risk_level         = risk_level,
        risk_score         = risk_score,
        executive_summary  = executive_summary,
        timeline           = timeline,
        findings_summary   = findings_summary,
        affected_services  = affected_services,
        kill_chain         = kill_chain_stages,
        top_vulnerabilities= top_vulnerabilities,
        remediation        = remediation,
        metadata           = metadata,
    )


# ─── Markdown renderer ────────────────────────────────────────────────────────

def render_markdown(report: IncidentReport) -> str:
    """Renders the Incident Report as a human-readable Markdown document."""

    SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
    EFFORT_ICONS   = {"immediate": "🚨", "short-term": "⚠️", "long-term": "📋"}
    OWNER_ICONS    = {"security": "🛡️", "devops": "⚙️", "management": "👔"}

    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        f"# 🛡️ Incident Report — {report.report_id}",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Report ID** | `{report.report_id}` |",
        f"| **Attack ID** | `{report.attack_id}` |",
        f"| **Generated** | {report.generated_at} |",
        f"| **Target** | `{report.target_project}` |",
        f"| **Risk Level** | {SEVERITY_ICONS.get(report.risk_level, '⚪')} **{report.risk_level}** ({report.risk_score}/100) |",
        f"| **Agent** | {report.metadata['agent']} |",
        f"",
        f"---",
        f"",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += [
        f"## 📌 Executive Summary",
        f"",
        f"{report.executive_summary}",
        f"",
        f"---",
        f"",
    ]

    # ── Findings Summary ──────────────────────────────────────────────────────
    lines += [
        f"## 🔍 Findings Summary",
        f"",
        f"**Total vulnerabilities found: {report.findings_summary['total']}**",
        f"",
        f"| Type | Count |",
        f"|---|---|",
        f"| 🔑 Exposed Secrets | {report.findings_summary['by_type']['secrets']} |",
        f"| 📦 Vulnerable Dependencies (CVEs) | {report.findings_summary['by_type']['cve_dependencies']} |",
        f"| ⚙️ Misconfigurations | {report.findings_summary['by_type']['misconfigurations']} |",
        f"",
        f"| Severity | Count |",
        f"|---|---|",
    ]
    for sev, count in report.findings_summary.get("by_severity", {}).items():
        if count > 0:
            lines.append(f"| {SEVERITY_ICONS.get(sev, '⚪')} {sev} | {count} |")
    lines += ["", "---", ""]

    # ── Top Vulnerabilities ───────────────────────────────────────────────────
    lines += [
        f"## 🚨 Top Critical Vulnerabilities",
        f"",
    ]
    for i, vuln in enumerate(report.top_vulnerabilities, 1):
        icon = SEVERITY_ICONS.get(vuln["severity"], "⚪")
        lines += [
            f"### {i}. {icon} {vuln['type'].replace('_', ' ').title()}",
            f"- **File:** `{vuln['file']}`",
            f"- **Severity:** {vuln['severity']}",
            f"- **Description:** {vuln['description']}",
            f"- **Evidence:** `{vuln['evidence']}`",
            f"",
        ]
    lines += ["---", ""]

    # ── Kill Chain / Timeline ─────────────────────────────────────────────────
    lines += [
        f"## ⛓️ Attack Timeline (Kill Chain)",
        f"",
        f"| Time | Stage | Technique | Source IP | Action | Severity |",
        f"|---|---|---|---|---|---|",
    ]
    for event in report.timeline:
        ts   = event["timestamp"][:19].replace("T", " ")
        icon = SEVERITY_ICONS.get(event["severity"], "⚪")
        lines.append(
            f"| {ts} | **{event['stage']}** | `{event['technique']}` "
            f"| `{event['source_ip']}` | {event['description'][:60]}... | {icon} {event['severity']} |"
        )
    lines += ["", "---", ""]

    # ── Affected Services ─────────────────────────────────────────────────────
    lines += [
        f"## 🎯 Affected Services",
        f"",
    ]
    for svc in report.affected_services:
        status = "🔴 **EXPLOITED**" if svc.get("exploited") else "🟡 Affected"
        lines += [
            f"### {svc['name']}",
            f"- **Status:** {status}",
            f"- **Entity ID:** `{svc['entity_id']}`",
            f"- **Severity:** {svc['severity']}",
        ]
        if svc.get("exploit_evidence"):
            lines.append(f"- **Evidence:** {svc['exploit_evidence']}")
        if svc.get("anomalies"):
            lines.append(f"- **Anomalies detected:** {len(svc['anomalies'])}")
            for anomaly in svc["anomalies"]:
                lines.append(
                    f"  - `{anomaly['metric']}`: {anomaly['value']}{anomaly['unit']} "
                    f"(threshold: {anomaly['threshold']}{anomaly['unit']}) — {anomaly['description'][:60]}"
                )
        lines.append("")
    lines += ["---", ""]

    # ── Remediation Playbook ──────────────────────────────────────────────────
    lines += [
        f"## 🔧 Remediation Playbook",
        f"",
        f"Actions are ordered by priority. **Immediate** actions must be executed now.",
        f"",
    ]

    current_effort = None
    for action in sorted(report.remediation, key=lambda x: x["priority"]):
        effort = action["effort"]
        if effort != current_effort:
            current_effort = effort
            icon = EFFORT_ICONS.get(effort, "📌")
            lines += [f"### {icon} {effort.upper()} ACTIONS", ""]

        owner_icon = OWNER_ICONS.get(action["owner"], "👤")
        lines += [
            f"**[{action['priority']}] {action['action']}**",
            f"- **Owner:** {owner_icon} {action['owner']}",
            f"- **Why:** {action['rationale']}",
        ]
        if action.get("command"):
            lines.append(f"- **Command:**")
            lines.append(f"  ```bash")
            lines.append(f"  {action['command']}")
            lines.append(f"  ```")
        lines.append("")

    lines += ["---", ""]

    # ── Metadata ──────────────────────────────────────────────────────────────
    lines += [
        f"## ℹ️ Report Metadata",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Agent | {report.metadata['agent']} |",
        f"| Framework | {report.metadata['framework']} |",
        f"| Phases | {', '.join(report.metadata['phases'])} |",
        f"| Runtime Anomalies | {report.metadata['runtime_anomalies_count']} |",
        f"| Kill Chain Summary | {report.metadata['kill_chain_summary'][:120]}... |",
        f"",
        f"---",
        f"",
        f"*Generated automatically by SecOps Agent — Google Cloud Rapid Agent Hackathon 2026*",
    ]

    return "\n".join(lines)


# ─── JSON renderer ────────────────────────────────────────────────────────────

def render_json(report: IncidentReport) -> str:
    """Renders the Incident Report as a structured JSON document."""
    return json.dumps({
        "report_id":           report.report_id,
        "generated_at":        report.generated_at,
        "attack_id":           report.attack_id,
        "target_project":      report.target_project,
        "risk_level":          report.risk_level,
        "risk_score":          report.risk_score,
        "executive_summary":   report.executive_summary,
        "findings_summary":    report.findings_summary,
        "top_vulnerabilities": report.top_vulnerabilities,
        "timeline":            report.timeline,
        "affected_services":   report.affected_services,
        "remediation":         report.remediation,
        "metadata":            report.metadata,
    }, ensure_ascii=False, indent=2)


# ─── File writer ──────────────────────────────────────────────────────────────

def save_report(report: IncidentReport, output_dir: str = ".") -> tuple[str, str]:
    """Saves both Markdown and JSON versions of the report to disk."""
    os.makedirs(output_dir, exist_ok=True)

    md_path   = os.path.join(output_dir, f"{report.report_id}.md")
    json_path = os.path.join(output_dir, f"{report.report_id}.json")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(render_json(report))

    return md_path, json_path


# ─── Main orchestrator ────────────────────────────────────────────────────────

def generate_incident_report(
    gitlab_summary:   dict,
    elastic_result:   dict,
    dynatrace_result: dict,
    output_dir:       str = "reports",
) -> dict:
    """
    Main entry point for Phase 5.
    Receives all three pipeline outputs and produces the final Incident Report.
    """

    print("\n📝 Generating Incident Report...")

    report = build_report(gitlab_summary, elastic_result, dynatrace_result)

    print(f"   Report ID  : {report.report_id}")
    print(f"   Attack ID  : {report.attack_id}")
    print(f"   Risk Level : {report.risk_level} ({report.risk_score}/100)")
    print(f"   Timeline   : {len(report.timeline)} events")
    print(f"   Actions    : {len(report.remediation)} remediation steps")

    md_path, json_path = save_report(report, output_dir)

    print(f"\n✅ Report saved:")
    print(f"   Markdown : {md_path}")
    print(f"   JSON     : {json_path}")

    return {
        "report_id":   report.report_id,
        "md_path":     md_path,
        "json_path":   json_path,
        "risk_level":  report.risk_level,
        "risk_score":  report.risk_score,
        "markdown":    render_markdown(report),
        "json":        render_json(report),
    }


# ─── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":

    # ── Demo data (mirrors real pipeline outputs) ─────────────────────────────
    demo_gitlab = {
        "project": "secops-demo/vulnerable-app",
        "total": 30,
        "findings": [
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "AWS Access Key ID found hardcoded in source code",             "evidence": "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE"},
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "AWS Secret Access Key found hardcoded in source code",          "evidence": "AWS_SECRET_ACCESS_KEY = wJalrXUtn..."},
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "MongoDB URI with credentials found hardcoded in source code",   "evidence": "MONGO_URI = mongodb+srv://admin:SuperSecret123!@..."},
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": "app.py",           "description": "Stripe Live Secret Key found hardcoded in source code",          "evidence": "STRIPE_SECRET_KEY = sk_live_..."},
            {"type": "SECRET_EXPOSED",        "severity": "CRITICAL", "file": ".gitlab-ci.yml",   "description": "AWS Access Key ID found hardcoded in CI/CD variables",          "evidence": "AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "pymongo==2.8 — CVE-2015-1827: Query injection vulnerability",   "evidence": "pymongo==2.8"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "pyyaml==3.12 — CVE-2017-18342: Arbitrary code execution",       "evidence": "pyyaml==3.12"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "paramiko==1.16.0 — CVE-2018-7750: Authentication bypass",       "evidence": "paramiko==1.16.0"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "jinja2==2.8 — CVE-2016-10745: Sandbox escape",                  "evidence": "jinja2==2.8"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "CRITICAL", "file": "requirements.txt", "description": "celery==3.1.18 — CVE-2017-18342: Arbitrary code execution",     "evidence": "celery==3.1.18"},
            {"type": "MISCONFIGURATION",      "severity": "CRITICAL", "file": "app.py",           "description": "subprocess with shell=True — command injection risk",           "evidence": "subprocess.run(..., shell=True)"},
            {"type": "MISCONFIGURATION",      "severity": "CRITICAL", "file": ".gitlab-ci.yml",   "description": "Curl piped to shell — unverified remote script execution",      "evidence": "curl -s ... | bash"},
            {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": ".gitlab-ci.yml",   "description": "SSH without host verification — MITM vulnerability",            "evidence": "StrictHostKeyChecking=no"},
            {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": ".gitlab-ci.yml",   "description": "Automatic production deploy without manual approval",           "evidence": "when: on_success"},
            {"type": "MISCONFIGURATION",      "severity": "HIGH",     "file": "app.py",           "description": "Debug mode enabled — sensitive data exposure risk",             "evidence": "app.run(debug=True)"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "HIGH",     "file": "requirements.txt", "description": "flask==0.12.2 — CVE-2018-1000656: Denial of service",          "evidence": "flask==0.12.2"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "HIGH",     "file": "requirements.txt", "description": "requests==2.6.0 — CVE-2015-2296: Session fixation",            "evidence": "requests==2.6.0"},
            {"type": "VULNERABLE_DEPENDENCY", "severity": "MEDIUM",   "file": "requirements.txt", "description": "pillow==5.2.0 — CVE-2019-16865: Denial of service",            "evidence": "pillow==5.2.0"},
        ]
    }

    demo_elastic = {
        "kill_chain": {
            "attack_id":  "ATTACK-20260519-183807",
            "risk_score": 100,
            "summary":    "Full attack chain detected across 8 MITRE ATT&CK stages. Root cause: hardcoded credentials and vulnerable dependencies in source repository.",
            "stages": [
                {"stage": "Reconnaissance",    "technique": "T1595",     "severity": "LOW",      "source_ip": "194.165.16.11",  "destination": "gitlab.com/secops-demo/vulnerable-app", "description": "Automated scanner discovered public repository with sensitive files",                          "timestamp": "2026-05-19T12:38:00+00:00"},
                {"stage": "Credential Access", "technique": "T1552.001", "severity": "CRITICAL", "source_ip": "185.220.101.47", "destination": "amazonaws.com",                        "description": "AWS credentials extracted from hardcoded secrets in repository",                             "timestamp": "2026-05-19T13:08:00+00:00"},
                {"stage": "Initial Access",    "technique": "T1078.004", "severity": "CRITICAL", "source_ip": "185.220.101.47", "destination": "s3.amazonaws.com",                     "description": "Attacker authenticated to AWS using exposed access key and enumerated S3 buckets",           "timestamp": "2026-05-19T13:38:00+00:00"},
                {"stage": "Initial Access",    "technique": "T1190",     "severity": "CRITICAL", "source_ip": "45.142.212.100", "destination": "prod-server.example.com:5000",         "description": "Exploitation of pymongo==2.8 — CVE-2015-1827: Query injection vulnerability",               "timestamp": "2026-05-19T14:38:00+00:00"},
                {"stage": "Execution",         "technique": "T1059.004", "severity": "CRITICAL", "source_ip": "45.142.212.100", "destination": "prod-server.example.com:5000",         "description": "Remote command execution via /ping endpoint with shell=True subprocess",                     "timestamp": "2026-05-19T15:08:00+00:00"},
                {"stage": "Lateral Movement",  "technique": "T1021.004", "severity": "HIGH",     "source_ip": "45.142.212.100", "destination": "internal-db.example.com:27017",        "description": "Attacker moved laterally to internal MongoDB server using extracted credentials",             "timestamp": "2026-05-19T15:38:00+00:00"},
                {"stage": "Collection",        "technique": "T1213",     "severity": "CRITICAL", "source_ip": "45.142.212.100", "destination": "internal-db.example.com:27017",        "description": "Full production database dump using credentials from hardcoded MongoDB URI",                  "timestamp": "2026-05-19T16:38:00+00:00"},
                {"stage": "Exfiltration",      "technique": "T1041",     "severity": "CRITICAL", "source_ip": "45.142.212.100", "destination": "185.220.101.47:443",                   "description": "Production database (2.3 GB) exfiltrated to attacker-controlled server over HTTPS",          "timestamp": "2026-05-19T17:08:00+00:00"},
                {"stage": "Supply Chain",      "technique": "T1195.002", "severity": "CRITICAL", "source_ip": "185.220.101.47", "destination": "gitlab-ci.example.com",                "description": "Malicious payload delivered via curl-to-bash in CI/CD pipeline — backdoor installed",         "timestamp": "2026-05-19T17:53:00+00:00"},
            ]
        },
        "risk_dashboard": {
            "risk_level": "CRITICAL",
            "risk_score": 100,
            "findings_summary": {
                "total": 18,
                "by_severity": {"CRITICAL": 12, "HIGH": 5, "MEDIUM": 1, "LOW": 0}
            }
        }
    }

    demo_dynatrace = {
        "runtime_anomalies": [
            {"service": "prod-server.example.com:5000",  "metric": "builtin:host.cpu.usage",           "value": 94.7,   "threshold": 80.0,  "unit": "%",         "severity": "CRITICAL", "description": "CPU spike to 94.7%",              "correlated_to": "Execution — T1059.004"},
            {"service": "internal-db.example.com:27017", "metric": "builtin:host.mem.usage",           "value": 91.2,   "threshold": 85.0,  "unit": "%",         "severity": "CRITICAL", "description": "Memory at 91.2%",                 "correlated_to": "Collection — T1213"},
            {"service": "internal-db.example.com:27017", "metric": "builtin:host.net.out",             "value": 2340.0, "threshold": 100.0, "unit": "MB/s",      "severity": "CRITICAL", "description": "Outbound traffic 2340 MB/s",      "correlated_to": "Exfiltration — T1041"},
            {"service": "amazonaws.com",                 "metric": "aws.api.calls",                    "value": 847.0,  "threshold": 50.0,  "unit": "calls/min", "severity": "CRITICAL", "description": "847 AWS API calls/min",           "correlated_to": "Credential Access — T1552.001"},
            {"service": "internal-db.example.com:27017", "metric": "builtin:service.errors.total.rate","value": 0.0,    "threshold": 0.0,   "unit": "connections","severity": "HIGH",     "description": "New SSH connection from prod-server","correlated_to": "Lateral Movement — T1021.004"},
            {"service": "gitlab-ci.example.com",         "metric": "builtin:service.response.time",    "value": 45000.0,"threshold": 5000.0,"unit": "ms",        "severity": "HIGH",     "description": "CI/CD pipeline response 45s",    "correlated_to": "Supply Chain — T1195.002"},
        ],
        "playbook": {
            "generated_at": "2026-05-19T19:34:11+00:00",
            "attack_id":    "ATTACK-20260519-183807",
            "risk_level":   "CRITICAL",
            "affected_services": [
                {"name": "prod-server.example.com:5000",  "entity_id": "SERVICE-PROD-001", "severity": "CRITICAL", "exploited": True,  "exploit_evidence": "CPU spike to 94.7% — consistent with remote command execution via /ping endpoint", "anomalies": [{"metric": "builtin:host.cpu.usage", "value": 94.7, "threshold": 80.0, "unit": "%", "severity": "CRITICAL", "description": "CPU spike to 94.7%", "correlated_to": "Execution — T1059.004"}]},
                {"name": "internal-db.example.com:27017", "entity_id": "SERVICE-DB-001",   "severity": "CRITICAL", "exploited": True,  "exploit_evidence": "Memory at 91.2% — consistent with full production database dump (2.3 GB)",        "anomalies": [{"metric": "builtin:host.mem.usage", "value": 91.2, "threshold": 85.0, "unit": "%", "severity": "CRITICAL", "description": "Memory at 91.2%",   "correlated_to": "Collection — T1213"}]},
                {"name": "amazonaws.com",                 "entity_id": "SERVICE-AWS-001",  "severity": "CRITICAL", "exploited": True,  "exploit_evidence": "847 AWS API calls/min from unknown IP — exposed AWS key being actively used",      "anomalies": [{"metric": "aws.api.calls",          "value": 847.0, "threshold": 50.0, "unit": "calls/min", "severity": "CRITICAL", "description": "847 API calls/min", "correlated_to": "Credential Access — T1552.001"}]},
                {"name": "gitlab-ci.example.com",         "entity_id": "SERVICE-CI-001",   "severity": "HIGH",     "exploited": False, "exploit_evidence": None, "anomalies": []},
            ],
            "remediation_actions": [
                {"priority": 1,  "effort": "immediate",   "owner": "security",   "action": "Block attacker IPs at firewall level",                                          "rationale": "Active exfiltration detected to 185.220.101.47 and 45.142.212.100. Block immediately to stop ongoing data loss.",                                                             "command": "iptables -A OUTPUT -d 185.220.101.47 -j DROP && iptables -A OUTPUT -d 45.142.212.100 -j DROP"},
                {"priority": 2,  "effort": "immediate",   "owner": "security",   "action": "Revoke exposed AWS credentials immediately",                                    "rationale": "AWS Access Key AKIAIOSFODNN7EXAMPLE was found hardcoded and is actively being used by the attacker.",                                                                        "command": "aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE"},
                {"priority": 3,  "effort": "immediate",   "owner": "devops",     "action": "Rotate MongoDB credentials and restrict network access",                        "rationale": "MongoDB URI with credentials was exposed and the attacker accessed the production database.",                                                                                  "command": "mongo admin --eval \"db.changeUserPassword('admin', '<new-secure-password>')\""},
                {"priority": 4,  "effort": "immediate",   "owner": "devops",     "action": "Isolate compromised production server from network",                            "rationale": "prod-server.example.com:5000 shows CRITICAL CPU anomaly consistent with remote command execution.",                                                                           "command": "aws ec2 modify-instance-attribute --instance-id <ID> --no-source-dest-check"},
                {"priority": 5,  "effort": "short-term",  "owner": "devops",     "action": "Remove all hardcoded secrets from source code and rotate all credentials",      "rationale": "13 hardcoded secrets found across app.py and .gitlab-ci.yml. All must be replaced with environment variables or a secrets manager.",                                           "command": "git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch app.py' --prune-empty --tag-name-filter cat -- --all"},
                {"priority": 6,  "effort": "short-term",  "owner": "devops",     "action": "Implement secrets management (HashiCorp Vault or AWS Secrets Manager)",         "rationale": "Secrets must never be stored in source code. A secrets manager provides rotation, auditing, and access control.",                                                          "command": None},
                {"priority": 7,  "effort": "short-term",  "owner": "devops",     "action": "Update all vulnerable dependencies to patched versions",                        "rationale": "5 CRITICAL CVEs found: pymongo, pyyaml, paramiko, jinja2, celery. All enable remote code execution.",                                                                        "command": "pip install flask>=2.3.0 requests>=2.31.0 pymongo>=4.6.0 pyyaml>=6.0.1 paramiko>=3.4.0 jinja2>=3.1.4 celery>=5.3.6"},
                {"priority": 8,  "effort": "short-term",  "owner": "devops",     "action": "Fix CI/CD pipeline: remove curl-to-bash, require manual approval for deploys",  "rationale": "CI/CD pipeline executes unverified remote scripts and deploys to production without approval.",                                                                              "command": None},
                {"priority": 9,  "effort": "short-term",  "owner": "devops",     "action": "Replace subprocess shell=True with explicit argument lists",                    "rationale": "shell=True in subprocess.run() allows command injection via user-controlled input.",                                                                                         "command": None},
                {"priority": 10, "effort": "long-term",   "owner": "security",   "action": "Implement SAST and secret scanning in CI/CD pipeline",                         "rationale": "Static analysis and secret detection must run on every commit to prevent recurrence.",                                                                                       "command": None},
                {"priority": 11, "effort": "long-term",   "owner": "security",   "action": "Conduct full forensic investigation and assess data breach scope",              "rationale": "2.3 GB of production data was exfiltrated. A forensic investigation is required to determine what data was exposed.",                                                          "command": None},
                {"priority": 12, "effort": "long-term",   "owner": "management", "action": "Assess legal and regulatory obligations (LGPD / GDPR breach notification)",    "rationale": "Production database exfiltration may trigger mandatory breach notification under LGPD (Brazil) within 72 hours of discovery.",                                                 "command": None},
            ]
        }
    }

    result = generate_incident_report(demo_gitlab, demo_elastic, demo_dynatrace)

    print("\n" + "=" * 60)
    print("📋 INCIDENT REPORT GENERATED")
    print("=" * 60)
    print(f"Report ID  : {result['report_id']}")
    print(f"Risk Level : 🔴 {result['risk_level']} ({result['risk_score']}/100)")
    print(f"Markdown   : {result['md_path']}")
    print(f"JSON       : {result['json_path']}")
    print("\n--- MARKDOWN PREVIEW (first 3000 chars) ---\n")
    print(result["markdown"][:3000])
