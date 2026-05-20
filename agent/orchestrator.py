"""
orchestrator.py
SecOps Agent — Main Orchestrator

Runs the full security pipeline end-to-end with a single command:

  Phase 2 (GitLab)    → scan repository for vulnerabilities
  Phase 3 (Elastic)   → detect attack patterns and build kill chain
  Phase 4 (Dynatrace) → correlate runtime anomalies and generate playbook
  Phase 5 (Report)    → consolidate everything into an Incident Report

Design decisions:
- Each phase is imported as a module and called sequentially, with the
  output of each phase passed as input to the next.
- All credentials are loaded from environment variables — never hardcoded.
- The orchestrator prints a clear progress banner between phases so the
  demo video has natural visual breakpoints.
- On any phase failure, the orchestrator stops and prints a clear error
  message indicating which phase failed and why.
- A final summary is printed at the end with paths to all output files.
"""

import os
import sys
import json
import time
from datetime import datetime, timezone

# Add project root to path so modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tools.gitlab_mcp    import scan_repository
from agent.tools.elastic_mcp   import run_elastic_pipeline
from agent.tools.dynatrace_mcp import run_dynatrace_pipeline
from agent.report.generator    import generate_incident_report


# ─── Banner helpers ───────────────────────────────────────────────────────────

def banner(title: str, phase: str = "") -> None:
    print("\n" + "=" * 60)
    if phase:
        print(f"  {phase}")
    print(f"  {title}")
    print("=" * 60)


def success(msg: str) -> None:
    print(f"\n✅ {msg}")


def fail(msg: str) -> None:
    print(f"\n❌ {msg}")


# ─── Credential loader ────────────────────────────────────────────────────────

def load_credentials() -> dict:
    """
    Loads all required credentials from environment variables.
    Raises ValueError if any required credential is missing.
    """
    required = {
        "GITLAB_TOKEN":    "GitLab Personal Access Token",
        "ELASTIC_URL":     "Elasticsearch cluster URL",
        "ELASTIC_API_KEY": "Elasticsearch API key",
        "DYNATRACE_URL":   "Dynatrace environment URL",
        "DYNATRACE_TOKEN": "Dynatrace API token",
    }

    missing = []
    creds   = {}

    for env_var, description in required.items():
        value = os.getenv(env_var)
        if not value:
            missing.append(f"  - {env_var} ({description})")
        else:
            creds[env_var] = value

    if missing:
        raise ValueError(
            "Missing required environment variables:\n" +
            "\n".join(missing) +
            "\n\nSet them before running the orchestrator."
        )

    return creds


# ─── Main pipeline ────────────────────────────────────────────────────────────

def run_pipeline(project_path: str = "secops-demo/vulnerable-app") -> dict:
    """
    Runs the full SecOps Agent pipeline end-to-end.

    Args:
        project_path: GitLab namespace/project to scan (default: demo repo)

    Returns:
        dict with paths to all generated output files and a summary.
    """

    started_at = datetime.now(timezone.utc)

    # ── Header ────────────────────────────────────────────────────────────────
    print("\n" + "🛡️  " * 20)
    print("\n  SECOPS AGENT — Autonomous Security Operations")
    print(f"  Target: {project_path}")
    print(f"  Started: {started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("\n" + "🛡️  " * 20)

    # ── Load credentials ──────────────────────────────────────────────────────
    print("\n🔑 Loading credentials...")
    try:
        creds = load_credentials()
        print(f"   ✅ All credentials loaded ({len(creds)} variables)")
    except ValueError as e:
        fail(str(e))
        raise SystemExit(1)

    results = {}

    # ── Phase 2: GitLab scan ──────────────────────────────────────────────────
    banner("PHASE 2 — Repository Scan", "🔍 GitLab MCP")
    phase2_start = time.time()

    try:
        scan_result    = scan_repository(
            project_path = project_path,
            token        = creds["GITLAB_TOKEN"],
        )
        gitlab_summary = scan_result.summary()
        results["gitlab"] = gitlab_summary

        elapsed = time.time() - phase2_start
        success(
            f"Phase 2 complete in {elapsed:.1f}s — "
            f"{gitlab_summary['total']} vulnerabilities found "
            f"({gitlab_summary['by_severity'].get('CRITICAL', 0)} critical)"
        )

    except Exception as e:
        fail(f"Phase 2 failed: {e}")
        raise SystemExit(1)

    # ── Phase 3: Elastic detection ────────────────────────────────────────────
    banner("PHASE 3 — Threat Detection", "⚡ Elastic MCP")
    phase3_start = time.time()

    try:
        os.environ["ELASTIC_URL"]     = creds["ELASTIC_URL"]
        os.environ["ELASTIC_API_KEY"] = creds["ELASTIC_API_KEY"]

        elastic_result    = run_elastic_pipeline(gitlab_summary)
        results["elastic"] = elastic_result

        elapsed    = time.time() - phase3_start
        kill_chain = elastic_result.get("kill_chain", {})
        stages     = list(dict.fromkeys(
            s["stage"] for s in kill_chain.get("stages", [])
        ))
        success(
            f"Phase 3 complete in {elapsed:.1f}s — "
            f"Kill chain: {' → '.join(stages[:4])}..."
        )

    except Exception as e:
        fail(f"Phase 3 failed: {e}")
        raise SystemExit(1)

    # ── Phase 4: Dynatrace correlation ────────────────────────────────────────
    banner("PHASE 4 — Runtime Correlation", "🔭 Dynatrace MCP")
    phase4_start = time.time()

    try:
        os.environ["DYNATRACE_URL"]   = creds["DYNATRACE_URL"]
        os.environ["DYNATRACE_TOKEN"] = creds["DYNATRACE_TOKEN"]

        dynatrace_result    = run_dynatrace_pipeline(elastic_result, gitlab_summary)
        results["dynatrace"] = dynatrace_result

        elapsed   = time.time() - phase4_start
        playbook  = dynatrace_result.get("playbook", {})
        exploited = sum(
            1 for s in playbook.get("affected_services", []) if s.get("exploited")
        )
        actions = len(playbook.get("remediation_actions", []))
        success(
            f"Phase 4 complete in {elapsed:.1f}s — "
            f"{exploited} services exploited, {actions} remediation actions generated"
        )

    except Exception as e:
        fail(f"Phase 4 failed: {e}")
        raise SystemExit(1)

    # ── Phase 5: Incident Report ──────────────────────────────────────────────
    banner("PHASE 5 — Incident Report", "📋 Report Generator")
    phase5_start = time.time()

    try:
        report_result    = generate_incident_report(
            gitlab_summary   = gitlab_summary,
            elastic_result   = elastic_result,
            dynatrace_result = dynatrace_result,
            output_dir       = "reports",
        )
        results["report"] = report_result

        elapsed = time.time() - phase5_start
        success(
            f"Phase 5 complete in {elapsed:.1f}s — "
            f"Report {report_result['report_id']} saved"
        )

    except Exception as e:
        fail(f"Phase 5 failed: {e}")
        raise SystemExit(1)

    # ── Final summary ─────────────────────────────────────────────────────────
    total_elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()

    banner("PIPELINE COMPLETE", "🎯 SecOps Agent")
    print(f"""
  Target project : {project_path}
  Risk level     : 🔴 {report_result['risk_level']} ({report_result['risk_score']}/100)
  Total time     : {total_elapsed:.1f}s
  Report ID      : {report_result['report_id']}

  Output files:
    📄 Markdown  : {report_result['md_path']}
    📊 JSON      : {report_result['json_path']}

  Summary:
    🔍 Vulnerabilities found : {gitlab_summary['total']}
       🔴 Critical           : {gitlab_summary['by_severity'].get('CRITICAL', 0)}
       🟠 High               : {gitlab_summary['by_severity'].get('HIGH', 0)}
       🟡 Medium             : {gitlab_summary['by_severity'].get('MEDIUM', 0)}
    ⛓️  Kill chain stages    : {len(kill_chain.get('stages', []))}
    🎯 Services exploited   : {exploited}
    🔧 Remediation actions  : {actions}
""")

    return results


# ─── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    project = sys.argv[1] if len(sys.argv) > 1 else "secops-demo/vulnerable-app"
    run_pipeline(project_path=project)
