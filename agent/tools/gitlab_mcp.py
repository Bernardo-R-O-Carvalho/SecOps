"""
gitlab_mcp.py
SecOps Agent — Phase 2: Vulnerability Scanner via GitLab API

Scans GitLab repositories for:
- Exposed secrets (API keys, tokens, hardcoded passwords)
- Vulnerable dependencies (CVE database cross-reference)
- CI/CD and code misconfigurations

Design decisions:
- Pure GitLab REST API (no SDK) for transparency and portability
- Regex-based secret detection to avoid false negatives from AST parsers
- Local CVE database (no external API calls) for speed and reliability
- Dataclass-based result model for clean serialization to JSON
- Severity enum enforces consistent classification across all scanners
"""

import os
import re
import base64
import httpx
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─── Configuration ────────────────────────────────────────────────────────────

GITLAB_TOKEN    = os.getenv("GITLAB_TOKEN", "")
GITLAB_BASE_URL = "https://gitlab.com/api/v4"
PROJECT_PATH    = "secops-demo/vulnerable-app"


# ─── Data models ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


@dataclass
class Vulnerability:
    type:        str
    severity:    Severity
    file:        str
    description: str
    line:        Optional[int] = None
    evidence:    Optional[str] = None


@dataclass
class ScanResult:
    project:           str
    secrets:           list[Vulnerability] = field(default_factory=list)
    cve_findings:      list[Vulnerability] = field(default_factory=list)
    misconfigurations: list[Vulnerability] = field(default_factory=list)

    def all_findings(self) -> list[Vulnerability]:
        return self.secrets + self.cve_findings + self.misconfigurations

    def summary(self) -> dict:
        findings = self.all_findings()
        severity_order = list(Severity)
        return {
            "project": self.project,
            "total": len(findings),
            "by_severity": {
                s.value: sum(1 for f in findings if f.severity == s)
                for s in Severity
            },
            "findings": [
                {
                    "type":        f.type,
                    "severity":    f.severity.value,
                    "file":        f.file,
                    "description": f.description,
                    "line":        f.line,
                    "evidence":    f.evidence,
                }
                for f in sorted(findings, key=lambda x: severity_order.index(x.severity))
            ]
        }


# ─── GitLab API client ────────────────────────────────────────────────────────

class GitLabClient:
    """
    Minimal GitLab REST API client.
    Uses PRIVATE-TOKEN authentication header.
    Handles both 'main' and 'master' default branches transparently.
    """

    def __init__(self, token: str, base_url: str = GITLAB_BASE_URL):
        self.headers  = {"PRIVATE-TOKEN": token}
        self.base_url = base_url

    def _get(self, endpoint: str, params: dict = None) -> dict | list:
        url      = f"{self.base_url}/{endpoint}"
        response = httpx.get(url, headers=self.headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_project_id(self, project_path: str) -> int:
        encoded = project_path.replace("/", "%2F")
        project = self._get(f"projects/{encoded}")
        return project["id"]

    def list_files(self, project_id: int, ref: str = "main") -> list[dict]:
        """Recursively lists all files in the repository."""
        params = {"ref": ref, "recursive": True, "per_page": 100}
        try:
            return self._get(f"projects/{project_id}/repository/tree", params)
        except Exception:
            params["ref"] = "master"
            return self._get(f"projects/{project_id}/repository/tree", params)

    def get_file_content(self, project_id: int, file_path: str, ref: str = "main") -> str:
        """Returns decoded content of a single file."""
        encoded = file_path.replace("/", "%2F")
        try:
            data = self._get(f"projects/{project_id}/repository/files/{encoded}", {"ref": ref})
        except Exception:
            data = self._get(f"projects/{project_id}/repository/files/{encoded}", {"ref": "master"})
        return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")


# ─── Secret scanner ───────────────────────────────────────────────────────────

# Each entry: (regex_pattern, secret_type_label, severity)
# Patterns ordered from most specific (CRITICAL) to least specific (HIGH)
# to reduce false positives on generic key= patterns.
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}",                                          "AWS Access Key ID",              Severity.CRITICAL),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",   "AWS Secret Access Key",          Severity.CRITICAL),
    (r"sk_live_[0-9a-zA-Z]{24,}",                                  "Stripe Live Secret Key",         Severity.CRITICAL),
    (r"ghp_[0-9a-zA-Z]{36}",                                       "GitHub Personal Access Token",   Severity.CRITICAL),
    (r"glpat-[0-9a-zA-Z\-_]{20,}",                                 "GitLab Personal Access Token",   Severity.CRITICAL),
    (r"mongodb(\+srv)?://[^:]+:[^@]+@",                            "MongoDB URI with credentials",   Severity.CRITICAL),
    (r"postgresql://[^:]+:[^@]+@",                                 "PostgreSQL URI with credentials",Severity.HIGH),
    (r"(?i)jwt.{0,10}secret.{0,10}['\"][^'\"]{8,}['\"]",          "Hardcoded JWT Secret",           Severity.HIGH),
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",     "Hardcoded Password",             Severity.HIGH),
    (r"(?i)(secret|token|key)\s*=\s*['\"][^'\"]{8,}['\"]",        "Hardcoded Secret/Token/Key",     Severity.HIGH),
]


def scan_secrets(content: str, filename: str) -> list[Vulnerability]:
    """
    Line-by-line regex scan for exposed credentials.
    Evidence is truncated at 120 chars to avoid logging full secrets.
    """
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        for pattern, secret_type, severity in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(Vulnerability(
                    type="SECRET_EXPOSED",
                    severity=severity,
                    file=filename,
                    description=f"{secret_type} found hardcoded in source code",
                    line=i,
                    evidence=line.strip()[:120],
                ))
    return findings


# ─── Dependency / CVE scanner ─────────────────────────────────────────────────

# Curated CVE database for demo purposes.
# Structure: { package_name: { affected_version: (cve_id, description, severity) } }
# In production this would be replaced by a live OSV/NVD API call.
CVE_DATABASE: dict[str, dict[str, tuple]] = {
    "flask":        {"0.12.2":  ("CVE-2018-1000656", "Denial of service via crafted JSON",                   Severity.HIGH)},
    "requests":     {"2.6.0":   ("CVE-2015-2296",    "Session fixation vulnerability",                       Severity.HIGH)},
    "pymongo":      {"2.8":     ("CVE-2015-1827",     "Query injection vulnerability",                        Severity.CRITICAL)},
    "pyyaml":       {"3.12":    ("CVE-2017-18342",    "Arbitrary code execution via yaml.load()",            Severity.CRITICAL)},
    "paramiko":     {"1.16.0":  ("CVE-2018-7750",     "Authentication bypass — unauthenticated remote exec", Severity.CRITICAL)},
    "urllib3":      {"1.10.0":  ("CVE-2019-11324",    "Certificate verification bypass",                     Severity.HIGH)},
    "django":       {"1.11.0":  ("CVE-2017-7233",     "Open redirect vulnerability",                         Severity.HIGH)},
    "cryptography": {"1.3.1":   ("CVE-2016-9243",     "HKDF vulnerability — sensitive data exposure",        Severity.HIGH)},
    "pillow":       {"5.2.0":   ("CVE-2019-16865",    "Denial of service via crafted image file",            Severity.MEDIUM)},
    "werkzeug":     {"0.11.10": ("CVE-2019-14806",    "Debug PIN brute-force vulnerability",                 Severity.HIGH)},
    "jinja2":       {"2.8":     ("CVE-2016-10745",    "Sandbox escape — arbitrary code execution",           Severity.CRITICAL)},
    "celery":       {"3.1.18":  ("CVE-2017-18342",    "Arbitrary code execution via YAML config",            Severity.CRITICAL)},
}


def parse_requirements(content: str) -> list[tuple[str, str]]:
    """Extracts (package, version) pairs from requirements.txt format."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_\-]+)==([0-9][^\s#]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2).strip()))
    return packages


def scan_dependencies(content: str, filename: str) -> list[Vulnerability]:
    """Cross-references declared dependencies against the CVE database."""
    findings = []
    for package, version in parse_requirements(content):
        if package in CVE_DATABASE and version in CVE_DATABASE[package]:
            cve_id, description, severity = CVE_DATABASE[package][version]
            findings.append(Vulnerability(
                type="VULNERABLE_DEPENDENCY",
                severity=severity,
                file=filename,
                description=f"{package}=={version} — {cve_id}: {description}",
                evidence=f"{package}=={version}",
            ))
    return findings


# ─── Misconfiguration scanner ─────────────────────────────────────────────────

# Each entry: (regex_pattern, description, severity)
MISCONFIG_PATTERNS = [
    (r"curl\s+.+\|\s*(bash|sh)",          "Curl piped to shell — unverified remote script execution",  Severity.CRITICAL),
    (r"shell\s*=\s*True",                 "subprocess with shell=True — command injection risk",        Severity.CRITICAL),
    (r"StrictHostKeyChecking=no",         "SSH without host verification — MITM vulnerability",         Severity.HIGH),
    (r"(?i)debug\s*[=:]\s*true",         "Debug mode enabled — sensitive data exposure risk",          Severity.HIGH),
    (r"when:\s*on_success",               "Automatic production deploy without manual approval",        Severity.HIGH),
    (r"(?i)user\s+root",                  "Container running as root user",                             Severity.HIGH),
    (r"(?i)chmod\s+777",                  "World-writable permissions (chmod 777)",                     Severity.HIGH),
    (r"allow_failure:\s*true",           "Pipeline continues despite security failures",               Severity.MEDIUM),
    (r"host\s*=\s*['\"]0\.0\.0\.0['\"]", "Service exposed on all network interfaces",                  Severity.MEDIUM),
    (r"FROM\s+\w+\s*$",                   "Docker image without version tag — non-reproducible build", Severity.MEDIUM),
]

MISCONFIG_EXTENSIONS = {".yml", ".yaml", ".py", ".sh", ".tf", ".json"}
MISCONFIG_FILENAMES  = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}


def scan_misconfigurations(content: str, filename: str) -> list[Vulnerability]:
    """Detects insecure patterns in CI/CD configs, Dockerfiles, and source code."""
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        for pattern, description, severity in MISCONFIG_PATTERNS:
            if re.search(pattern, line):
                findings.append(Vulnerability(
                    type="MISCONFIGURATION",
                    severity=severity,
                    file=filename,
                    description=description,
                    line=i,
                    evidence=line.strip()[:120],
                ))
    return findings


# ─── Main orchestrator ────────────────────────────────────────────────────────

def scan_repository(project_path: str = PROJECT_PATH, token: str = None) -> ScanResult:
    """
    Main entry point: scans a full GitLab repository and returns a ScanResult.

    Scanning strategy per file:
    - All files              -> secret scanner
    - requirements.txt etc. -> dependency/CVE scanner
    - .yml/.py/Dockerfile   -> misconfiguration scanner
    """
    token = token or GITLAB_TOKEN
    if not token:
        raise ValueError("GITLAB_TOKEN is not set. Export it as an environment variable.")

    client = GitLabClient(token)
    result = ScanResult(project=project_path)

    print(f"\n🔍 Starting repository scan: {project_path}")

    project_id = client.get_project_id(project_path)
    print(f"   Project ID: {project_id}")

    files      = client.list_files(project_id)
    code_files = [f for f in files if f["type"] == "blob"]
    print(f"   Files found: {len(code_files)}\n")

    dep_files = {"requirements.txt", "Pipfile", "setup.cfg", "pyproject.toml"}

    for file_info in code_files:
        filepath = file_info["path"]
        ext      = os.path.splitext(filepath)[1]
        basename = os.path.basename(filepath)

        print(f"   Scanning: {filepath}")

        try:
            content = client.get_file_content(project_id, filepath)
        except Exception as e:
            print(f"   ⚠️  Could not read {filepath}: {e}")
            continue

        result.secrets.extend(scan_secrets(content, filepath))

        if basename in dep_files:
            result.cve_findings.extend(scan_dependencies(content, filepath))

        if ext in MISCONFIG_EXTENSIONS or basename in MISCONFIG_FILENAMES:
            result.misconfigurations.extend(scan_misconfigurations(content, filepath))

    total = len(result.all_findings())
    print(f"\n✅ Scan complete — {total} vulnerabilities found")
    return result


# ─── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    token = os.getenv("GITLAB_TOKEN")
    if not token:
        print("❌ Set the GITLAB_TOKEN environment variable before running.")
        raise SystemExit(1)

    result  = scan_repository(token=token)
    summary = result.summary()

    SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

    print("\n" + "=" * 60)
    print("📋 VULNERABILITY REPORT")
    print("=" * 60)
    print(f"Project : {summary['project']}")
    print(f"Total   : {summary['total']} vulnerabilities found\n")

    for sev, count in summary["by_severity"].items():
        if count > 0:
            print(f"  {SEVERITY_ICONS.get(sev, '⚪')} {sev}: {count}")

    print()
    for finding in summary["findings"]:
        icon = SEVERITY_ICONS.get(finding["severity"], "⚪")
        loc  = f" (line {finding['line']})" if finding["line"] else ""
        print(f"{icon} [{finding['severity']}] {finding['type']}")
        print(f"   File: {finding['file']}{loc}")
        print(f"   {finding['description']}")
        if finding["evidence"]:
            print(f"   Evidence: {finding['evidence'][:80]}")
        print()

    print(json.dumps(summary, ensure_ascii=False, indent=2))
