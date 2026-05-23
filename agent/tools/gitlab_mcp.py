"""
gitlab_mcp.py
SecOps Agent — Phase 2: Vulnerability Scanner via GitLab API

Scans GitLab repositories for:
- Exposed secrets (API keys, tokens, hardcoded passwords)
- Vulnerable dependencies (Python + Node.js CVE database)
- CI/CD and code misconfigurations

Design decisions:
- Pure GitLab REST API (no SDK) for transparency and portability
- Regex-based secret detection to avoid false negatives from AST parsers
- Expanded local CVE database covering Python AND Node.js ecosystems
- Supports requirements.txt, package.json, package-lock.json, yarn.lock
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
        params = {"ref": ref, "recursive": True, "per_page": 100}
        try:
            return self._get(f"projects/{project_id}/repository/tree", params)
        except Exception:
            params["ref"] = "master"
            return self._get(f"projects/{project_id}/repository/tree", params)

    def get_file_content(self, project_id: int, file_path: str, ref: str = "main") -> str:
        encoded = file_path.replace("/", "%2F")
        try:
            data = self._get(f"projects/{project_id}/repository/files/{encoded}", {"ref": ref})
        except Exception:
            data = self._get(f"projects/{project_id}/repository/files/{encoded}", {"ref": "master"})
        return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")


# ─── Secret scanner ───────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}",                                          "AWS Access Key ID",              Severity.CRITICAL),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",   "AWS Secret Access Key",          Severity.CRITICAL),
    (r"sk_live_[0-9a-zA-Z]{24,}",                                  "Stripe Live Secret Key",         Severity.CRITICAL),
    (r"sk_test_[0-9a-zA-Z]{24,}",                                  "Stripe Test Secret Key",         Severity.HIGH),
    (r"ghp_[0-9a-zA-Z]{36}",                                       "GitHub Personal Access Token",   Severity.CRITICAL),
    (r"glpat-[0-9a-zA-Z\-_]{20,}",                                 "GitLab Personal Access Token",   Severity.CRITICAL),
    (r"mongodb(\+srv)?://[^:]+:[^@]+@",                            "MongoDB URI with credentials",   Severity.CRITICAL),
    (r"postgresql://[^:]+:[^@]+@",                                 "PostgreSQL URI with credentials",Severity.HIGH),
    (r"mysql://[^:]+:[^@]+@",                                      "MySQL URI with credentials",     Severity.HIGH),
    (r"redis://:[^@]+@",                                           "Redis URI with password",        Severity.HIGH),
    (r"(?i)jwt.{0,10}secret.{0,10}['\"][^'\"]{8,}['\"]",          "Hardcoded JWT Secret",           Severity.HIGH),
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",     "Hardcoded Password",             Severity.HIGH),
    (r"(?i)(secret|token|key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",     "Hardcoded Secret/Token/Key",     Severity.HIGH),
    (r"AIza[0-9A-Za-z\-_]{35}",                                    "Google API Key",                 Severity.CRITICAL),
    (r"(?i)slack.{0,10}(token|webhook).{0,10}['\"][xob]-[^\s'\"]{10,}['\"]", "Slack Token",         Severity.HIGH),
    (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",                 "SendGrid API Key",               Severity.HIGH),
    (r"(?i)twilio.{0,20}(sid|token).{0,10}['\"][A-Za-z0-9]{32,}['\"]", "Twilio Credentials",        Severity.HIGH),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",          "Private Key in source code",    Severity.CRITICAL),
]


def scan_secrets(content: str, filename: str) -> list[Vulnerability]:
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


# ─── Python CVE database ──────────────────────────────────────────────────────

PYTHON_CVE_DATABASE: dict[str, dict[str, tuple]] = {
    "flask":        {"0.12.2":  ("CVE-2018-1000656", "Denial of service via crafted JSON",                   Severity.HIGH)},
    "requests":     {"2.6.0":   ("CVE-2015-2296",    "Session fixation vulnerability",                       Severity.HIGH),
                     "2.19.1":  ("CVE-2018-18074",   "Credentials exposure via HTTP redirect",               Severity.MEDIUM)},
    "pymongo":      {"2.8":     ("CVE-2015-1827",     "Query injection vulnerability",                        Severity.CRITICAL)},
    "pyyaml":       {"3.12":    ("CVE-2017-18342",    "Arbitrary code execution via yaml.load()",            Severity.CRITICAL),
                     "5.1":     ("CVE-2019-20477",    "Arbitrary code execution via FullLoader",              Severity.CRITICAL)},
    "paramiko":     {"1.16.0":  ("CVE-2018-7750",     "Authentication bypass — unauthenticated remote exec", Severity.CRITICAL)},
    "urllib3":      {"1.10.0":  ("CVE-2019-11324",    "Certificate verification bypass",                     Severity.HIGH),
                     "1.24.1":  ("CVE-2019-11236",    "CRLF injection via request parameter",                Severity.MEDIUM)},
    "django":       {"1.11.0":  ("CVE-2017-7233",     "Open redirect vulnerability",                         Severity.HIGH),
                     "2.0.0":   ("CVE-2018-7536",     "Denial of service via malformed query",               Severity.MEDIUM),
                     "2.1.0":   ("CVE-2019-3498",     "Content spoofing vulnerability",                      Severity.MEDIUM)},
    "cryptography": {"1.3.1":   ("CVE-2016-9243",     "HKDF vulnerability — sensitive data exposure",        Severity.HIGH)},
    "pillow":       {"5.2.0":   ("CVE-2019-16865",    "Denial of service via crafted image file",            Severity.MEDIUM),
                     "6.2.0":   ("CVE-2020-5310",     "Integer overflow in TIFF image parsing",              Severity.HIGH)},
    "werkzeug":     {"0.11.10": ("CVE-2019-14806",    "Debug PIN brute-force vulnerability",                 Severity.HIGH)},
    "jinja2":       {"2.8":     ("CVE-2016-10745",    "Sandbox escape — arbitrary code execution",           Severity.CRITICAL),
                     "2.10.0":  ("CVE-2019-10906",    "Sandbox escape via str.format_map",                   Severity.HIGH)},
    "celery":       {"3.1.18":  ("CVE-2017-18342",    "Arbitrary code execution via YAML config",            Severity.CRITICAL)},
    "sqlalchemy":   {"1.0.8":   ("CVE-2019-7548",     "SQL injection via order_by parameter",                Severity.HIGH)},
    "lxml":         {"3.6.0":   ("CVE-2018-19787",    "XSS vulnerability via crafted HTML",                  Severity.MEDIUM)},
    "boto3":        {"1.4.0":   ("CVE-2018-15869",    "Credential exposure via instance metadata",           Severity.HIGH)},
    "aiohttp":      {"2.3.0":   ("CVE-2018-1000808",  "HTTP header injection vulnerability",                 Severity.HIGH)},
    "httplib2":     {"0.9.2":   ("CVE-2020-11078",    "CRLF injection vulnerability",                        Severity.HIGH)},
    "scrapy":       {"1.5.0":   ("CVE-2019-12422",    "Cookie injection via response headers",               Severity.MEDIUM)},
    "twisted":      {"18.7.0":  ("CVE-2019-12387",    "HTTP header injection vulnerability",                 Severity.HIGH)},
    "ansible":      {"2.4.0":   ("CVE-2019-10156",    "Information disclosure via template injection",       Severity.MEDIUM)},
}


# ─── Node.js CVE database ─────────────────────────────────────────────────────

NODE_CVE_DATABASE: dict[str, dict[str, tuple]] = {
    "lodash":           {"4.17.4":  ("CVE-2019-10744",  "Prototype pollution via defaultsDeep",              Severity.CRITICAL),
                         "4.17.10": ("CVE-2018-16487",  "Prototype pollution via merge/mergeWith",           Severity.HIGH)},
    "express":          {"4.16.0":  ("CVE-2022-24999",  "Open redirect vulnerability",                       Severity.MEDIUM)},
    "axios":            {"0.18.0":  ("CVE-2019-10742",  "Denial of service via crafted response",            Severity.HIGH),
                         "0.21.0":  ("CVE-2021-3749",   "ReDoS via crafted URL parameter",                   Severity.HIGH)},
    "moment":           {"2.19.0":  ("CVE-2022-24785",  "Path traversal vulnerability",                      Severity.HIGH),
                         "2.24.0":  ("CVE-2022-31129",  "ReDoS via user-controlled date string",             Severity.HIGH)},
    "node-fetch":       {"2.6.0":   ("CVE-2022-0235",   "Exposure of sensitive information via URL redirect", Severity.HIGH)},
    "minimist":         {"1.2.0":   ("CVE-2020-7598",   "Prototype pollution via constructor",               Severity.CRITICAL)},
    "serialize-javascript": {"1.7.0": ("CVE-2020-7660", "Arbitrary code execution via crafted input",        Severity.CRITICAL)},
    "handlebars":       {"4.1.0":   ("CVE-2019-19919",  "Prototype pollution via crafted template",          Severity.CRITICAL)},
    "marked":           {"0.6.0":   ("CVE-2022-21681",  "ReDoS via crafted Markdown",                        Severity.HIGH)},
    "jsonwebtoken":     {"8.3.0":   ("CVE-2022-23529",  "Arbitrary file read via crafted JWT",               Severity.CRITICAL)},
    "ejs":              {"2.6.1":   ("CVE-2022-29078",  "Server-side template injection",                     Severity.CRITICAL)},
    "grunt":            {"1.0.4":   ("CVE-2020-7729",   "Arbitrary code execution via package.json",         Severity.HIGH)},
    "tar":              {"4.4.8":   ("CVE-2021-37701",  "Arbitrary file creation via symlink attack",         Severity.HIGH)},
    "ws":               {"5.2.0":   ("CVE-2021-3807",   "ReDoS via HTTP header",                             Severity.HIGH)},
    "mysql":            {"2.16.0":  ("CVE-2022-21227",  "Denial of service via crafted packet",              Severity.HIGH)},
    "sequelize":        {"5.21.0":  ("CVE-2019-10748",  "SQL injection via order clause",                    Severity.CRITICAL)},
    "mongoose":         {"5.7.0":   ("CVE-2019-17426",  "Prototype pollution via query parameter",           Severity.HIGH)},
    "validator":        {"10.11.0": ("CVE-2021-3765",   "ReDoS via crafted email string",                    Severity.MEDIUM)},
    "sharp":            {"0.26.0":  ("CVE-2021-29063",  "Denial of service via crafted image",               Severity.MEDIUM)},
    "passport":         {"0.4.0":   ("CVE-2022-25896",  "Session fixation vulnerability",                    Severity.HIGH)},
}


def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_\-]+)==([0-9][^\s#]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2).strip()))
    return packages


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """Extracts (package, version) pairs from package.json."""
    import json as _json
    packages = []
    try:
        data = _json.loads(content)
        for section in ["dependencies", "devDependencies"]:
            for pkg, version in data.get(section, {}).items():
                # Clean version string (remove ^, ~, >=, etc.)
                clean = re.sub(r"[^0-9.]", "", version.split("-")[0])
                if clean:
                    packages.append((pkg.lower(), clean))
    except Exception:
        pass
    return packages


def parse_package_lock(content: str) -> list[tuple[str, str]]:
    """Extracts (package, version) pairs from package-lock.json."""
    import json as _json
    packages = []
    try:
        data = _json.loads(content)
        # Support both v1 and v2 lockfile formats
        deps = data.get("dependencies", data.get("packages", {}))
        for name, info in deps.items():
            if isinstance(info, dict) and "version" in info:
                pkg = name.lstrip("node_modules/").split("/")[-1].lower()
                packages.append((pkg, info["version"]))
    except Exception:
        pass
    return packages


def parse_yarn_lock(content: str) -> list[tuple[str, str]]:
    """Extracts (package, version) pairs from yarn.lock."""
    packages = []
    current_pkg = None
    for line in content.splitlines():
        # Match package declaration line: "lodash@^4.17.4:"
        pkg_match = re.match(r'^"?([a-zA-Z0-9@/_\-]+)@', line)
        if pkg_match and line.rstrip().endswith(":"):
            current_pkg = pkg_match.group(1).split("/")[-1].lower()
        # Match version line: "  version "4.17.4""
        ver_match = re.match(r'\s+version\s+"([0-9][^"]+)"', line)
        if ver_match and current_pkg:
            packages.append((current_pkg, ver_match.group(1)))
            current_pkg = None
    return packages


def scan_dependencies(content: str, filename: str) -> list[Vulnerability]:
    """Cross-references declared dependencies against both CVE databases."""
    findings = []
    basename = os.path.basename(filename)

    # Select parser and CVE database based on file type
    if basename == "requirements.txt":
        packages = parse_requirements_txt(content)
        cve_db   = PYTHON_CVE_DATABASE
    elif basename == "package.json":
        packages = parse_package_json(content)
        cve_db   = NODE_CVE_DATABASE
    elif basename == "package-lock.json":
        packages = parse_package_lock(content)
        cve_db   = NODE_CVE_DATABASE
    elif basename == "yarn.lock":
        packages = parse_yarn_lock(content)
        cve_db   = NODE_CVE_DATABASE
    else:
        return findings

    for package, version in packages:
        if package in cve_db and version in cve_db[package]:
            cve_id, description, severity = cve_db[package][version]
            findings.append(Vulnerability(
                type="VULNERABLE_DEPENDENCY",
                severity=severity,
                file=filename,
                description=f"{package}=={version} — {cve_id}: {description}",
                evidence=f"{package}=={version}",
            ))
    return findings


# ─── Misconfiguration scanner ─────────────────────────────────────────────────

MISCONFIG_PATTERNS = [
    (r"curl\s+.+\|\s*(bash|sh)",          "Curl piped to shell — unverified remote script execution",  Severity.CRITICAL),
    (r"shell\s*=\s*True",                 "subprocess with shell=True — command injection risk",        Severity.CRITICAL),
    (r"eval\s*\(",                        "eval() usage — potential code injection",                    Severity.HIGH),
    (r"StrictHostKeyChecking=no",         "SSH without host verification — MITM vulnerability",         Severity.HIGH),
    (r"(?i)debug\s*[=:]\s*true",         "Debug mode enabled — sensitive data exposure risk",          Severity.HIGH),
    (r"when:\s*on_success",               "Automatic production deploy without manual approval",        Severity.HIGH),
    (r"(?i)user\s+root",                  "Container running as root user",                             Severity.HIGH),
    (r"(?i)chmod\s+777",                  "World-writable permissions (chmod 777)",                     Severity.HIGH),
    (r"allow_failure:\s*true",           "Pipeline continues despite security failures",               Severity.MEDIUM),
    (r"host\s*=\s*['\"]0\.0\.0\.0['\"]", "Service exposed on all network interfaces",                  Severity.MEDIUM),
    (r"FROM\s+\w+\s*$",                   "Docker image without version tag — non-reproducible build", Severity.MEDIUM),
    (r"(?i)verify\s*=\s*false",          "SSL/TLS verification disabled",                              Severity.HIGH),
    (r"(?i)ssl_verify\s*=\s*false",      "SSL/TLS verification disabled",                              Severity.HIGH),
    (r"NODE_ENV\s*=\s*['\"]development['\"]", "Development mode in production config",                 Severity.MEDIUM),
    (r"(?i)cors.*origin.*\*",            "CORS wildcard origin — allows any domain",                   Severity.MEDIUM),
    (r"(?i)helmet\s*\(\s*\{\s*\}\s*\)",  "Helmet.js configured with no protections",                  Severity.MEDIUM),
    (r"(?i)xframe.*allow-from.*\*",      "X-Frame-Options allows all origins — clickjacking risk",     Severity.MEDIUM),
    (r"--privileged",                     "Docker container running in privileged mode",                Severity.CRITICAL),
    (r"(?i)no.?verify\s*=\s*true",       "Certificate verification disabled",                          Severity.HIGH),
]

MISCONFIG_EXTENSIONS = {".yml", ".yaml", ".py", ".js", ".ts", ".sh", ".tf", ".json", ".env"}
MISCONFIG_FILENAMES  = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".env", ".env.production"}


def scan_misconfigurations(content: str, filename: str) -> list[Vulnerability]:
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
    token = token or GITLAB_TOKEN
    if not token:
        raise ValueError("GITLAB_TOKEN is not set.")

    client = GitLabClient(token)
    result = ScanResult(project=project_path)

    print(f"\n🔍 Starting repository scan: {project_path}")

    project_id = client.get_project_id(project_path)
    print(f"   Project ID: {project_id}")

    files      = client.list_files(project_id)
    code_files = [f for f in files if f["type"] == "blob"]
    print(f"   Files found: {len(code_files)}\n")

    dep_files = {
        "requirements.txt", "Pipfile", "setup.cfg", "pyproject.toml",
        "package.json", "package-lock.json", "yarn.lock",
    }

    for file_info in code_files:
        filepath = file_info["path"]
        ext      = os.path.splitext(filepath)[1]
        basename = os.path.basename(filepath)

        print(f"   Scanning: {filepath}")

        try:
            content = client.get_file_content(project_id, filepath)
        except Exception as e:
            print(f"   Warning: Could not read {filepath}: {e}")
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
    import json, sys

    token = os.getenv("GITLAB_TOKEN")
    if not token:
        print("Set GITLAB_TOKEN before running.")
        raise SystemExit(1)

    project = sys.argv[1] if len(sys.argv) > 1 else PROJECT_PATH
    result  = scan_repository(project_path=project, token=token)
    summary = result.summary()

    SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

    print("\n" + "=" * 60)
    print("📋 VULNERABILITY REPORT")
    print("=" * 60)
    print(f"Project : {summary['project']}")
    print(f"Total   : {summary['total']} vulnerabilities\n")

    for sev, count in summary["by_severity"].items():
        if count > 0:
            print(f"  {SEVERITY_ICONS.get(sev)} {sev}: {count}")

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
