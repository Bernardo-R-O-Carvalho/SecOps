"""
main.py
SecOps Agent — Web UI + API

FastAPI backend that serves the web interface and exposes the pipeline
as a REST API. The frontend is embedded as a single HTML string to keep
the deployment simple (one file, one process, one Cloud Run container).

Endpoints:
  GET  /          → serves the web UI
  POST /scan      → runs the full pipeline and streams progress via SSE
  GET  /health    → health check for Cloud Run
"""

import os
import sys
import json
import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(title="SecOps Agent", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory report store (keyed by report_id)
_report_store: dict = {}


# ─── Request model ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    project_path: str = "secops-demo/vulnerable-app"


# ─── HTML UI ──────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecOps Agent</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #050810;
    --bg2:       #090d1a;
    --panel:     #0c1120;
    --border:    #1a2540;
    --accent:    #00f5d4;
    --accent2:   #f72585;
    --accent3:   #7209b7;
    --text:      #c8d8f0;
    --text-dim:  #4a6080;
    --red:       #ff3860;
    --orange:    #ff8c42;
    --yellow:    #ffd166;
    --green:     #06d6a0;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Rajdhani', sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,245,212,0.015) 2px,
      rgba(0,245,212,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* Grid background */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,245,212,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,245,212,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 24px;
  }

  /* ── Header ── */
  header {
    display: flex;
    align-items: center;
    gap: 20px;
    margin-bottom: 48px;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--border);
  }

  .logo {
    width: 52px;
    height: 52px;
    background: linear-gradient(135deg, var(--accent3), var(--accent));
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    flex-shrink: 0;
    box-shadow: 0 0 30px rgba(0,245,212,0.3);
  }

  .header-text h1 {
    font-family: var(--sans);
    font-size: 28px;
    font-weight: 700;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #fff;
  }

  .header-text p {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--accent);
    letter-spacing: 2px;
    margin-top: 2px;
  }

  .header-badge {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-dim);
    text-align: right;
    line-height: 1.6;
  }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border: 1px solid var(--accent);
    color: var(--accent);
    border-radius: 3px;
    font-size: 10px;
    letter-spacing: 1px;
  }

  /* ── Input panel ── */
  .input-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
  }

  .input-panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent3), var(--accent), transparent);
  }

  .input-label {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 10px;
  }

  .input-row {
    display: flex;
    gap: 12px;
    align-items: center;
  }

  input[type="text"] {
    flex: 1;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
  }

  input[type="text"]:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(0,245,212,0.08);
  }

  .btn-scan {
    background: linear-gradient(135deg, var(--accent3), var(--accent));
    border: none;
    border-radius: 8px;
    padding: 14px 32px;
    color: #000;
    font-family: var(--sans);
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .btn-scan:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 8px 24px rgba(0,245,212,0.3);
  }

  .btn-scan:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* ── Stats bar ── */
  .stats-bar {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 28px;
    opacity: 0;
    transition: opacity 0.4s;
  }

  .stats-bar.visible { opacity: 1; }

  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
  }

  .stat-value {
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 4px;
  }

  .stat-label {
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--text-dim);
  }

  .stat-critical .stat-value { color: var(--red); }
  .stat-high     .stat-value { color: var(--orange); }
  .stat-stages   .stat-value { color: var(--accent); }
  .stat-score    .stat-value { color: var(--accent2); }

  /* ── Terminal ── */
  .terminal {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 28px;
  }

  .terminal-header {
    background: var(--panel);
    padding: 10px 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid var(--border);
  }

  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot-red    { background: #ff5f57; }
  .dot-yellow { background: #ffbd2e; }
  .dot-green  { background: #28c840; }

  .terminal-title {
    margin-left: 8px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-dim);
  }

  .terminal-body {
    padding: 20px;
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.7;
    min-height: 200px;
    max-height: 420px;
    overflow-y: auto;
  }

  .terminal-body::-webkit-scrollbar { width: 4px; }
  .terminal-body::-webkit-scrollbar-track { background: transparent; }
  .terminal-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .log-line { display: block; animation: fadeIn 0.2s ease; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }

  .log-phase   { color: var(--accent); font-weight: bold; }
  .log-success { color: var(--green); }
  .log-warning { color: var(--yellow); }
  .log-error   { color: var(--red); }
  .log-info    { color: var(--text); }
  .log-dim     { color: var(--text-dim); }

  .cursor {
    display: inline-block;
    width: 8px;
    height: 14px;
    background: var(--accent);
    animation: blink 1s infinite;
    vertical-align: middle;
    margin-left: 4px;
  }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }

  /* ── Phase progress ── */
  .phases {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 28px;
  }

  .phase-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
    transition: all 0.3s;
  }

  .phase-card.active {
    border-color: var(--accent);
    box-shadow: 0 0 20px rgba(0,245,212,0.15);
  }

  .phase-card.done {
    border-color: var(--green);
    box-shadow: 0 0 20px rgba(6,214,160,0.1);
  }

  .phase-icon { font-size: 24px; margin-bottom: 8px; }

  .phase-name {
    font-family: var(--sans);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 4px;
  }

  .phase-card.active .phase-name { color: var(--accent); }
  .phase-card.done   .phase-name { color: var(--green); }

  .phase-status {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-dim);
  }

  .phase-card.active .phase-status { color: var(--accent); }
  .phase-card.done   .phase-status { color: var(--green); }

  /* ── Report panel ── */
  .report-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    display: none;
  }

  .report-panel.visible { display: block; }

  .report-header {
    background: linear-gradient(135deg, rgba(114,9,183,0.3), rgba(0,245,212,0.1));
    padding: 20px 28px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .report-title {
    font-family: var(--sans);
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #fff;
  }

  .risk-badge {
    padding: 6px 16px;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 13px;
    font-weight: bold;
    letter-spacing: 2px;
  }

  .risk-CRITICAL { background: rgba(255,56,96,0.2); color: var(--red); border: 1px solid var(--red); }
  .risk-HIGH     { background: rgba(255,140,66,0.2); color: var(--orange); border: 1px solid var(--orange); }

  .report-body { padding: 28px; }

  .report-section { margin-bottom: 28px; }

  .section-title {
    font-family: var(--sans);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .summary-text {
    font-size: 15px;
    line-height: 1.7;
    color: var(--text);
  }

  .kill-chain {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }

  .chain-stage {
    background: rgba(0,245,212,0.08);
    border: 1px solid rgba(0,245,212,0.2);
    border-radius: 4px;
    padding: 4px 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--accent);
  }

  .chain-arrow { color: var(--text-dim); font-size: 16px; }

  .vuln-list { display: flex; flex-direction: column; gap: 8px; }

  .vuln-item {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }

  .vuln-sev {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 1px;
    padding: 2px 8px;
    border-radius: 3px;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .sev-CRITICAL { background: rgba(255,56,96,0.15); color: var(--red); border: 1px solid rgba(255,56,96,0.3); }
  .sev-HIGH     { background: rgba(255,140,66,0.15); color: var(--orange); border: 1px solid rgba(255,140,66,0.3); }

  .vuln-desc { font-size: 13px; color: var(--text); }
  .vuln-file { font-family: var(--mono); font-size: 11px; color: var(--text-dim); margin-top: 2px; }

  .action-list { display: flex; flex-direction: column; gap: 8px; }

  .action-item {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    display: flex;
    gap: 12px;
    align-items: flex-start;
  }

  .action-priority {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-dim);
    white-space: nowrap;
    flex-shrink: 0;
  }

  .action-effort-immediate { color: var(--red); }
  .action-effort-short     { color: var(--orange); }
  .action-effort-long      { color: var(--yellow); }

  .action-text { font-size: 13px; color: var(--text); }

  .download-btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: transparent;
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 8px 20px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
    text-decoration: none;
  }

  .download-btn:hover {
    background: rgba(0,245,212,0.08);
    box-shadow: 0 0 16px rgba(0,245,212,0.2);
  }

  /* Spinner */
  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid rgba(0,245,212,0.2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    vertical-align: middle;
    margin-right: 6px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 700px) {
    .stats-bar, .phases { grid-template-columns: repeat(2, 1fr); }
    .input-row { flex-direction: column; }
    .btn-scan { width: 100%; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header>
    <div class="logo">🛡️</div>
    <div class="header-text">
      <h1>SecOps Agent</h1>
      <p>AUTONOMOUS SECURITY OPERATIONS</p>
    </div>
    <div class="header-badge">
      <div><span class="badge">MITRE ATT&CK</span></div>
      <div style="margin-top:6px">Google Cloud Rapid Agent Hackathon 2026</div>
    </div>
  </header>

  <!-- Input -->
  <div class="input-panel">
    <div class="input-label">// Target Repository</div>
    <div class="input-row">
      <input type="text" id="project-input" value="secops-demo/vulnerable-app"
        placeholder="namespace/repository">
      <button class="btn-scan" id="scan-btn" onclick="startScan()">
        ▶ RUN AGENT
      </button>
    </div>
  </div>

  <!-- Phase progress -->
  <div class="phases">
    <div class="phase-card" id="phase-2">
      <div class="phase-icon">🔍</div>
      <div class="phase-name">GitLab MCP</div>
      <div class="phase-status">Waiting</div>
    </div>
    <div class="phase-card" id="phase-3">
      <div class="phase-icon">⚡</div>
      <div class="phase-name">Elastic MCP</div>
      <div class="phase-status">Waiting</div>
    </div>
    <div class="phase-card" id="phase-4">
      <div class="phase-icon">🔭</div>
      <div class="phase-name">Dynatrace MCP</div>
      <div class="phase-status">Waiting</div>
    </div>
    <div class="phase-card" id="phase-5">
      <div class="phase-icon">📋</div>
      <div class="phase-name">Incident Report</div>
      <div class="phase-status">Waiting</div>
    </div>
  </div>

  <!-- Stats bar -->
  <div class="stats-bar" id="stats-bar">
    <div class="stat-card stat-critical">
      <div class="stat-value" id="stat-critical">—</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card stat-high">
      <div class="stat-value" id="stat-high">—</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card stat-stages">
      <div class="stat-value" id="stat-stages">—</div>
      <div class="stat-label">Attack Stages</div>
    </div>
    <div class="stat-card stat-score">
      <div class="stat-value" id="stat-score">—</div>
      <div class="stat-label">Risk Score</div>
    </div>
  </div>

  <!-- Terminal -->
  <div class="terminal">
    <div class="terminal-header">
      <div class="dot dot-red"></div>
      <div class="dot dot-yellow"></div>
      <div class="dot dot-green"></div>
      <span class="terminal-title">secops-agent — pipeline output</span>
    </div>
    <div class="terminal-body" id="terminal">
      <span class="log-dim">$ Ready. Enter a GitLab repository and click RUN AGENT.</span>
      <span class="cursor"></span>
    </div>
  </div>

  <!-- Report panel -->
  <div class="report-panel" id="report-panel">
    <div class="report-header">
      <div>
        <div class="report-title">📋 Incident Report</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-top:4px" id="report-meta"></div>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="risk-badge" id="risk-badge"></span>
        <a class="download-btn" id="download-md" href="#" download>⬇ Markdown</a>
        <a class="download-btn" id="download-json" href="#" download>⬇ JSON</a>
      </div>
    </div>
    <div class="report-body">
      <div class="report-section">
        <div class="section-title">Executive Summary</div>
        <div class="summary-text" id="exec-summary"></div>
      </div>
      <div class="report-section">
        <div class="section-title">Kill Chain</div>
        <div class="kill-chain" id="kill-chain"></div>
      </div>
      <div class="report-section">
        <div class="section-title">Top Critical Vulnerabilities</div>
        <div class="vuln-list" id="vuln-list"></div>
      </div>
      <div class="report-section">
        <div class="section-title">Immediate Remediation Actions</div>
        <div class="action-list" id="action-list"></div>
      </div>
    </div>
  </div>

</div>

<script>
let reportData = null;

function log(text, cls = 'log-info') {
  const terminal = document.getElementById('terminal');
  // Remove cursor from last line
  const cursors = terminal.querySelectorAll('.cursor');
  cursors.forEach(c => c.remove());

  const span = document.createElement('span');
  span.className = `log-line ${cls}`;
  span.textContent = text;
  terminal.appendChild(span);
  terminal.appendChild(document.createElement('br'));

  // Add cursor
  const cursor = document.createElement('span');
  cursor.className = 'cursor';
  terminal.appendChild(cursor);

  terminal.scrollTop = terminal.scrollHeight;
}

function setPhase(n, state) {
  const card = document.getElementById(`phase-${n}`);
  const status = card.querySelector('.phase-status');
  card.className = `phase-card ${state}`;
  status.textContent = state === 'active' ? 'Running...' : state === 'done' ? 'Complete ✓' : 'Waiting';
}

async function startScan() {
  const project = document.getElementById('project-input').value.trim();
  if (!project) return;

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> SCANNING...';

  // Reset UI
  document.getElementById('terminal').innerHTML = '';
  document.getElementById('report-panel').classList.remove('visible');
  document.getElementById('stats-bar').classList.remove('visible');
  [2,3,4,5].forEach(n => setPhase(n, ''));

  log('$ secops-agent --target ' + project, 'log-dim');
  log('', 'log-dim');

  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_path: project })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value);
      const lines = chunk.split('\\n').filter(l => l.startsWith('data: '));

      for (const line of lines) {
        try {
          const data = JSON.parse(line.slice(6));
          handleEvent(data);
        } catch(e) {
          // Skip malformed SSE lines
        }
      }
    }
  } catch (e) {
    log('Error: ' + e.message, 'log-error');
  }

  // After SSE stream ends, fetch the latest report from the server
  try {
    const listRes = await fetch('/reports/latest');
    if (listRes.ok) {
      const latest = await listRes.json();
      if (latest.report_id) {
        const repRes = await fetch('/report/' + latest.report_id);
        if (repRes.ok) {
          const report = await repRes.json();
          renderReport(report);
        }
      }
    }
  } catch(e) {
    // No report available yet
  }

  btn.disabled = false;
  btn.innerHTML = '▶ RUN AGENT';
}

function handleEvent(data) {
  switch (data.type) {
    case 'phase_start':
      log('', 'log-dim');
      log(`══ ${data.phase} ══`, 'log-phase');
      setPhase(data.phase_num, 'active');
      break;

    case 'phase_done':
      setPhase(data.phase_num, 'done');
      log(`✓ ${data.message}`, 'log-success');
      break;

    case 'log':
      log(data.message, data.cls || 'log-info');
      break;

    case 'stats':
      document.getElementById('stat-critical').textContent = data.critical;
      document.getElementById('stat-high').textContent     = data.high;
      document.getElementById('stat-stages').textContent   = data.stages;
      document.getElementById('stat-score').textContent    = data.score + '/100';
      document.getElementById('stats-bar').classList.add('visible');
      break;

    case 'report':
      renderReport(data.report);
      break;

    case 'report_ready':
      // Fetch report from server via separate HTTP request (avoids SSE size limits)
      fetch('/report/' + data.report_id)
        .then(r => r.json())
        .then(report => renderReport(report))
        .catch(e => log('Error loading report: ' + e.message, 'log-error'));
      break;
  }
}

function renderReport(report) {
  reportData = report;

  document.getElementById('report-meta').textContent =
    `${report.report_id}  ·  ${report.generated_at?.slice(0,19).replace('T',' ')} UTC`;

  const badge = document.getElementById('risk-badge');
  badge.textContent = report.risk_level + ' — ' + report.risk_score + '/100';
  badge.className = `risk-badge risk-${report.risk_level}`;

  document.getElementById('exec-summary').textContent = report.executive_summary;

  // Kill chain
  const kc = document.getElementById('kill-chain');
  kc.innerHTML = '';
  const stages = [...new Set(report.timeline?.map(e => e.stage) || [])];
  stages.forEach((s, i) => {
    const span = document.createElement('span');
    span.className = 'chain-stage';
    span.textContent = s;
    kc.appendChild(span);
    if (i < stages.length - 1) {
      const arrow = document.createElement('span');
      arrow.className = 'chain-arrow';
      arrow.textContent = '→';
      kc.appendChild(arrow);
    }
  });

  // Vulnerabilities
  const vl = document.getElementById('vuln-list');
  vl.innerHTML = '';
  (report.top_vulnerabilities || []).forEach(v => {
    vl.innerHTML += `
      <div class="vuln-item">
        <span class="vuln-sev sev-${v.severity}">${v.severity}</span>
        <div>
          <div class="vuln-desc">${v.description}</div>
          <div class="vuln-file">${v.file}</div>
        </div>
      </div>`;
  });

  // Actions (immediate only)
  const al = document.getElementById('action-list');
  al.innerHTML = '';
  (report.remediation || [])
    .filter(a => a.effort === 'immediate')
    .forEach(a => {
      al.innerHTML += `
        <div class="action-item">
          <span class="action-priority action-effort-immediate">[${a.priority}] 🚨</span>
          <div class="action-text">${a.action}</div>
        </div>`;
    });

  // Download links — decode base64 encoded content
  const md   = report.markdown_b64 ? atob(report.markdown_b64) : '';
  const json = report.json_b64     ? atob(report.json_b64)     : '';

  const mdBlob   = new Blob([md],   { type: 'text/markdown' });
  const jsonBlob = new Blob([json], { type: 'application/json' });

  document.getElementById('download-md').href   = URL.createObjectURL(mdBlob);
  document.getElementById('download-md').download = `${report.report_id}.md`;
  document.getElementById('download-json').href   = URL.createObjectURL(jsonBlob);
  document.getElementById('download-json').download = `${report.report_id}.json`;

  document.getElementById('report-panel').classList.add('visible');
}
</script>
</body>
</html>"""


# ─── SSE pipeline ─────────────────────────────────────────────────────────────

async def run_pipeline_stream(project_path: str) -> AsyncGenerator[str, None]:
    """
    Runs the SecOps pipeline and yields Server-Sent Events with progress updates.
    Each event is a JSON object with a 'type' field.
    """

    def event(data: dict) -> str:
        return f"data: {json.dumps(data, ensure_ascii=True)}\n\n"

    def log(msg: str, cls: str = "log-info"):
        return event({"type": "log", "message": msg, "cls": cls})

    try:
        # ── Import modules ────────────────────────────────────────────────────
        from agent.tools.gitlab_mcp    import scan_repository
        from agent.tools.elastic_mcp   import run_elastic_pipeline
        from agent.tools.dynatrace_mcp import run_dynatrace_pipeline
        from agent.report.generator    import generate_incident_report, render_markdown, render_json, build_report

        # ── Phase 2: GitLab ───────────────────────────────────────────────────
        yield event({"type": "phase_start", "phase": "PHASE 2 — GitLab MCP: Repository Scan", "phase_num": 2})
        yield log(f"Scanning repository: {project_path}")

        scan_result    = scan_repository(project_path=project_path)
        gitlab_summary = scan_result.summary()

        total    = gitlab_summary["total"]
        critical = gitlab_summary["by_severity"].get("CRITICAL", 0)
        high     = gitlab_summary["by_severity"].get("HIGH", 0)

        yield log(f"  Files scanned — {total} vulnerabilities found")
        yield log(f"  🔴 Critical: {critical}  🟠 High: {high}", "log-warning")
        yield event({"type": "phase_done", "phase_num": 2, "message": f"Repository scan complete — {total} findings"})

        await asyncio.sleep(0.3)

        # ── Phase 3: Elastic ──────────────────────────────────────────────────
        yield event({"type": "phase_start", "phase": "PHASE 3 — Elastic MCP: Threat Detection", "phase_num": 3})
        yield log("Ingesting findings into Elasticsearch...")

        elastic_result = run_elastic_pipeline(gitlab_summary)
        kill_chain     = elastic_result.get("kill_chain", {})
        stages         = list(dict.fromkeys(s["stage"] for s in kill_chain.get("stages", [])))
        risk_score     = kill_chain.get("risk_score", 0)

        yield log(f"  Kill chain: {' → '.join(stages[:4])}...")
        yield log(f"  Risk score: {risk_score}/100 CRITICAL", "log-error")
        yield event({"type": "phase_done", "phase_num": 3, "message": f"Kill chain built — {len(stages)} ATT&CK stages"})

        await asyncio.sleep(0.3)

        # ── Phase 4: Dynatrace ────────────────────────────────────────────────
        yield event({"type": "phase_start", "phase": "PHASE 4 — Dynatrace MCP: Runtime Correlation", "phase_num": 4})
        yield log("Correlating runtime anomalies with kill chain...")

        dynatrace_result = run_dynatrace_pipeline(elastic_result, gitlab_summary)
        playbook         = dynatrace_result.get("playbook", {})
        exploited        = sum(1 for s in playbook.get("affected_services", []) if s.get("exploited"))
        actions          = len(playbook.get("remediation_actions", []))

        yield log(f"  {exploited} services confirmed exploited")
        yield log(f"  {actions} remediation actions generated")
        yield event({"type": "phase_done", "phase_num": 4, "message": f"{exploited} services exploited — playbook ready"})

        # Emit stats
        yield event({
            "type":     "stats",
            "critical": critical,
            "high":     high,
            "stages":   len(stages),
            "score":    risk_score,
        })

        await asyncio.sleep(0.3)

        # ── Phase 5: Report ───────────────────────────────────────────────────
        yield event({"type": "phase_start", "phase": "PHASE 5 — Incident Report Generator", "phase_num": 5})
        yield log("Generating Incident Report...")

        report_obj = build_report(gitlab_summary, elastic_result, dynatrace_result)
        md_content = render_markdown(report_obj)
        json_content = render_json(report_obj)

        yield log(f"  Report ID: {report_obj.report_id}")
        yield log(f"  Timeline: {len(report_obj.timeline)} events")
        yield log(f"  Actions: {len(report_obj.remediation)} remediation steps")
        yield event({"type": "phase_done", "phase_num": 5, "message": f"Report {report_obj.report_id} generated"})

        # Store report in memory and notify frontend with just the ID.
        # The frontend fetches the full report via GET /report/{report_id}.
        # This avoids SSE JSON parse errors caused by large payloads.
        import base64
        _report_store[report_obj.report_id] = {
            "report_id":           report_obj.report_id,
            "generated_at":        report_obj.generated_at,
            "attack_id":           report_obj.attack_id,
            "risk_level":          report_obj.risk_level,
            "risk_score":          report_obj.risk_score,
            "executive_summary":   report_obj.executive_summary,
            "timeline":            report_obj.timeline,
            "top_vulnerabilities": report_obj.top_vulnerabilities,
            "remediation":         report_obj.remediation,
            "markdown_b64":        base64.b64encode(md_content.encode()).decode(),
            "json_b64":            base64.b64encode(json_content.encode()).decode(),
        }
        yield f'data: {{"type": "report_ready", "report_id": "{report_obj.report_id}"}}\n\n'

        yield log("", "log-dim")
        yield log("✓ Pipeline complete.", "log-success")

    except Exception as e:
        yield event({"type": "log", "message": f"Error: {e}", "cls": "log-error"})


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML


@app.post("/scan")
async def scan(request: ScanRequest):
    return StreamingResponse(
        run_pipeline_stream(request.project_path),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/reports/latest")
async def get_latest_report():
    from fastapi.responses import JSONResponse
    if not _report_store:
        return JSONResponse({"error": "No reports yet"}, status_code=404)
    latest_id = sorted(_report_store.keys())[-1]
    return JSONResponse({"report_id": latest_id})


@app.get("/report/{report_id}")
async def get_report(report_id: str):
    from fastapi.responses import JSONResponse
    report = _report_store.get(report_id)
    if not report:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    return JSONResponse(report)


@app.get("/health")
async def health():
    return {"status": "ok", "agent": "SecOps Agent v1.0"}


# ─── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
