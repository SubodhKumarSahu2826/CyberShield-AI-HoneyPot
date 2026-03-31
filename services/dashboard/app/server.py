"""
Dashboard Service — aiohttp-based server (Day 3 Update)

Serves a dark-themed single-page dashboard that auto-polls the API service
every 10 seconds. Day 3 adds an Attacker Sessions panel.

Port: 3000
"""

import asyncio
import json
import logging
import os
import sys

from aiohttp import ClientSession, ClientTimeout, web

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "service": "dashboard", "level": "%(levelname)s", "message": "%(message)s"}',
)
logger = logging.getLogger("dashboard")

API_HOST = os.environ.get("API_HOST", "api")
API_PORT = os.environ.get("API_PORT", "3001")
API_BASE = f"http://{API_HOST}:{API_PORT}"

# ---------------------------------------------------------------------------
# Dashboard HTML — dark theme, sessions panel, auto-refresh
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CyberShield — Live Monitor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:         #060B14; /* Deep Navy Background */
      --bg2:        rgba(17, 24, 39, 0.65); /* Rich Glass Background */
      --border:     rgba(51, 65, 85, 0.4); /* Subtle borders */
      --accent:     #38bdf8; /* Sky Blue */
      --accent2:    #818cf8; /* Indigo */
      --danger:     #fb7185; /* Rose */
      --warn:       #fbbf24; /* Amber */
      --success:    #34d399; /* Emerald */
      --text:       #f8fafc; /* Slate text */
      --text-muted: #94a3b8; /* Dimmed text */
      --font:       'Outfit', sans-serif;
      --mono:       'JetBrains Mono', monospace;
      --radius:     16px;
    }
    body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; }

    /* GLOW BACKGROUND */
    .glow-bg { position: fixed; inset: 0; overflow: hidden; z-index: -1; pointer-events: none; }
    .blob { position: absolute; filter: blur(140px); border-radius: 50%; opacity: 0.15; animation: float 15s infinite ease-in-out alternate; }
    .blob-1 { width: 50vw; height: 50vw; max-width: 600px; max-height: 600px; background: var(--accent); top: -10%; left: -10%; }
    .blob-2 { width: 60vw; height: 60vw; max-width: 700px; max-height: 700px; background: var(--accent2); bottom: -20%; right: -10%; animation-delay: -7s; }
    @keyframes float { 0% { transform: translateY(0) scale(1); } 100% { transform: translateY(40px) scale(1.1); } }

    /* CUSTOM SCROLLBAR */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(51, 65, 85, 0.6); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(148, 163, 184, 0.8); }

    /* HEADER */
    header { display: flex; align-items: center; justify-content: space-between; padding: 1.25rem 2.5rem;
      background: rgba(6, 11, 20, 0.85); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
      border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100; box-shadow: 0 4px 30px rgba(0,0,0,0.5); }
    .logo { display: flex; align-items: center; gap: 1rem; }
    .logo-icon { width: 44px; height: 44px; background: linear-gradient(135deg, var(--accent), var(--accent2));
      border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; 
      box-shadow: 0 8px 20px rgba(129, 140, 248, 0.3), inset 0 2px 4px rgba(255,255,255,0.4); 
      border: 1px solid rgba(255,255,255,0.1); }
    .logo-text { font-size: 1.3rem; font-weight: 700; letter-spacing: -0.02em; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
    .logo-sub  { font-size: 0.75rem; color: var(--text-muted); letter-spacing: 0.15em; text-transform: uppercase; font-weight: 600; }
    .header-right { display: flex; align-items: center; gap: 1.5rem; }
    .status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
      background: var(--success); box-shadow: 0 0 12px var(--success); animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{ opacity:1; transform: scale(1); } 50%{ opacity:0.5; transform: scale(1.1); } }
    .last-update { font-size: 0.85rem; color: var(--text-muted); font-family: var(--mono); font-weight: 500; }
    .tag { font-size: 0.75rem; padding: 0.4rem 1rem; border-radius: 999px; font-weight: 600;
      background: linear-gradient(90deg, rgba(56,189,248,0.15), rgba(129,140,248,0.15)); 
      color: var(--text); border: 1px solid rgba(129,140,248,0.3); letter-spacing: 0.05em; 
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); }
      
    /* MAIN */
    main { padding: 2.5rem; max-width: 1600px; margin: 0 auto; z-index: 1; position: relative; animation: fadeIn 0.6s ease-out; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* GLASS CARDS */
    .glass-panel { background: var(--bg2); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
      border: 1px solid var(--border); border-radius: var(--radius); 
      box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05); overflow: hidden; }

    /* STAT CARDS */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }
    .stat-card { position: relative; padding: 1.75rem; transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275), box-shadow 0.3s; }
    .stat-card:hover { transform: translateY(-5px); box-shadow: 0 20px 40px -15px rgba(0,0,0,0.7); border-color: rgba(255,255,255,0.15); z-index: 10; }
    .stat-card::before { content: ''; position: absolute; inset: 0; background: radial-gradient(circle at top right, rgba(255,255,255,0.03), transparent 60%); pointer-events: none; }
    .stat-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.75rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .stat-value { font-size: 2.8rem; font-weight: 700; font-family: var(--font); line-height: 1; letter-spacing: -0.03em; text-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    .stat-icon { position: absolute; top: 1.5rem; right: 1.5rem; font-size: 1.8rem; opacity: 0.15; transition: opacity 0.3s, transform 0.3s; filter: grayscale(100%); }
    .stat-card:hover .stat-icon { opacity: 0.8; transform: scale(1.1) rotate(5deg); filter: grayscale(0%); }

    /* SECTION TITLE */
    .section-title { font-size: 0.95rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.15em;
      color: var(--text-muted); margin-bottom: 1.25rem; display: flex; align-items: center; gap: 0.75rem; 
      text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
    .section-title::after { content: ''; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border), transparent); }

    /* LAYOUT */
    .dual-col { display: grid; grid-template-columns: 1fr 380px; gap: 2rem; margin-bottom: 2.5rem; }
    @media (max-width: 1200px) { .dual-col { grid-template-columns: 1fr; } }

    /* CARD COMPONENTS */
    .card-header { padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.25);
      font-size: 0.9rem; font-weight: 600; display: flex; justify-content: space-between; align-items: center; letter-spacing: 0.05em; }
    .badge { font-size: 0.75rem; padding: 0.25rem 0.75rem; border-radius: 999px; background: rgba(255,255,255,0.08); 
      font-weight: 600; box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.05); }

    /* TABLE */
    .table-container { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 0 0 var(--radius) var(--radius); }
    table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.85rem; min-width: 900px; }
    thead th { position: sticky; top: 0; padding: 1rem 1.25rem; text-align: left; font-size: 0.75rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted);
      background: rgba(10, 15, 24, 0.95); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); z-index: 20; }
    tbody tr { transition: all 0.2s ease; position: relative; }
    tbody tr::after { content: ''; position: absolute; bottom: 0; left: 1.25rem; right: 1.25rem; height: 1px; background: var(--border); opacity: 0.5; }
    tbody tr:last-child::after { display: none; }
    tbody tr:hover { background: rgba(255,255,255,0.04); transform: scale(1.005); z-index: 10; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
    tbody td { padding: 0.85rem 1.25rem; font-family: var(--mono); font-size: 0.82rem;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 240px; }

    /* BUTTONS & ACTIONS */
    .btn-view { display: inline-flex; align-items: center; justify-content: center; gap: 6px; background: linear-gradient(135deg, rgba(129,140,248,0.2), rgba(56,189,248,0.2)); border: 1px solid rgba(129,140,248,0.4); color: var(--accent); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; transition: transform 0.2s, box-shadow 0.2s; text-transform: uppercase; white-space: nowrap; margin-top: 6px; }
    .btn-view:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(129,140,248,0.3); background: linear-gradient(135deg, rgba(129,140,248,0.3), rgba(56,189,248,0.3)); }

    /* BADGES */
    .method { display: inline-flex; align-items: center; justify-content: center; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; min-width: 60px; }
    .m-GET    { background: rgba(52, 211, 153, 0.15); color: var(--success); border: 1px solid rgba(52, 211, 153, 0.3); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); }
    .m-POST   { background: rgba(129, 140, 248, 0.15); color: var(--accent2); border: 1px solid rgba(129, 140, 248, 0.3); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); }
    .m-PUT    { background: rgba(251, 191, 36, 0.15); color: var(--warn); border: 1px solid rgba(251, 191, 36, 0.3); }
    .m-DELETE { background: rgba(251, 113, 133, 0.15);  color: var(--danger); border: 1px solid rgba(251, 113, 133, 0.3); }
    .m-PATCH  { background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }
    .m-OTHER  { background: rgba(148, 163, 184, 0.15);color: var(--text-muted); border: 1px solid rgba(148, 163, 184, 0.3); }

    .status-badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; border: 1px solid transparent; box-shadow: inset 0 1px 0 rgba(255,255,255,0.05); }
    .s-malicious  { background: rgba(251, 113, 133, 0.15);  color: var(--danger); border-color: rgba(251, 113, 133, 0.3); box-shadow: 0 0 15px rgba(251, 113, 133, 0.15), inset 0 1px 0 rgba(255,255,255,0.1); }
    .s-suspicious { background: rgba(251, 191, 36, 0.15); color: var(--warn); border-color: rgba(251, 191, 36, 0.3); }

    /* SIDE PANELS & BARS */
    .side-panels { display: flex; flex-direction: column; gap: 2rem; }
    .list-panel { list-style: none; padding: 0.25rem 0; }
    .list-panel li { display: flex; align-items: center; justify-content: space-between;
      padding: 0.85rem 1.5rem; font-size: 0.85rem; position: relative; z-index: 1; border-bottom: 1px solid rgba(255,255,255,0.03); }
    .list-panel li:last-child { border-bottom: none; }
    .list-panel li:hover { background: rgba(255,255,255,0.02); }
    
    .lp-bar { position: absolute; top: 0; left: 0; bottom: 0; z-index: -1; 
      /* fallback if custom property fails */ width: 0%; 
      border-radius: 0 6px 6px 0; transition: width 1s cubic-bezier(0.25, 0.8, 0.25, 1); }
    .bar-blue { background: linear-gradient(90deg, rgba(56, 189, 248, 0.15), transparent); border-right: 1px solid rgba(56, 189, 248, 0.3); }
    .bar-red  { background: linear-gradient(90deg, rgba(251, 113, 133, 0.15), transparent); border-right: 1px solid rgba(251, 113, 133, 0.3); }
    .bar-warn { background: linear-gradient(90deg, rgba(251, 191, 36, 0.15), transparent); border-right: 1px solid rgba(251, 191, 36, 0.3); }

    .lp-name { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px; font-weight: 500; }
    .lp-count { background: rgba(255,255,255,0.08); border-radius: 6px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-family: var(--mono); font-weight: 600; flex-shrink: 0; box-shadow: inset 0 1px 0 rgba(255,255,255,0.1), 0 2px 4px rgba(0,0,0,0.2); }

    /* EMPTY STATE */
    .empty-state { padding: 4rem 2rem; text-align: center; color: var(--text-muted); font-size: 0.95rem; font-weight: 500; }
    .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.4; animation: float 6s infinite ease-in-out alternate; filter: grayscale(50%); }

    /* MODAL */
    .modal-overlay { position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); animation: fadeIn 0.2s ease-out; }
    .modal-content { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); width: 90%; max-width: 800px; max-height: 80vh; display: flex; flex-direction: column; box-shadow: 0 20px 40px rgba(0,0,0,0.8); }
    .modal-header { padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.3); border-radius: var(--radius) var(--radius) 0 0; }
    .modal-close { background: none; border: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; transition: color 0.2s; padding: 0.2rem 0.5rem; }
    .modal-close:hover { color: var(--danger); }
    .modal-body { padding: 1.5rem; overflow-y: auto; font-family: var(--mono); font-size: 0.85rem; color: var(--accent); white-space: pre-wrap; word-break: break-all; }

    /* NAVBAR & RESPONSIVE QUERIES */
    .navbar { display: flex; gap: 0.5rem; justify-content: center; padding: 0.75rem 2.5rem; background: rgba(0,0,0,0.5); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 99; backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); overflow-x: auto; white-space: nowrap; }
    .nav-link { color: var(--text-muted); text-decoration: none; font-weight: 600; font-size: 0.85rem; padding: 0.6rem 1.2rem; border-radius: 8px; transition: all 0.2s; display: inline-flex; align-items: center; gap: 8px; border: 1px solid transparent; }
    .nav-link:hover { background: rgba(56, 189, 248, 0.1); color: var(--text); border-color: rgba(56, 189, 248, 0.3); }

    @media (max-width: 1200px) {
      .dual-col { grid-template-columns: 1fr; }
      .dual-col[style*="grid-template-columns"] { grid-template-columns: 1fr !important; }
    }
    @media (max-width: 768px) {
      header { flex-direction: column; align-items: flex-start; gap: 1rem; padding: 1rem; position: relative; }
      .header-right { flex-direction: column; align-items: flex-start; gap: 0.5rem; width: 100%; }
      .navbar { padding: 0.5rem 1rem; }
      main { padding: 1rem; }
      .stats-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 480px) {
      .stats-grid { grid-template-columns: 1fr; }
    }

    /* FOOTER */
    footer { text-align: center; padding: 2.5rem; font-size: 0.85rem; color: var(--text-muted); border-top: 1px solid var(--border); font-weight: 500; letter-spacing: 0.08em; margin-top: 3rem; background: rgba(0,0,0,0.2); }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    Chart.defaults.color = 'rgba(148, 163, 184, 0.8)';
    Chart.defaults.font.family = "'Outfit', sans-serif";
    let timelineChartInstance = null;
    let pieChartInstance = null;
  </script>
</head>
<body>
<div class="glow-bg">
  <div class="blob blob-1"></div>
  <div class="blob blob-2"></div>
</div>

<header>
  <div class="logo">
    <div>
      <div class="logo-text">CyberShield</div>
      <div class="logo-sub">Threat Intelligence Platform</div>
    </div>
  </div>
  <div class="header-right">
    <div style="display:flex;align-items:center;gap:8px;background:rgba(0,0,0,0.3);padding:0.4rem 1rem;border-radius:999px;border:1px solid var(--border);box-shadow:inset 0 1px 0 rgba(255,255,255,0.05);">
      <span class="status-dot" id="status-dot"></span>
      <span class="last-update" id="last-update">Connecting...</span>
    </div>
  </div>
</header>

<nav class="navbar">
  <a href="#stats" class="nav-link">Overview</a>
  <a href="#analytics" class="nav-link">Analytics</a>
  <a href="#captures" class="nav-link">Live Captures</a>
  <a href="#sessions" class="nav-link">Sessions</a>
  <a href="#intelligence" class="nav-link">Intelligence</a>
</nav>

<main>
  <!-- STAT CARDS -->
  <div id="stats" class="stats-grid">
    <div class="stat-card glass-panel" style="border-top: 2px solid var(--accent)">
      <div class="stat-label">Total Requests</div>
      <div class="stat-value" id="stat-total" style="color: var(--accent)">—</div>
      <div class="stat-icon">📡</div>
    </div>
    <div class="stat-card glass-panel" style="border-top: 2px solid var(--accent2)">
      <div class="stat-label">Unique IPs</div>
      <div class="stat-value" id="stat-ips" style="color: var(--accent2)">—</div>
      <div class="stat-icon">🌐</div>
    </div>
    <div class="stat-card glass-panel" style="border-top: 2px solid var(--danger)">
      <div class="stat-label">Malicious</div>
      <div class="stat-value" id="stat-malicious" style="color:var(--danger)">—</div>
      <div class="stat-icon">⚠️</div>
    </div>
    <div class="stat-card glass-panel" style="border-top: 2px solid var(--warn)">
      <div class="stat-label">Active Sessions</div>
      <div class="stat-value" id="stat-sessions" style="color:var(--warn)">—</div>
      <div class="stat-icon">🕵️</div>
    </div>
    <div class="stat-card glass-panel" style="border-top: 2px solid var(--success)">
      <div class="stat-label">Capture Status</div>
      <div class="stat-value" style="color:var(--success);font-size:1.2rem;padding-top:0.8rem;display:flex;align-items:center;gap:8px;">
        <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--success);box-shadow:0 0 10px var(--success);"></span> ACTIVE
      </div>
      <div class="stat-icon">🔒</div>
    </div>
  </div>

  <!-- ANALYTICS SECTION (Milestone 3) -->
  <div id="analytics" class="section-title" style="margin-top: 1rem; padding-top: 2rem;">📈 Analytics & Threat Feed</div>
  <div class="dual-col" style="margin-bottom: 2.5rem;">
    <div class="card glass-panel" style="grid-column: 1 / -1;">
      <div class="card-header">Traffic Timeline (24h Window)</div>
      <div style="padding: 1.5rem; min-height: 260px;">
        <canvas id="timelineChart"></canvas>
      </div>
    </div>
  </div>
  
  <div class="dual-col" style="grid-template-columns: 1fr 1fr; margin-bottom: 2.5rem;">
    <div class="card glass-panel" style="min-height: 380px;">
      <div class="card-header">Attack Method Distribution</div>
      <div style="padding: 1.5rem; display: flex; justify-content: center; min-height: 320px;">
        <canvas id="pieChart"></canvas>
      </div>
    </div>
    <div class="card glass-panel" style="min-height: 380px;">
      <div class="card-header">Critical Alerts Feed</div>
      <ul class="list-panel" id="alerts-list" style="overflow-y: auto; max-height: 320px;">
        <li><span class="lp-name" style="color:var(--success)">System Secure — Monitoring Active</span></li>
      </ul>
    </div>
  </div>

  <!-- REQUESTS + SIDE PANELS -->
  <div id="captures" class="dual-col" style="padding-top: 2rem;">
    <!-- REQUESTS TABLE -->
    <div>
      <div class="section-title">📋 Recent Captures</div>
      <div class="card glass-panel">
        <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
          <div style="display:flex; align-items:center; gap:0.5rem;">
            <span>Recent Captures</span> <span class="badge" id="req-count">0</span>
            <select id="req-limit" onchange="loadRequests()" style="background:rgba(0,0,0,0.5);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:0.75rem;padding:2px 4px;outline:none;">
              <option value="20">Last 20</option>
              <option value="100">Last 100</option>
              <option value="500">Last 500</option>
            </select>
          </div>
          <div style="display:flex; gap:0.5rem;">
            <a href="/api/export/csv" target="_blank" download="cybershield-attack-logs.csv" class="btn-view" style="text-decoration:none; padding: 4px 10px; font-size: 0.7rem; color: var(--success); border-color: rgba(52, 211, 153, 0.4); background: rgba(52, 211, 153, 0.1);">📄 Export CSV</a>
            <a href="/api/export/json" target="_blank" download="cybershield-attack-logs.json" class="btn-view" style="text-decoration:none; padding: 4px 10px; font-size: 0.7rem; color: var(--warn); border-color: rgba(251, 191, 36, 0.4); background: rgba(251, 191, 36, 0.1);">{ } Export JSON</a>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Method</th>
                <th>Endpoint</th>
                <th>Source IP</th>
                <th>Status</th>
                <th>Detection</th>
                <th>Deception</th>
                <th>Session</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody id="requests-tbody">
              <tr><td colspan="9" class="empty-state">
                <div class="icon">📭</div>Waiting for captured traffic...
              </td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- SIDE PANELS -->
    <div class="side-panels">
      <div>
        <div class="section-title">🎯 Top Endpoints</div>
        <div class="card glass-panel">
          <div class="card-header">Most Targeted</div>
          <ul class="list-panel" id="endpoints-list">
            <li><span class="lp-name" style="color:var(--text-muted)">No data yet</span></li>
          </ul>
        </div>
      </div>
      <div>
        <div class="section-title">⚔️ Attack Breakdown</div>
        <div class="card glass-panel">
          <div class="card-header">By Type</div>
          <ul class="list-panel" id="attacks-list">
            <li><span class="lp-name" style="color:var(--text-muted)">No attacks yet</span></li>
          </ul>
        </div>
      </div>
      <div>
        <div class="section-title">👤 Attacker Types</div>
        <div class="card glass-panel">
          <div class="card-header">By Profile</div>
          <ul class="list-panel" id="attacker-types-list">
            <li><span class="lp-name" style="color:var(--text-muted)">No data yet</span></li>
          </ul>
        </div>
      </div>
    </div>
  </div>

  <!-- SESSIONS TABLE (Day 3) -->
  <div id="sessions" class="sessions-section" style="margin-top: 1rem; padding-top: 2rem;">
    <div class="section-title">🕵️ Attacker Sessions</div>
    <div class="card glass-panel">
      <div class="card-header">
        Active Attacker Sessions
        <span class="badge" id="session-count">0</span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Session ID</th>
              <th>Source IP</th>
              <th>Requests</th>
              <th>Top Attack</th>
              <th>First Seen</th>
              <th>Last Seen</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody id="sessions-tbody">
            <tr><td colspan="7" class="empty-state">
              <div class="icon">🕵️</div>No sessions tracked yet...
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- PROFILES TABLE (Milestone 2B) -->
  <div id="intelligence" class="sessions-section" style="margin-top: 3.5rem; padding-top: 2rem;">
    <div class="section-title">🧠 Attacker Behaviour Intelligence</div>
    <div class="card glass-panel">
      <div class="card-header">
        Identified Threat Profiles
        <span class="badge" id="profile-count">0</span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Session ID</th>
              <th>Source IP</th>
              <th>Attacker Type</th>
              <th>Dominant Pattern</th>
              <th>Sophistication Score</th>
              <th>Last Interaction</th>
            </tr>
          </thead>
          <tbody id="profiles-tbody">
            <tr><td colspan="6" class="empty-state">
              <div class="icon">🧠</div>No categorized behavior profiles yet...
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- MODAL INJECTION -->
  <div class="modal-overlay" id="response-modal" style="display:none;" onclick="closeModal(event)">
    <div class="modal-content" onclick="event.stopPropagation()" style="width: 95vw; max-width: 1400px; height: 90vh;">
      <div class="modal-header">
        <h3 style="color:var(--accent);font-weight:600;font-size:1.1rem;letter-spacing:0.05em;">Generated Target Response</h3>
        <button class="modal-close" onclick="closeModal()">×</button>
      </div>
      <div class="modal-body" id="modal-text" style="font-size: 0.95rem; line-height: 1.5; padding: 2rem;"></div>
    </div>
  </div>

</main>

<footer>
  CyberShield Platform &mdash; Adaptive Intelligence &mdash; Refreshes every 10s
</footer>

<script>
  let currentRequests = [];

  function openModal(index) {
    const req = currentRequests[index];
    if (!req) return;
    const modal = document.getElementById('response-modal');
    document.getElementById('modal-text').textContent = req.response || "No response generated.";
    modal.style.display = 'flex';
  }

  function closeModal(e) { 
    if(e && e.target !== e.currentTarget && e.target.className !== 'modal-close') return;
    document.getElementById('response-modal').style.display = 'none'; 
  }

  function methodClass(m) {
    const map = { GET:'m-GET', POST:'m-POST', PUT:'m-PUT', DELETE:'m-DELETE', PATCH:'m-PATCH' };
    return map[m] || 'm-OTHER';
  }
  function statusClass(s) { return s === 'malicious' ? 's-malicious' : 's-suspicious'; }
  function short(s, n=16) { return s && s.length > n ? s.slice(0,n)+'…' : (s||''); }

  function timeAgo(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400) return `${Math.floor(s/3600)}h ago`;
    return d.toLocaleDateString();
  }

  function fmtDuration(sec) {
    if (!sec || sec < 1) return '<1s';
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec/60)}m ${sec%60}s`;
    return `${Math.floor(sec/3600)}h ${Math.floor((sec%3600)/60)}m`;
  }

  async function loadStats() {
    try {
      const r = await fetch('/api/stats');
      if (!r.ok) return;
      const d = await r.json();
      document.getElementById('stat-total').textContent    = (d.total_requests  || 0).toLocaleString();
      document.getElementById('stat-ips').textContent      = (d.unique_ips      || 0).toLocaleString();
      document.getElementById('stat-malicious').textContent = (d.malicious_count || 0).toLocaleString();

      const epList = document.getElementById('endpoints-list');
      if (d.top_endpoints && d.top_endpoints.length > 0) {
        const max = Math.max(...d.top_endpoints.map(e => e.hit_count));
        epList.innerHTML = d.top_endpoints.slice(0,8).map(e => {
          const perc = max > 0 ? (e.hit_count / max) * 100 : 0;
          return `
          <li>
            <div class="lp-bar bar-blue" style="width: ${perc}%"></div>
            <span class="lp-name" style="color:var(--accent)" title="${e.endpoint}">${e.endpoint}</span>
            <span class="lp-count">${e.hit_count}</span>
          </li>`;
        }).join('');
      }

      const atkList = document.getElementById('attacks-list');
      if (d.attack_breakdown && d.attack_breakdown.length > 0) {
        const max = Math.max(...d.attack_breakdown.map(a => a.count));
        atkList.innerHTML = d.attack_breakdown.slice(0,8).map(a => {
          const perc = max > 0 ? (a.count / max) * 100 : 0;
          return `
          <li>
            <div class="lp-bar bar-red" style="width: ${perc}%"></div>
            <span class="lp-name" style="color:var(--danger)" title="${a.attack_type}">${a.attack_type}</span>
            <span class="lp-count">${a.count}</span>
          </li>`;
        }).join('');
        if(typeof renderPie === 'function') renderPie(d.attack_breakdown);
      }

      if (d.attacker_breakdown && d.attacker_breakdown.length > 0) {
        const max = Math.max(...d.attacker_breakdown.map(a => a.count));
        document.getElementById('attacker-types-list').innerHTML = d.attacker_breakdown.map(a => {
          const perc = max > 0 ? (a.count / max) * 100 : 0;
          return `
          <li>
            <div class="lp-bar bar-warn" style="width: ${perc}%"></div>
            <span class="lp-name" style="color:var(--warn)">${a.attacker_type}</span>
            <span class="lp-count">${a.count}</span>
          </li>`;
        }).join('');
      }
    } catch(e) { console.warn('Stats fetch failed', e); }
  }

  async function loadRequests() {
    try {
      const limitEl = document.getElementById('req-limit');
      const limit = limitEl ? limitEl.value : '20';
      const endpoint = limit === '20' ? '/api/requests/latest' : `/api/requests?limit=${limit}`;
      const r = await fetch(endpoint);
      if (!r.ok) return;
      const d = await r.json();
      const rows = d.requests || [];
      document.getElementById('req-count').textContent = rows.length;
      currentRequests = rows;
      const tbody = document.getElementById('requests-tbody');
      if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><div class="icon">📭</div>Waiting for captured traffic...</td></tr>`;
        return;
      }
      tbody.innerHTML = rows.map((req, i) => `
        <tr>
          <td style="color:var(--text-muted)">${req.id || i+1}</td>
          <td><span class="method ${methodClass(req.method)}">${req.method}</span></td>
          <td title="${req.endpoint}">${short(req.endpoint, 55)}</td>
          <td style="color:var(--accent)">
            ${req.source_ip}
            ${req.attacker_type && req.attacker_type !== 'unknown' ? `<br><span style="font-size:0.65rem;color:var(--warn)">[${req.attacker_type}] Score: ${Math.round(req.attacker_score||0)}/10</span>` : ''}
          </td>
          <td><span class="status-badge ${statusClass(req.detection_status)}">${req.detection_status||'—'}</span></td>
          <td>
            ${req.attack_type !== 'unknown' ? `<div style="color:var(--danger);font-weight:600;">${short(req.attack_type, 35)}</div>` : ((req.ai_attack_type && req.ai_attack_type !== 'model_unavailable' && req.ai_attack_type !== 'Unknown Anomaly' && req.ai_attack_type !== 'None / Benign') ? '' : '<div style="color:var(--text-muted);font-weight:400;font-size:0.75rem">—</div>')}
            ${req.ai_attack_type && req.ai_attack_type !== 'model_unavailable' && req.ai_attack_type !== '' && req.ai_attack_type !== 'Unknown Anomaly' && req.ai_attack_type !== 'None / Benign'
              ? `<div style="color:var(--accent);font-size:0.7rem;margin-top:${req.attack_type !== 'unknown' ? '4px' : '0'};">🤖 AI: ${short(req.ai_attack_type, 25)} (${Math.round((req.ai_confidence_score||0)*100)}%)</div>` 
              : `<div style="color:var(--text-muted);font-size:0.65rem;margin-top:4px;opacity:0.6">🤖 AI: Unclassified</div>`}
          </td>
          <td>
            <div style="color:var(--success);font-size:0.8rem;font-weight:600;margin-bottom:6px;">${short(req.response_type||'—', 20)}</div>
            ${req.response ? `<button class="btn-view" onclick="openModal(${i}); return false;">👁️ Read Response</button>` : ''}
          </td>
          <td style="color:var(--text-muted);font-size:0.75rem">${short(req.session_id||'', 16)}</td>
          <td style="color:var(--text-muted)">${timeAgo(req.timestamp)}</td>
        </tr>`).join('');
    } catch(e) { console.warn('Requests fetch failed', e); }
  }

  async function loadSessions() {
    try {
      const r = await fetch('/api/sessions');
      if (!r.ok) return;
      const d = await r.json();
      const sessions = d.sessions || [];
      document.getElementById('session-count').textContent = sessions.length;
      document.getElementById('stat-sessions').textContent = sessions.length.toLocaleString();
      const tbody = document.getElementById('sessions-tbody');
      if (sessions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><div class="icon">🕵️</div>No sessions tracked yet...</td></tr>`;
        return;
      }
      tbody.innerHTML = sessions.slice(0, 30).map(s => `
        <tr>
          <td style="color:var(--accent);font-size:0.75rem">${s.session_id}</td>
          <td style="color:var(--text);font-weight:500;">${s.source_ip}</td>
          <td style="color:var(--warn);font-weight:700">${s.request_count}</td>
          <td style="color:var(--danger);font-weight:600;">${short(s.top_attack_type||'',20)}</td>
          <td style="color:var(--text-muted)">${timeAgo(s.first_seen)}</td>
          <td style="color:var(--text-muted)">${timeAgo(s.last_seen)}</td>
          <td style="color:var(--text-muted)">${fmtDuration(s.duration_seconds)}</td>
        </tr>`).join('');
    } catch(e) { console.warn('Sessions fetch failed', e); }
  }

  async function loadPending() {
    try {
      const r = await fetch('/api/queue');
      if (!r.ok) return;
      const d = await r.json();
      document.getElementById('stat-pending').textContent = d.queue_size || 0;
    } catch (e) { console.warn('Failed to load queue size', e); }
  }

  async function loadProfiles() {
    try {
      const r = await fetch('/api/attacker-profiles');
      if (!r.ok) return;
      const d = await r.json();
      const profiles = d.profiles || [];
      document.getElementById('profile-count').textContent = profiles.length;
      const tbody = document.getElementById('profiles-tbody');
      if (profiles.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><div class="icon">🧠</div>No categorized behavior profiles yet...</td></tr>`;
        return;
      }
      tbody.innerHTML = profiles.slice(0, 30).map(p => `
        <tr>
          <td style="color:var(--accent);font-size:0.75rem">${p.session_id}</td>
          <td style="color:var(--text);font-weight:500;">${p.source_ip}</td>
          <td style="color:var(--warn);font-weight:700">${p.attacker_type}</td>
          <td style="color:var(--danger);font-weight:600;">${short(p.attack_pattern||'none',20)}</td>
          <td>
            <div style="display:flex;align-items:center;gap:6px;">
              <span style="color:var(--accent);font-weight:bold">${Math.round(p.attacker_score||0)} / 10</span>
              <div style="flex:1;height:4px;background:rgba(255,255,255,0.1);border-radius:2px;overflow:hidden;min-width:40px;">
                <div style="height:100%;width:${(p.attacker_score||0)*10}%;background:var(--accent)"></div>
              </div>
            </div>
          </td>
          <td style="color:var(--text-muted)">${timeAgo(p.timestamp)}</td>
        </tr>`).join('');
    } catch(e) { console.warn('Profiles fetch failed', e); }
  }

  async function loadAnalytics() {
    try {
      const r = await fetch('/api/analytics');
      if (!r.ok) return;
      const d = await r.json();
      const rows = d.timeline || [];
      const labels = rows.map(r => new Date(r.time_bucket).getHours() + ':00');
      const data = rows.map(r => r.event_count);
      
      const ctx = document.getElementById('timelineChart').getContext('2d');
      if (timelineChartInstance) timelineChartInstance.destroy();
      timelineChartInstance = new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: [{
          label: 'Requests', data, borderColor: '#38bdf8', backgroundColor: 'rgba(56, 189, 248, 0.2)', borderWidth: 2, fill: true, tension: 0.4
        }]},
        options: { maintainAspectRatio: false, responsive: true }
      });
    } catch(e) { console.warn('Analytics fetch failed', e); }
  }

  async function loadAlerts() {
    try {
      const r = await fetch('/api/alerts');
      if (!r.ok) return;
      const d = await r.json();
      const alerts = d.alerts || [];
      const tbody = document.getElementById('alerts-list');
      if (alerts.length === 0) {
        tbody.innerHTML = `<li><span class="lp-name" style="color:var(--success)">System Secure — No Alerts Found</span></li>`;
        return;
      }
      tbody.innerHTML = alerts.map(a => `
        <li style="border-left: 3px solid ${a.severity === 'critical' ? 'var(--danger)' : 'var(--warn)'}">
          <div>
            <span style="font-size:0.75rem; color:var(--text-muted)">${timeAgo(a.timestamp)}</span><br>
            <span style="color:var(--text); font-weight:600;">${a.message}</span>
            <div style="font-size:0.7rem; color:${a.severity === 'critical' ? 'var(--danger)' : 'var(--warn)'}; margin-top:2px;">
              [${a.severity.toUpperCase()}] IP: ${a.source_ip}
            </div>
          </div>
        </li>
      `).join('');
    } catch(e) { console.warn('Alerts fetch failed', e); }
  }

  async function renderPie(attackData) {
      if(!attackData || attackData.length === 0) return;
      const ctx = document.getElementById('pieChart').getContext('2d');
      if (pieChartInstance) pieChartInstance.destroy();
      pieChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: attackData.map(a => a.attack_type),
          datasets: [{
            data: attackData.map(a => a.count),
            backgroundColor: ['#fb7185', '#fbbf24', '#38bdf8', '#818cf8', '#34d399', '#f472b6', '#c084fc']
          }]
        },
        options: { maintainAspectRatio: false, responsive: true, plugins: { legend: { position: 'right', labels: {color: 'rgba(255,255,255,0.7)'} } } }
      });
  }

  async function refresh() {
    await Promise.all([loadStats(), loadRequests(), loadSessions(), loadPending(), loadProfiles(), loadAnalytics(), loadAlerts()]);
    document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    document.getElementById('status-dot').style.background = 'var(--success)';
    document.getElementById('status-dot').style.boxShadow = '0 0 12px var(--success)';
  }

  refresh();
  setInterval(refresh, 10000);
</script>
</body>
</html>"""

# ---------------------------------------------------------------------------
# aiohttp server with /api/* proxy to the API service
# ---------------------------------------------------------------------------

async def handle_dashboard(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD_HTML, content_type="text/html", charset="utf-8")


async def proxy_api(request: web.Request) -> web.Response:
    """Proxy /api/* requests to the internal API service."""
    path  = request.match_info.get("path", "")
    query = request.query_string
    target = f"{API_BASE}/{path}"
    if query:
        target += f"?{query}"

    timeout = ClientTimeout(total=10)
    try:
        async with ClientSession(timeout=timeout) as session:
            async with session.get(target) as resp:
                body = await resp.read()
                return web.Response(
                    body=body,
                    status=resp.status,
                    content_type=resp.content_type or "application/json",
                )
    except Exception as exc:  # noqa: BLE001
        logger.error(f"API proxy error: {exc}")
        return web.Response(
            text=json.dumps({"error": "API service unavailable", "detail": str(exc)}),
            status=503,
            content_type="application/json",
        )


async def handle_health(request: web.Request) -> web.Response:  # noqa: ARG001
    return web.Response(
        text=json.dumps({"status": "healthy", "service": "dashboard"}),
        content_type="application/json",
    )


async def proxy_queue(request: web.Request) -> web.Response:  # noqa: ARG001
    """Proxy /api/queue requests natively to honeypot background worker hook."""
    timeout = ClientTimeout(total=5)
    HONEYPOT_URL = os.environ.get("HONEYPOT_URL", "http://honeypot:8080/_queue_size")
    try:
        async with ClientSession(timeout=timeout) as session:
            async with session.get(HONEYPOT_URL) as resp:
                body = await resp.read()
                return web.Response(
                    body=body,
                    status=resp.status,
                    content_type="application/json",
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Queue query failed: {exc}")
        return web.Response(
            text=json.dumps({"queue_size": 0}),
            status=200,
            content_type="application/json"
        )


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", handle_dashboard)
    app.router.add_get("/_health", handle_health)
    app.router.add_get("/api/queue", proxy_queue)
    app.router.add_get("/api/{path:.*}", proxy_api)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", "3000"))
    logger.info(f"Dashboard starting on port {port}")
    web.run_app(create_app(), host="0.0.0.0", port=port, access_log=None)
