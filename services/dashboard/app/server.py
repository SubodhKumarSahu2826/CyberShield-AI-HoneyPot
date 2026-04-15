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
    html { scroll-behavior: smooth; }
    :root {
      --bg:         #060B14;
      --bg2:        rgba(17, 24, 39, 0.65);
      --border:     rgba(51, 65, 85, 0.4);
      --accent:     #38bdf8;
      --accent2:    #818cf8;
      --danger:     #fb7185;
      --warn:       #fbbf24;
      --success:    #34d399;
      --text:       #f8fafc;
      --text-muted: #94a3b8;
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
    .blob-3 { width: 30vw; height: 30vw; max-width: 350px; max-height: 350px; background: var(--danger); top: 40%; left: 50%; opacity: 0.07; animation-delay: -3s; }
    @keyframes float { 0% { transform: translateY(0) scale(1); } 100% { transform: translateY(40px) scale(1.1); } }

    /* CUSTOM SCROLLBAR */
    ::-webkit-scrollbar { width: 8px; height: 6px; }
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
      box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05); overflow: hidden;
      transition: border-color 0.3s ease; }
    .glass-panel:hover { border-color: rgba(255,255,255,0.1); }

    /* STAT CARDS */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.25rem; margin-bottom: 2.5rem; }
    .stat-card { position: relative; padding: 1.5rem; transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275), box-shadow 0.3s; }
    .stat-card:hover { transform: translateY(-5px); box-shadow: 0 20px 40px -15px rgba(0,0,0,0.7); border-color: rgba(255,255,255,0.15); z-index: 10; }
    .stat-card::before { content: ''; position: absolute; inset: 0; background: radial-gradient(circle at top right, rgba(255,255,255,0.03), transparent 60%); pointer-events: none; }
    .stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .stat-value { font-size: 2.5rem; font-weight: 700; font-family: var(--font); line-height: 1; letter-spacing: -0.03em; text-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    .stat-icon { position: absolute; top: 1.25rem; right: 1.25rem; font-size: 1.6rem; opacity: 0.15; transition: opacity 0.3s, transform 0.3s; filter: grayscale(100%); }
    .stat-card:hover .stat-icon { opacity: 0.8; transform: scale(1.1) rotate(5deg); filter: grayscale(0%); }

    /* SECTION TITLE */
    .section-title { font-size: 0.95rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.15em;
      color: var(--text-muted); margin-bottom: 1.25rem; display: flex; align-items: center; gap: 0.75rem; 
      text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
    .section-title::after { content: ''; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border), transparent); }

    /* LAYOUT */
    .dual-col { display: grid; grid-template-columns: 1fr 380px; gap: 2rem; margin-bottom: 2.5rem; }

    /* CARD COMPONENTS */
    .card-header { padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.25);
      font-size: 0.9rem; font-weight: 600; display: flex; justify-content: space-between; align-items: center; letter-spacing: 0.05em; flex-wrap: wrap; gap: 0.5rem; }
    .badge { font-size: 0.75rem; padding: 0.25rem 0.75rem; border-radius: 999px; background: rgba(255,255,255,0.08); 
      font-weight: 600; box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.05); }

    /* TABLE */
    .table-wrapper { position: relative; }
    .table-wrapper::after { content: ''; position: absolute; top: 0; right: 0; bottom: 0; width: 30px;
      background: linear-gradient(90deg, transparent, var(--bg)); pointer-events: none; opacity: 0; transition: opacity 0.3s; z-index: 15; }
    .table-wrapper.has-scroll::after { opacity: 1; }
    .table-container { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 0 0 var(--radius) var(--radius); }
    table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.85rem; min-width: 850px; }
    thead th { position: sticky; top: 0; padding: 0.85rem 1rem; text-align: left; font-size: 0.72rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted);
      background: rgba(10, 15, 24, 0.95); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); z-index: 20; }
    tbody tr { transition: all 0.2s ease; position: relative; }
    tbody tr::after { content: ''; position: absolute; bottom: 0; left: 1rem; right: 1rem; height: 1px; background: var(--border); opacity: 0.5; }
    tbody tr:last-child::after { display: none; }
    tbody tr:hover { background: rgba(255,255,255,0.04); transform: scale(1.005); z-index: 10; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
    tbody td { padding: 0.75rem 1rem; font-family: var(--mono); font-size: 0.78rem;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 220px; }

    /* BUTTONS & ACTIONS */
    .btn-view { display: inline-flex; align-items: center; justify-content: center; gap: 6px; background: linear-gradient(135deg, rgba(129,140,248,0.2), rgba(56,189,248,0.2)); border: 1px solid rgba(129,140,248,0.4); color: var(--accent); padding: 6px 14px; border-radius: 8px; cursor: pointer; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em; transition: transform 0.2s, box-shadow 0.2s; text-transform: uppercase; white-space: nowrap; margin-top: 4px; }
    .btn-view:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(129,140,248,0.3); background: linear-gradient(135deg, rgba(129,140,248,0.3), rgba(56,189,248,0.3)); }

    /* METHOD & STATUS BADGES */
    .method { display: inline-flex; align-items: center; justify-content: center; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em; min-width: 55px; }
    .m-GET    { background: rgba(52, 211, 153, 0.15); color: var(--success); border: 1px solid rgba(52, 211, 153, 0.3); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); }
    .m-POST   { background: rgba(129, 140, 248, 0.15); color: var(--accent2); border: 1px solid rgba(129, 140, 248, 0.3); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1); }
    .m-PUT    { background: rgba(251, 191, 36, 0.15); color: var(--warn); border: 1px solid rgba(251, 191, 36, 0.3); }
    .m-DELETE { background: rgba(251, 113, 133, 0.15);  color: var(--danger); border: 1px solid rgba(251, 113, 133, 0.3); }
    .m-PATCH  { background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }
    .m-OTHER  { background: rgba(148, 163, 184, 0.15);color: var(--text-muted); border: 1px solid rgba(148, 163, 184, 0.3); }

    .status-badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; border: 1px solid transparent; box-shadow: inset 0 1px 0 rgba(255,255,255,0.05); }
    .s-malicious  { background: rgba(251, 113, 133, 0.15);  color: var(--danger); border-color: rgba(251, 113, 133, 0.3); box-shadow: 0 0 15px rgba(251, 113, 133, 0.15), inset 0 1px 0 rgba(255,255,255,0.1); }
    .s-suspicious { background: rgba(251, 191, 36, 0.15); color: var(--warn); border-color: rgba(251, 191, 36, 0.3); }
    .s-safe       { background: rgba(52, 211, 153, 0.15); color: var(--success); border-color: rgba(52, 211, 153, 0.3); box-shadow: 0 0 10px rgba(52, 211, 153, 0.1), inset 0 1px 0 rgba(255,255,255,0.1); }

    /* RESPONSE TYPE BADGES */
    .resp-badge { display: inline-flex; align-items: center; gap: 4px; padding: 0.2rem 0.55rem; border-radius: 6px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; border: 1px solid transparent; }
    .rt-sql     { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border-color: rgba(56, 189, 248, 0.3); }
    .rt-file    { background: rgba(52, 211, 153, 0.15); color: #34d399; border-color: rgba(52, 211, 153, 0.3); }
    .rt-auth    { background: rgba(129, 140, 248, 0.15); color: #818cf8; border-color: rgba(129, 140, 248, 0.3); }
    .rt-generic { background: rgba(148, 163, 184, 0.1); color: #94a3b8; border-color: rgba(148, 163, 184, 0.2); }
    .rt-fallback { background: rgba(251, 191, 36, 0.1); color: #fbbf24; border-color: rgba(251, 191, 36, 0.2); }

    /* SIDE PANELS & BARS */
    .side-panels { display: flex; flex-direction: column; gap: 2rem; }
    .list-panel { list-style: none; padding: 0.25rem 0; }
    .list-panel li { display: flex; align-items: center; justify-content: space-between;
      padding: 0.85rem 1.5rem; font-size: 0.85rem; position: relative; z-index: 1; border-bottom: 1px solid rgba(255,255,255,0.03); transition: background 0.2s; }
    .list-panel li:last-child { border-bottom: none; }
    .list-panel li:hover { background: rgba(255,255,255,0.03); }
    
    .lp-bar { position: absolute; top: 0; left: 0; bottom: 0; z-index: -1; 
      width: 0%; 
      border-radius: 0 6px 6px 0; transition: width 1s cubic-bezier(0.25, 0.8, 0.25, 1); }
    .bar-blue { background: linear-gradient(90deg, rgba(56, 189, 248, 0.15), transparent); border-right: 1px solid rgba(56, 189, 248, 0.3); }
    .bar-red  { background: linear-gradient(90deg, rgba(251, 113, 133, 0.15), transparent); border-right: 1px solid rgba(251, 113, 133, 0.3); }
    .bar-warn { background: linear-gradient(90deg, rgba(251, 191, 36, 0.15), transparent); border-right: 1px solid rgba(251, 191, 36, 0.3); }

    .lp-name { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px; font-weight: 500; }
    .lp-count { background: rgba(255,255,255,0.08); border-radius: 6px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-family: var(--mono); font-weight: 600; flex-shrink: 0; box-shadow: inset 0 1px 0 rgba(255,255,255,0.1), 0 2px 4px rgba(0,0,0,0.2); }

    /* EMPTY STATE */
    .empty-state { padding: 3rem 2rem; text-align: center; color: var(--text-muted); font-size: 0.95rem; font-weight: 500; }
    .empty-state .icon { font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.4; animation: float 6s infinite ease-in-out alternate; filter: grayscale(50%); }

    /* MODAL */
    .modal-overlay { position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.75); backdrop-filter: blur(12px); animation: fadeIn 0.2s ease-out; }
    .modal-content { background: rgba(17,24,39,0.95); border: 1px solid var(--border); border-radius: var(--radius); width: 95vw; max-width: 1300px; max-height: 85vh; display: flex; flex-direction: column; box-shadow: 0 25px 60px rgba(0,0,0,0.9); backdrop-filter: blur(20px); }
    .modal-header { padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.3); border-radius: var(--radius) var(--radius) 0 0; flex-shrink: 0; }
    .modal-header-info { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    .modal-close { background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: var(--text-muted); font-size: 1.2rem; cursor: pointer; transition: all 0.2s; padding: 0.4rem 0.8rem; border-radius: 8px; }
    .modal-close:hover { color: var(--danger); background: rgba(251,113,133,0.1); border-color: rgba(251,113,133,0.3); }
    .modal-body { padding: 1.5rem; overflow-y: auto; font-family: var(--mono); font-size: 0.85rem; color: #c4d4e8; white-space: pre-wrap; word-break: break-all; line-height: 1.6; flex: 1; }

    /* NAVBAR */
    .navbar { display: flex; gap: 0.5rem; justify-content: center; padding: 0.75rem 2.5rem; background: rgba(0,0,0,0.5); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 99; backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); overflow-x: auto; white-space: nowrap; -ms-overflow-style: none; scrollbar-width: none; }
    .navbar::-webkit-scrollbar { display: none; }
    .nav-link { color: var(--text-muted); text-decoration: none; font-weight: 600; font-size: 0.82rem; padding: 0.5rem 1rem; border-radius: 8px; transition: all 0.2s; display: inline-flex; align-items: center; gap: 6px; border: 1px solid transparent; flex-shrink: 0; }
    .nav-link:hover, .nav-link.active { background: rgba(56, 189, 248, 0.1); color: var(--text); border-color: rgba(56, 189, 248, 0.3); }

    /* RESPONSIVE BREAKPOINTS */
    @media (max-width: 1200px) {
      .dual-col { grid-template-columns: 1fr !important; }
    }
    @media (max-width: 900px) {
      header { padding: 1rem 1.5rem; }
      main { padding: 1.5rem; }
      .stats-grid { grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; }
      .stat-value { font-size: 2rem; }
      .stat-card { padding: 1.25rem; }
      .card-header { padding: 1rem 1.25rem; font-size: 0.82rem; }
      table { min-width: 750px; }
      thead th { padding: 0.7rem 0.8rem; font-size: 0.68rem; }
      tbody td { padding: 0.6rem 0.8rem; font-size: 0.75rem; }
    }
    @media (max-width: 768px) {
      header { flex-direction: column; align-items: flex-start; gap: 0.75rem; padding: 1rem; position: relative; }
      .header-right { flex-direction: row; align-items: center; gap: 0.75rem; width: 100%; justify-content: space-between; }
      .navbar { padding: 0.5rem 0.75rem; gap: 0.25rem; justify-content: flex-start; }
      .nav-link { font-size: 0.75rem; padding: 0.4rem 0.8rem; }
      main { padding: 1rem; }
      .stats-grid { grid-template-columns: 1fr 1fr; gap: 0.75rem; }
      .stat-value { font-size: 1.75rem; }
      .stat-label { font-size: 0.68rem; margin-bottom: 0.4rem; }
      .section-title { font-size: 0.82rem; }
      .modal-content { width: 95vw; max-height: 90vh; border-radius: 12px; }
      .modal-header { padding: 1rem 1.25rem; }
      .modal-body { padding: 1rem; font-size: 0.78rem; }
    }
    @media (max-width: 480px) {
      .stats-grid { grid-template-columns: 1fr; }
      .logo-text { font-size: 1.1rem; }
      .logo-sub { font-size: 0.65rem; }
      .stat-icon { display: none; }
      .card-header { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
    }

    /* FOOTER */
    footer { text-align: center; padding: 2rem; font-size: 0.82rem; color: var(--text-muted); border-top: 1px solid var(--border); font-weight: 500; letter-spacing: 0.08em; margin-top: 3rem; background: rgba(0,0,0,0.2); }

    /* MICRO-ANIMATIONS */
    @keyframes slideUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
    .animate-in { animation: slideUp 0.4s ease-out; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    Chart.defaults.color = 'rgba(148, 163, 184, 0.8)';
    Chart.defaults.font.family = "'Outfit', sans-serif";
    let timelineChartInstance = null;
    let pieChartInstance = null;
    let radarChartInstance = null;
    let threatMap = null;
    let mapMarkers = [];
  </script>
</head>
<body>
<div class="glow-bg">
  <div class="blob blob-1"></div>
  <div class="blob blob-2"></div>
  <div class="blob blob-3"></div>
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
      <div class="card-header">Live Geo-IP Threat Map</div>
      <div id="threat-map" style="height: 380px; width: 100%; border-radius: 0 0 16px 16px; z-index: 1;"></div>
    </div>
  </div>
  <div class="dual-col" style="margin-bottom: 2.5rem;">
    <div class="card glass-panel" style="grid-column: 1 / -1;">
      <div class="card-header">Traffic Timeline (24h Window)</div>
      <div style="padding: 1.5rem; min-height: 260px;">
        <canvas id="timelineChart"></canvas>
      </div>
    </div>
  </div>
  
  <div class="dual-col" style="grid-template-columns: 1fr 1fr 1fr; margin-bottom: 2.5rem;">
    <div class="card glass-panel" style="min-height: 380px;">
      <div class="card-header">Attack Method Distribution</div>
      <div style="padding: 1.5rem; display: flex; justify-content: center; min-height: 320px;">
        <canvas id="pieChart"></canvas>
      </div>
    </div>
    <div class="card glass-panel" style="min-height: 380px;">
      <div class="card-header">Live Attack Radar</div>
      <div style="padding: 1.5rem; display: flex; justify-content: center; min-height: 320px;">
        <canvas id="radarChart"></canvas>
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
                <th>Threat Level</th>
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

    <!-- MITIGATION RULES -->
  <div id="mitigation" class="sessions-section" style="margin-top: 3.5rem; padding-top: 2rem; margin-bottom: 5rem;">
    <div class="section-title">🛡️ Auto-Generated Mitigation Rules</div>
    <div class="card glass-panel" style="padding: 1.5rem;">
      <div style="font-family: var(--mono); font-size: 0.85rem; color: #34d399; background: #000; padding: 1.5rem; border-radius: 8px; overflow-x: auto; white-space: pre;" id="waf-rules">
# Analyzing latest traffic and generating dynamic WAF rules...
      </div>
    </div>
  </div>

  <!-- MODAL INJECTION -->
  <div class="modal-overlay" id="response-modal" style="display:none;" onclick="closeModal(event)">
    <div class="modal-content" onclick="event.stopPropagation()">
      <div class="modal-header">
        <div class="modal-header-info">
          <h3 style="color:var(--accent);font-weight:600;font-size:1rem;letter-spacing:0.05em;">🎭 Deception Response</h3>
          <span class="resp-badge" id="modal-type-badge"></span>
        </div>
        <button class="modal-close" onclick="closeModal()" title="Close">✕</button>
      </div>
      <div class="modal-body" id="modal-text"></div>
    </div>
  </div>

</main>

<footer>
  CyberShield Platform &mdash; Adaptive Intelligence &mdash; Refreshes every 10s
</footer>

<script>
  let currentRequests = [];

  function respTypeClass(t) {
    if (!t) return 'rt-generic';
    const lower = t.toLowerCase();
    if (lower === 'sql') return 'rt-sql';
    if (lower === 'file') return 'rt-file';
    if (lower === 'auth') return 'rt-auth';
    if (lower === 'fallback' || lower.includes('fallback')) return 'rt-fallback';
    return 'rt-generic';
  }

  function respTypeIcon(t) {
    if (!t) return '🌐';
    const lower = t.toLowerCase();
    if (lower === 'sql') return '🗄️';
    if (lower === 'file') return '📂';
    if (lower === 'auth') return '🔐';
    if (lower === 'fallback' || lower.includes('fallback')) return '⚡';
    return '🌐';
  }

  function openModal(index) {
    const req = currentRequests[index];
    if (!req) return;
    const modal = document.getElementById('response-modal');
    document.getElementById('modal-text').innerHTML = `
      <div style="display:flex; gap: 1.5rem; height: 100%;">
         <div style="flex:1; border-right: 1px solid var(--border); padding-right: 1rem; overflow:hidden; display:flex; flex-direction:column;">
           <h4 style="color:var(--accent); margin-bottom: 0.5rem; text-transform:uppercase; font-size:12px; flex-shrink:0;">Raw Threat Payload</h4>
           <div style="flex:1; overflow-y:auto; background:rgba(0,0,0,0.3); border-radius:8px; padding:1rem; box-shadow:inset 0 2px 4px rgba(0,0,0,0.2);">
             <pre style="white-space:pre-wrap; word-break:break-all; font-size: 0.8rem; color:var(--danger); margin:0;">${(req.payload || req.endpoint || 'No payload')}</pre>
           </div>
         </div>
         <div style="flex:1.5; overflow:hidden; display:flex; flex-direction:column;">
           <h4 style="color:var(--success); margin-bottom: 0.5rem; text-transform:uppercase; font-size:12px; flex-shrink:0;">AI Rendered Deception</h4>
           <div style="flex:1; overflow-y:auto; overflow-x:auto; background:rgba(0,0,0,0.3); border-radius:8px; padding:1rem; box-shadow:inset 0 2px 4px rgba(0,0,0,0.2);">
             <pre style="white-space:pre-wrap; word-break:normal; font-size: 0.85rem; color:#e2e8f0; margin:0;">${(req.response || "No response generated.")}</pre>
           </div>
         </div>
      </div>
    `;
    const typeBadge = document.getElementById('modal-type-badge');
    const rt = req.response_type || 'unknown';
    typeBadge.className = 'resp-badge ' + respTypeClass(rt);
    typeBadge.textContent = respTypeIcon(rt) + ' ' + rt.toUpperCase();
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
  function statusClass(s) { return s === 'malicious' ? 's-malicious' : s === 'safe' ? 's-safe' : 's-suspicious'; }
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
      updateMapAndRules(rows);
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
            <span class="resp-badge ${respTypeClass(req.response_type)}">${respTypeIcon(req.response_type)} ${(req.response_type||'—').toUpperCase()}</span>
            ${req.response ? `<button class="btn-view" onclick="openModal(${i}); return false;">👁️ View</button>` : ''}
          </td>
          <td style="text-align:center;">
            ${(() => {
                let s = Math.max(req.detection_score || 0, req.ai_confidence_score || 0);
                if (s >= 0.8) return `<span class="badge s-malicious" style="background:#fb7185;color:#000;">CRIT (${Math.round(s*10)}/10)</span>`;
                if (s >= 0.5) return `<span class="badge s-suspicious" style="background:rgba(251, 191, 36, 0.2);color:var(--warn)">HIGH (${Math.round(s*10)}/10)</span>`;
                if (s >= 0.2) return `<span class="badge" style="color:var(--success);border-color:var(--success)">MED (${Math.round(s*10)}/10)</span>`;
                return `<span class="badge s-safe">LOW (${Math.round(s*10)}/10)</span>`;
            })()}
          </td>
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
      
      const ctx2 = document.getElementById('radarChart').getContext('2d');
      if (radarChartInstance) radarChartInstance.destroy();
      radarChartInstance = new Chart(ctx2, {
        type: 'radar',
        data: {
          labels: attackData.map(a => a.attack_type),
          datasets: [{
            label: 'Attack Density',
            data: attackData.map(a => a.count),
            backgroundColor: 'rgba(251, 113, 133, 0.2)',
            borderColor: '#fb7185',
            pointBackgroundColor: '#fb7185'
          }]
        },
        options: { maintainAspectRatio: false, responsive: true, scales: { r: { angleLines: { color: 'rgba(255,255,255,0.1)' }, grid: { color: 'rgba(255,255,255,0.1)' }, pointLabels: { color: 'rgba(255,255,255,0.7)', font: { size: 10 } } } }, plugins: { legend: { display: false } } }
      });
  }

  async function refresh() {
    await Promise.all([loadStats(), loadRequests(), loadSessions(), loadPending(), loadProfiles(), loadAnalytics(), loadAlerts()]);
    document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    document.getElementById('status-dot').style.background = 'var(--success)';
    document.getElementById('status-dot').style.boxShadow = '0 0 12px var(--success)';
  }
  function initMap() {
    if(document.getElementById('threat-map') && !threatMap) {
       threatMap = L.map('threat-map', {zoomControl: false}).setView([20, 0], 2);
       L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
         attribution: '&copy; OpenStreetMap', subdomains: 'abcd', maxZoom: 19
       }).addTo(threatMap);
    }
  }

  function updateMapAndRules(requests) {
    if(threatMap) {
      mapMarkers.forEach(m => m.remove());
      mapMarkers = [];
      requests.slice(0, 15).forEach(req => {
        if(req.source_ip) {
           let hash = 0;
           for(let i=0; i<req.source_ip.length; i++) { hash = req.source_ip.charCodeAt(i) + ((hash << 5) - hash); }
           let lat = Math.abs(hash % 100) - 50; // Keep roughly in populated areas
           let lng = ((hash >> 8) % 240) - 120;
           let marker = L.circleMarker([lat, lng], {
              radius: req.detection_score > 0.8 ? 8 : 5,
              fillColor: req.detection_score > 0.8 ? '#fb7185' : '#fbbf24',
              color: '#fff', weight: 1, opacity: 1, fillOpacity: 0.8
           }).addTo(threatMap);
           marker.bindPopup(`<b>IP:</b> ${req.source_ip}<br><b>Threat:</b> ${req.attack_type}`);
           mapMarkers.push(marker);
        }
      });
    }

    const rulesBlock = document.getElementById('waf-rules');
    if(rulesBlock && requests.length > 0) {
       let rules = `# Active Intelligent Firewall Rules Derived from Recent Traffic\\n\\n`;
       let blockedIPs = [...new Set(requests.filter(r => r.detection_score > 0.7).map(r => r.source_ip))].slice(0, 4);
       blockedIPs.forEach(ip => rules += `iptables -A INPUT -s ${ip} -j DROP # Auto-ban high threat score\\n`);
       
       let sqlHits = requests.filter(r => (r.attack_type||'').toLowerCase().includes('sql'));
       if(sqlHits.length > 0) rules += `\\nSecRule ARGS "@detectSQLi" "id:1001,deny,log,status:403" # Prevent observed SQL injection patterns\\n`;

       let travHits = requests.filter(r => (r.attack_type||'').toLowerCase().includes('traversal'));
       if(travHits.length > 0) rules += `SecRule REQUEST_URI "@rx (\\\\.\\\\./|\\\\.\\\\.\\\\|%2e%2e%2f)" "id:1003,deny,status:403" # Traversal detected\\n`;

       rulesBlock.textContent = rules;
    }
  }

  initMap();
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
