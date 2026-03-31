"""
HTML layout structures for Chart.js rendering within Dashboard.
"""

def get_charts_html() -> str:
    return """
    <!-- ANALYTICS SECTION -->
    <div class="section-title" style="margin-top: 2rem;">📈 Analytics & Threat Feed</div>
    <div class="dual-col" style="margin-bottom: 2rem;">
      <div class="card glass-panel" style="grid-column: 1 / -1; padding-bottom: 1rem;">
        <div class="card-header">Traffic Timeline (24h Window)</div>
        <div style="padding: 1.5rem; height: 180px;">
          <canvas id="timelineChart"></canvas>
        </div>
      </div>
    </div>
    
    <div class="dual-col" style="grid-template-columns: 1fr 1fr;">
      <div class="card glass-panel" style="height: 320px;">
        <div class="card-header">Attack Method Distribution</div>
        <div style="padding: 1.5rem; display: flex; justify-content: center; height: 260px;">
          <canvas id="pieChart"></canvas>
        </div>
      </div>
      <div class="card glass-panel" style="height: 320px; overflow: hidden;">
        <div class="card-header">Critical Alerts Feed</div>
        <ul class="list-panel" id="alerts-list" style="overflow-y: auto; height: 100%;">
          <li><span class="lp-name" style="color:var(--success)">System Secure — Monitoring Active</span></li>
        </ul>
      </div>
    </div>
    """
