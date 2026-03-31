"""
Scripts and dependencies for charting rendering (Chart.js injection).
"""

def get_chart_js_scripts() -> str:
    """Returns required scripts to initialize Chart.js onto the DOM."""
    return """
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
      Chart.defaults.color = 'rgba(148, 163, 184, 0.8)';
      Chart.defaults.font.family = "'Outfit', sans-serif";
      let timelineChartInstance = null;
      let pieChartInstance = null;
    </script>
    """
