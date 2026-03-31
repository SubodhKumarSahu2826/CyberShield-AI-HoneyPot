This directory stores runtime logs from all honeypot platform services.

Files written here:
  - honeypot.log   — structured JSON logs from the capture service
  - api.log        — API service request logs (future)
  - dashboard.log  — dashboard service logs (future)

Logs are mounted via Docker volume (logs-data) and persist across container restarts.
