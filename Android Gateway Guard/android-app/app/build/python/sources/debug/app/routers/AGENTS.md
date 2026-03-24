# Routers

FastAPI endpoint modules. 5 routers expose `/api/*` endpoints.

## traffic.py
Collection control: start/stop, metrics stats, WebSocket streaming.
- POST `/api/traffic/start` - Init collection from configured source
- POST `/api/traffic/stop` - Halt collection and flush buffers
- GET `/api/traffic/stats` - Return traffic metrics (rate, volume)
- WS `/api/ws/traffic` - Real-time packet stream

## anomaly.py
Detection orchestration, event queries, severity filtering.
- POST `/api/anomaly/detect` - Trigger on-demand scan
- GET `/api/anomaly/events` - Fetch anomalies (severity, time range)
- DELETE `/api/anomaly/events/{id}` - Acknowledge event

## llm.py
AI chat, semantic analysis, report generation.
- POST `/api/llm/chat` - Text query with function calling
- POST `/api/llm/report` - Generate anomaly summary report

## system.py
Health checks, configuration management.
- GET `/api/system/health` - Liveness probe (200 OK)
- GET `/api/system/config` - Current YAML config snapshot
- PUT `/api/system/config` - Reload config (no restart)

## ws.py
WebSocket lifecycle, connection registry.
- WS `/api/ws/events` - Anomaly event broadcast
- WS `/api/ws/stats` - Real-time metrics stream
- GET `/api/ws/registry` - Active connections list

## Anti-pattern
Return HTTP 4xx/5xx for errors. Never return HTTP 200 with error payloads.
