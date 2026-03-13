# API Clients

## index.js — REST API Client

Axios-based client for CRUD operations. Centralized config with auto-auth headers.

### Endpoints
- `/api/traffic` — Traffic management (GET, POST, DELETE)
- `/api/anomaly` — Anomaly fetching, filtering (GET)
- `/api/llm` — LLM queries, function calling (POST)
- `/api/system` — Health, config, logs (GET/POST)

### Key Methods
```javascript
- getTraffic(filter)      // Traffic stream queries
- getAnomalies(severity)  // Severity filter: critical/high/medium/low
- callLLM(prompt)         // Send prompt → function calling
- getSystemInfo()         // Health + uptime stats
```

---

## ws.js — WebSocket Client

Real-time traffic streaming with resilience.

### Resilience Patterns
- **Auto-reconnect**: Exponential backoff (1s→30s cap)
- **Heartbeat**: 30s ping/pong, dead peer cleanup after 3× missed
- **Stream recovery**: Last timestamp sync on reconnect

### Key Methods
```javascript
- connect()        // Initiate connection
- disconnect()     // Graceful close
- subscribe(cb)    // Traffic packet callbacks
- sendHeartbeat()  // Manual heartbeat
```

### Events
- `open` — Connection established
- `message` — Traffic packet received
- `close` — Graceful disconnect
- `reconnecting` — Backoff in progress
- `error` — Fatal error (no auto-reconnect)
