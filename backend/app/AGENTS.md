# Backend Application Layer

FastAPI application implementing three-tier security pipeline: detection → understanding → dialogue.

## Entry Point

`main.py` - FastAPI app with CORS, router registration, startup/shutdown lifecycle hooks

## API Routers

### traffic.py
- POST `/api/traffic/start` - Start traffic collection (simulator/CAN/Ethernet/PCAP)
- POST `/api/traffic/stop` - Stop collection
- GET `/api/traffic/stats` - Traffic statistics by protocol
- WebSocket `/api/traffic/stream` - Real-time packet streaming

### anomaly.py
- POST `/api/anomaly/start` - Enable anomaly detection
- POST `/api/anomaly/stop` - Disable detection
- GET `/api/anomaly/events` - Query anomaly events (filter by severity/time)
- GET `/api/anomaly/stats` - Detection statistics

### llm.py
- POST `/api/llm/chat` - Natural language security queries
- POST `/api/llm/analyze` - Semantic analysis of traffic patterns
- POST `/api/llm/report` - Generate security reports

### system.py
- GET `/api/system/health` - Health check
- GET `/api/system/config` - Current configuration

## Core Services

### collector.py
Traffic collection orchestrator with pluggable data sources:
- `start_collection(source_type)` - Initialize source (simulator/CAN/Ethernet/PCAP)
- `stop_collection()` - Graceful shutdown
- `get_stats()` - Aggregated traffic metrics
- Defensive: logs warnings on source init failures, continues with available sources

### traffic_parser.py
Multi-protocol parser producing UnifiedPacket abstraction:
- `parse_packet(raw_data, protocol)` - Protocol-specific parsing
- UnifiedPacket: (timestamp, protocol, source, dest, msg_id, payload, domain)
- Enables cross-protocol anomaly correlation

### anomaly_detector.py
Two-tier detection system:
1. **Rule-based**: Frequency thresholds, unknown IDs, payload anomalies
2. **ML-based**: Isolation Forest on 5D feature vector (byte entropy)
- `detect(packet)` - Returns AnomalyEvent or None
- `update_model(packets)` - Retrain Isolation Forest

### llm_engine.py
LLM integration with function calling (ReAct pattern):
- `chat(message, history)` - Conversational interface
- `analyze(context)` - Semantic analysis
- Tools: `query_traffic_stats(protocol, time_range)`, `get_anomaly_events(severity, limit)`
- Dual provider: OpenAI API or Ollama (local)

## Simulators

### can_simulator.py
CAN bus traffic generator:
- Normal patterns: periodic messages (0x100-0x7FF)
- Attack patterns: DoS flooding, spoofing, replay

### ethernet_simulator.py
Automotive Ethernet/SOME-IP simulator:
- Service discovery messages
- Method call/response patterns

### v2x_simulator.py
V2X communication simulator:
- BSM (Basic Safety Message)
- CAM (Cooperative Awareness Message)

## Models

Pydantic schemas for request/response validation:
- `Packet` - Unified packet representation
- `AnomalyEvent` - Detection result with severity/confidence
- `ChatRequest/ChatResponse` - LLM interaction

## Configuration

`config.yaml` loaded at startup, environment variables override:
- App settings (host, port)
- LLM provider (openai/ollama) with API keys
- Detector thresholds (frequency_threshold, iforest_contamination)
- CORS origins
