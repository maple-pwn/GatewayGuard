# Data Models - GatewayGuard

## Core Abstractions

**UnifiedPacket** - 7-element cross-protocol abstraction:
- `timestamp` - millisecond precision
- `protocol` - "CAN", "ETH", "V2X", "RAW"
- `source` - sender identifier
- `dest` - receiver identifier  
- `msg_id` - message/frame ID
- `payload` - bytes payload
- `domain` - security domain (vehicle, network, application)

**AnomalyEvent** - Detector output with severity mapping:
- `severity` - "critical" | "high" | "medium" | "low"
- `detector` - rule-based | isoforest | hybrid
- `confidence` - 0.0-1.0
- `source_packets` - list of triggering packet IDs

## SQLAlchemy ORMs (Persistence)

- **PacketORM** - SQLite table: packets (id, timestamp, protocol, source, dest, msg_id, payload_raw, domain)
- **AnomalyEventORM** - SQLite table: anomaly_events (id, severity, detector, confidence, source_packets_json, created_at)
- **AnalysisReportORM** - SQLite table: analysis_reports (id, report_type, summary, content_json, created_at)
- **ChatHistoryORM** - SQLite table: chat_history (id, role, message, metadata_json, timestamp)

## Pydantic Schemas (API Layer)

- `Packet` - validated UnifiedPacket
- `AnomalyEvent` - validated event with severity
- `AnalysisReport` - report generation output
- `ChatMessage` - chat history entry

## Naming Convention

- **`*ORM` suffix** - SQLAlchemy persistence models
- **No suffix** - Pydantic API schemas
