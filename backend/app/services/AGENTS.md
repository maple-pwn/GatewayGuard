# Services - Core Business Logic

## Overview
Async-first services layer implementing traffic orchestration, multi-protocol parsing, two-tier anomaly detection, LLM integration, and WebSocket management.

---

## CollectorService
Traffic orchestrator with pluggable data sources (simulator/CAN/Ethernet/PCAP). Manages collection lifecycle (start/stop/status). Graceful degradation on source init failures—logs warning, continues with available sources.

## TrafficParserService
Protocol boundary normalizer. Parses CAN/Ethernet/V2X frames → UnifiedPacket abstraction (7-element: timestamp/protocol/source/dest/msg_id/payload/domain). Loop-level exception handling skips malformed packets, logs warning, continues stream.

## AnomalyDetectorService
Two-tier detection pipeline. Rule-based detector (frequency thresholds/unknown IDs/payload anomalies) + Isolation Forest ML (5D entropy features). cull_events() filters duplicates by msg_id/time window. All detections stored in DB for LLM retrieval.

## LLMEngine
OpenAI/Ollama adapter with function calling. Implements ReAct pattern: query_traffic_stats(protocol,time_range), get_anomaly_events(severity,limit). Configurable provider via config.yaml. Graceful fallback if LLM unavailable—returns empty results, logs warning.

## WSManager
WebSocket connection registry with heartbeat (30s interval) and cleanup (stale > 2×interval). Thread-safe connection map. Cleanup runs on schedule; individual connections removed on disconnect heartbeat timeout.

---

## Resilience Patterns
- **Graceful degradation**: Service init failures → warning log, continue with partial capability
- **Loop-level catches**: Collection/parsing loops catch exceptions, log, skip, continue
- **Unbounded retries**: No hard failures—always fallback to available functionality
- **DB as truth**: All detections/states persisted; in-memory caches are ephemeral

## Async Contract
All services exposed as async methods. No blocking calls. Use `asyncio.create_task()` for background operations (cleanup, heartbeat).
