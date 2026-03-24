# Backend Application Layer

FastAPI application implementing three-tier security pipeline: detection → understanding → dialogue.

## Architecture

- **Entry Point**: `main.py` - FastAPI app with CORS, routers, startup/shutdown hooks
- **API Routers**: HTTP endpoints (traffic, anomaly, llm, system)
- **Core Services**: Async collectors, parsers, detectors, LLM engine
- **Simulators**: CAN/Ethernet/V2X traffic generators
- **Models**: Pydantic schemas for validation

## Directory References

See subdirectory `AGENTS.md` files for detailed architecture:

- `routers/AGENTS.md` - API endpoint definitions
- `services/AGENTS.md` - Core service logic
- `simulators/AGENTS.md` - Traffic generation
- `models/AGENTS.md` - Data schemas

## Health & Monitoring

**Liveness**: `/health/live` - Process alive.

**Readiness**: `/health/ready` - Database, LLM engine, collectors available.

**Startup Checks**: Database connectivity, model files readable, required services accessible.

**Metrics**: Request counts, latency distributions, anomaly detection rates, connection pool utilization.

## Configuration

`config.yaml` with environment variable overrides (see `config.yaml`).

## Application Lifecycle

**Startup**: Database connection pool initialization, model loading, traffic collector warm-up, LLM engine initialization.

**Shutdown**: Graceful collector termination, pending packet processing flush, connection pool cleanup, model cache eviction.

**Signal Handling**: SIGTERM/SIGINT handlers ensure clean shutdown within 30s timeout.

## Middleware & Dependency Injection

**Middleware Stack**: Request timing, CORS, rate limiting, structured logging, exception handlers.

**Dependency Injection**: FastAPI `Depends()` for database sessions, configuration, LLM engine, security context, packet parsers.

**Security Plugins**: Token validation, role-based access control, API key authentication.

## Error Handling & Logging

**Error Categories**: Validation (422), Business (400), External (502), System (500).

**Logging Strategy**: Structured JSON logs via `structlog`, levels DEBUG/INFO/WARN/ERROR, correlation IDs per request, anomaly event logging.

**Exception Handlers**: Custom exceptions mapper to appropriate HTTP status codes with detailed error payloads.

## Database Connection Management

**Connection Pool**: SQLAlchemy async engine with 10-20 connection pool, 5s checkout timeout.

**Connection Lifecycle**: Per-request session via FastAPI dependencies, automatic context management, connection reuse via SessionScope.

**Health Monitoring**: Periodic connection pool stats logging, idle connection eviction, automatic reconnect on connection loss.
