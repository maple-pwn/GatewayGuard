# GatewayGuard Frontend Views

## Views

### Dashboard.vue
Real-time traffic visualization with ECharts (line/bar charts), start/stop controls for traffic capture, live protocol distribution monitoring.

**Implementation**: Uses composable `useTrafficStore` for state management; fetches via `/api/traffic/stats` and `/api/traffic/protocol` endpoints; reactive refs for chart configs; lifecycle hooks for auto-refresh interval management.

### Anomaly.vue
Anomaly event display with severity filtering (critical/high/medium/low), event triage workflow, detailed event inspection panel, bulk action support.

**Implementation**: Composable `useAnomalyStore` with pagination and filter state; `/api/anomalies` API integration with debounced search; event详情 modal via Element Plus Dialog; bulk action API calls with optimistic update pattern.

### Chat.vue
AI-powered security chat interface with natural language queries (`query_traffic_stats`, `get_anomaly_events`), semantic analysis, entity extraction, ReAct-style reasoning display.

**Implementation**: `useChatStore` manages message history and LLM state; async streaming response handling; ReAct reasoning tree rendering; form validation for time range parameters; error fallback with user-friendly messages.

## Stack
Vue 3 + Element Plus + ECharts

**Routing**: `/dashboard`, `/anomaly`, `/chat` via `vue-router` with lazy-loaded components; navigation guards for auth check; keep-alive for session persistence on Chat view.

**Data Flow**: API responses → store mutation → computed properties → reactive templates; WebSocket optional for real-time traffic push.

**Components**: Dashboard uses `TrafficChart`, `ProtocolDistribution`, `CaptureControl` sub-components; Anomaly uses `EventTable`, `FilterSidebar`, `EventDetails` sub-components; Chat uses `MessageList`, `InputBar`, `ReasoningPanel` sub-components.
