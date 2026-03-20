# GatewayGuard 前端视图

## 视图

### Dashboard.vue
使用 ECharts 进行实时流量可视化（折线图/柱状图），提供流量采集启动/停止控制，并实时监控协议分布。

**实现方式**: 使用组合式函数 `useTrafficStore` 进行状态管理；通过 `/api/traffic/stats` 和 `/api/traffic/protocol` 端点获取数据；使用响应式 `ref` 管理图表配置；通过生命周期钩子管理自动刷新间隔。

### Anomaly.vue
异常事件展示视图，支持严重等级过滤（critical/high/medium/low）、事件分诊流程、详细事件检查面板和批量操作。

**实现方式**: 组合式函数 `useAnomalyStore` 管理分页和过滤状态；集成 `/api/anomalies` API 并配合防抖搜索；通过 Element Plus Dialog 展示事件详情弹窗；批量操作 API 调用采用乐观更新模式。

### Chat.vue
AI 驱动的安全对话界面，支持自然语言查询（`query_traffic_stats`、`get_anomaly_events`）、语义分析、实体提取和 ReAct 风格推理展示。

**实现方式**: `useChatStore` 管理消息历史和 LLM 状态；处理异步流式响应；渲染 ReAct 推理树；对时间范围参数做表单校验；出现错误时提供用户友好的回退提示。

## 技术栈
Vue 3 + Element Plus + ECharts

**路由**: 通过 `vue-router` 提供 `/dashboard`、`/anomaly`、`/chat` 路由，并对组件进行懒加载；使用导航守卫进行认证检查；在 Chat 视图上通过 keep-alive 保持会话状态。

**数据流**: API 响应 → store 变更 → 计算属性 → 响应式模板；WebSocket 可选用于实时流量推送。

**组件**: Dashboard 使用 `TrafficChart`、`ProtocolDistribution`、`CaptureControl` 子组件；Anomaly 使用 `EventTable`、`FilterSidebar`、`EventDetails` 子组件；Chat 使用 `MessageList`、`InputBar`、`ReasoningPanel` 子组件。
