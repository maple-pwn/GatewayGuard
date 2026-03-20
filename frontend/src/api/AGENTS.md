# API 客户端

## index.js — REST API 客户端

基于 Axios 的 CRUD 客户端。集中式配置，并自动附带认证请求头。

### 端点
- `/api/traffic` — 流量管理（GET、POST、DELETE）
- `/api/anomaly` — 异常获取与过滤（GET）
- `/api/llm` — LLM 查询、函数调用（POST）
- `/api/system` — 健康状态、配置、日志（GET/POST）

### 关键方法
```javascript
- getTraffic(filter)      // 流量流查询
- getAnomalies(severity)  // 严重等级过滤：critical/high/medium/low
- callLLM(prompt)         // 发送提示词 → 函数调用
- getSystemInfo()         // 健康状态 + 运行时长统计
```

---

## ws.js — WebSocket 客户端

具备韧性的实时流量流式处理客户端。

### 韧性模式
- **自动重连**: 指数退避（1 秒起步，最大 30 秒）
- **心跳**: 30 秒 ping/pong，连续丢失 3 次后清理失活连接
- **流恢复**: 重连时按最后时间戳同步

### 关键方法
```javascript
- connect()        // 初始化连接
- disconnect()     // 优雅关闭
- subscribe(cb)    // 流量数据包回调订阅
- sendHeartbeat()  // 手动发送心跳
```

### 事件
- `open` — 连接建立
- `message` — 收到流量数据包
- `close` — 优雅断开
- `reconnecting` — 正在退避重连
- `error` — 致命错误（不会自动重连）
