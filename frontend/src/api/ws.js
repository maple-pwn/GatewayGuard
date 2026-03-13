/**
 * WebSocket 实时数据客户端
 *
 * 自动重连 + 事件分发，替代 3 秒轮询机制。
 */

const WS_BASE = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`
const WS_URL = `${WS_BASE}/ws/realtime`

const RECONNECT_BASE = 1000
const RECONNECT_MAX = 10000

export function createRealtimeWs() {
  let ws = null
  let reconnectDelay = RECONNECT_BASE
  let closed = false
  let pingTimer = null

  const listeners = {}

  function on(event, cb) {
    if (!listeners[event]) listeners[event] = []
    listeners[event].push(cb)
  }

  function off(event, cb) {
    if (!listeners[event]) return
    listeners[event] = listeners[event].filter(fn => fn !== cb)
  }

  function emit(event, data) {
    if (!listeners[event]) return
    for (const cb of listeners[event]) {
      try { cb(data) } catch (e) { console.error('ws listener error:', e) }
    }
  }

  function connect() {
    if (closed) return
    emit('state', 'connecting')

    ws = new WebSocket(WS_URL)

    ws.onopen = () => {
      reconnectDelay = RECONNECT_BASE
      emit('state', 'connected')
      startPing()
    }

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data)
        if (msg.type === 'pong') return
        emit(msg.type, msg.data)
      } catch { /* ignore malformed */ }
    }

    ws.onclose = () => {
      stopPing()
      emit('state', 'disconnected')
      scheduleReconnect()
    }

    ws.onerror = () => {
      ws.close()
    }
  }

  function scheduleReconnect() {
    if (closed) return
    setTimeout(() => {
      reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX)
      connect()
    }, reconnectDelay)
  }

  function startPing() {
    stopPing()
    pingTimer = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }))
      }
    }, 30000)
  }

  function stopPing() {
    if (pingTimer) {
      clearInterval(pingTimer)
      pingTimer = null
    }
  }

  function close() {
    closed = true
    stopPing()
    if (ws) {
      ws.onclose = null
      ws.close()
      ws = null
    }
  }

  connect()

  return { on, off, close }
}
