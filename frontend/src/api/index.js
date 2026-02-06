import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export const trafficApi = {
  getStats: () => api.get('/traffic/stats'),
  getPackets: (params) => api.get('/traffic/packets', { params }),
  simulate: (scenario, count) =>
    api.post(`/traffic/simulate?scenario=${scenario}&count=${count}`),
  collectStart: (mode) =>
    api.post(`/traffic/collect/start${mode ? '?mode=' + mode : ''}`),
  collectStop: () => api.post('/traffic/collect/stop'),
  collectStatus: () => api.get('/traffic/collect/status'),
  importFile: (filePath) =>
    api.post(`/traffic/import?file_path=${encodeURIComponent(filePath)}`),
}

export const anomalyApi = {
  getEvents: (params) => api.get('/anomaly/events', { params }),
  getDetail: (id) => api.get(`/anomaly/events/${id}`),
  detect: (limit) => api.post(`/anomaly/detect?limit=${limit || 500}`),
}

export const llmApi = {
  analyze: (eventId) => api.post(`/llm/analyze?event_id=${eventId}`),
  report: (limit) => api.post(`/llm/report?limit=${limit || 10}`),
  chat: (message, sessionId) =>
    api.post('/llm/chat', null, { params: { message, session_id: sessionId } }),
}

export const systemApi = {
  getStatus: () => api.get('/system/status'),
  clearData: () => api.delete('/system/clear-data'),
  clearPackets: (params) => api.delete('/system/clear-packets', { params }),
  clearAnomalies: (params) => api.delete('/system/clear-anomalies', { params }),
}
