<template>
  <div class="dashboard-page">
    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">监测总览</div>
          <div class="section-head__desc">
            按协议域拆解当前报文规模、采集状态与攻击演练入口。
          </div>
        </div>
      </div>

      <el-row :gutter="18">
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">总报文数</div>
            <div class="metric-card__value">{{ stats.total_packets }}</div>
            <div class="metric-card__meta">当前数据库中的全量采集记录</div>
            <div class="metric-card__accent">Telemetry Archive</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">CAN 报文</div>
            <div class="metric-card__value">{{ stats.can_count }}</div>
            <div class="metric-card__meta">关键控制域与网关通信主链路</div>
            <div class="metric-card__accent">Bus Priority</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">以太网报文</div>
            <div class="metric-card__value">{{ stats.eth_count }}</div>
            <div class="metric-card__meta">车载以太网与服务化通信数据</div>
            <div class="metric-card__accent">Service Network</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">V2X 报文</div>
            <div class="metric-card__value">{{ stats.v2x_count }}</div>
            <div class="metric-card__meta">外部协同通信与道路侧交互流量</div>
            <div class="metric-card__accent">Road Intelligence</div>
          </el-card>
        </el-col>
      </el-row>
    </section>

    <section class="section-block dashboard-grid">
      <el-card class="panel-card control-panel">
        <template #header>
          <div class="panel-header">
            <div>
              <div class="panel-header__title">实时采集控制台</div>
              <div class="panel-header__desc">统一管理在线采集模式、导入任务与 WebSocket 链路状态。</div>
            </div>
            <div class="status-line">
              <el-tag :type="wsStateTag" effect="plain">{{ wsStateLabel }}</el-tag>
              <el-tag :type="collectStatus.running ? 'success' : 'info'" effect="dark">
                {{ collectStatus.running ? '采集中' : '已停止' }}
              </el-tag>
            </div>
          </div>
        </template>

        <div class="control-layout">
          <div class="control-form">
            <div class="control-field">
              <label>数据源模式</label>
              <el-select v-model="sourceMode" :disabled="collectStatus.running">
                <el-option label="模拟器" value="simulator" />
                <el-option label="CAN 总线" value="can" />
                <el-option label="以太网" value="ethernet" />
                <el-option label="PCAP 文件" value="pcap" />
                <el-option label="多源混合" value="multi" />
              </el-select>
            </div>

            <div class="control-actions">
              <el-button
                type="success"
                @click="startCollect"
                :loading="collectLoading"
                :disabled="collectStatus.running"
              >
                启动采集
              </el-button>
              <el-button
                type="danger"
                @click="stopCollect"
                :loading="collectLoading"
                :disabled="!collectStatus.running"
              >
                停止采集
              </el-button>
              <el-button type="warning" plain @click="showImportDialog = true">
                导入抓包文件
              </el-button>
            </div>
          </div>

          <div class="signal-board">
            <div class="signal-board__item">
              <span>已采集</span>
              <strong>{{ collectStatus.total_collected || 0 }}</strong>
            </div>
            <div class="signal-board__item">
              <span>异常数</span>
              <strong>{{ collectStatus.total_anomalies || 0 }}</strong>
            </div>
            <div class="signal-board__item">
              <span>当前模式</span>
              <strong>{{ sourceMode.toUpperCase() }}</strong>
            </div>
          </div>
        </div>
      </el-card>

      <el-card class="panel-card panel-card--dark scenario-panel">
        <div class="scenario-panel__eyebrow">Threat Simulation</div>
        <h3>攻击演练与检测触发</h3>
        <p>以补天式门户首页的“核心能力入口”逻辑组织模拟、检测和清理动作，让关键操作集中可见。</p>

        <div class="scenario-field">
          <label>演练场景</label>
          <el-select v-model="scenario">
            <el-option label="正常流量" value="normal" />
            <el-option label="DoS 攻击" value="dos" />
            <el-option label="Fuzzy 攻击" value="fuzzy" />
            <el-option label="Spoofing 攻击" value="spoofing" />
            <el-option label="混合场景" value="mixed" />
          </el-select>
        </div>

        <div class="scenario-actions">
          <el-button type="primary" @click="simulateTraffic" :loading="simLoading">
            生成模拟流量
          </el-button>
          <el-button type="danger" @click="runDetection" :loading="detectLoading">
            执行异常检测
          </el-button>
        </div>

        <div v-if="detectResult" class="scenario-result">
          <el-alert
            :title="`检测完成，发现 ${detectResult.detected} 个异常`"
            :type="detectResult.detected > 0 ? 'warning' : 'success'"
            show-icon
            :closable="false"
          />
        </div>

        <div class="scenario-clean">
          <el-dropdown split-button type="info" plain @click="clearData">
            清空全部数据
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="showPartialClean = true">按条件清理</el-dropdown-item>
                <el-dropdown-item @click="keepRecent(500)">仅保留最近 500 条</el-dropdown-item>
                <el-dropdown-item @click="keepRecent(100)">仅保留最近 100 条</el-dropdown-item>
                <el-dropdown-item divided @click="clearByProtocol('CAN')">删除所有 CAN 报文</el-dropdown-item>
                <el-dropdown-item @click="clearByProtocol('ETH')">删除所有 ETH 报文</el-dropdown-item>
                <el-dropdown-item @click="clearByProtocol('V2X')">删除所有 V2X 报文</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-card>
    </section>

    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">实时告警流</div>
          <div class="section-head__desc">以时间线方式呈现最近告警，适合安全运营场景快速浏览。</div>
        </div>
        <el-button text @click="realtimeAlerts = []" :disabled="!realtimeAlerts.length">清空记录</el-button>
      </div>

      <el-card class="panel-card alert-card">
        <div v-if="realtimeAlerts.length" class="alert-stream">
          <div v-for="(alert, idx) in realtimeAlerts" :key="idx" class="alert-item">
            <div class="alert-item__marker" :class="`severity-${alert.severity}`" />
            <div class="alert-item__body">
              <div class="alert-item__meta">
                <el-tag :type="severityColor(alert.severity)" size="small">{{ alert.severity }}</el-tag>
                <span>{{ new Date(alert.timestamp * 1000).toLocaleTimeString() }}</span>
              </div>
              <div class="alert-item__text">{{ alert.description }}</div>
            </div>
          </div>
        </div>
        <el-empty v-else description="当前没有新的实时告警" />
      </el-card>
    </section>

    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">最近流量记录</div>
          <div class="section-head__desc">保留原有表格能力，但换成更整洁的门户化表格容器。</div>
        </div>
      </div>

      <el-card class="panel-card table-card">
        <el-table :data="packets" stripe style="width: 100%" max-height="460">
          <el-table-column prop="protocol" label="协议" width="90" />
          <el-table-column prop="source" label="源节点" width="140" />
          <el-table-column prop="destination" label="目标节点" width="140" />
          <el-table-column prop="msg_id" label="消息 ID" width="140" />
          <el-table-column prop="domain" label="功能域" width="120" />
          <el-table-column label="时间" width="200">
            <template #default="{ row }">
              {{ new Date(row.timestamp * 1000).toLocaleString() }}
            </template>
          </el-table-column>
          <el-table-column label="状态概览" min-width="200">
            <template #default="{ row }">
              <span class="packet-summary">
                {{ row.protocol }} / {{ row.domain || 'unknown' }} / {{ row.source || '-' }}
              </span>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </section>

    <el-dialog v-model="showPartialClean" title="按条件清理数据" width="480px">
      <el-form label-width="100px">
        <el-form-item label="清理目标">
          <el-radio-group v-model="cleanTarget">
            <el-radio value="packets">流量报文</el-radio>
            <el-radio value="anomalies">异常事件</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="清理方式">
          <el-radio-group v-model="cleanMode">
            <el-radio value="keep_recent">保留最近N条</el-radio>
            <el-radio value="by_type">按类型删除</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="cleanMode === 'keep_recent'" label="保留条数">
          <el-input-number v-model="keepCount" :min="10" :max="5000" :step="50" />
        </el-form-item>
        <el-form-item v-if="cleanMode === 'by_type' && cleanTarget === 'packets'" label="协议">
          <el-select v-model="cleanProtocol">
            <el-option label="CAN" value="CAN" />
            <el-option label="ETH" value="ETH" />
            <el-option label="V2X" value="V2X" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="cleanMode === 'by_type' && cleanTarget === 'anomalies'" label="严重程度">
          <el-select v-model="cleanSeverity">
            <el-option label="低 (low)" value="low" />
            <el-option label="中 (medium)" value="medium" />
            <el-option label="高 (high)" value="high" />
            <el-option label="严重 (critical)" value="critical" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPartialClean = false">取消</el-button>
        <el-button type="danger" @click="doPartialClean">确认清理</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showImportDialog" title="导入抓包文件" width="480px">
      <el-form label-width="100px">
        <el-form-item label="文件路径">
          <el-input
            v-model="importFilePath"
            placeholder="服务器上的文件路径，如 /data/capture.pcap"
          />
        </el-form-item>
        <el-form-item>
          <span class="dialog-tip">支持格式: .pcap / .pcapng / .blf / .asc</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showImportDialog = false">取消</el-button>
        <el-button type="primary" @click="doImportFile" :loading="importLoading">
          导入
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { trafficApi, anomalyApi, systemApi } from '../api/index.js'
import { createRealtimeWs } from '../api/ws.js'
import { ElMessage, ElMessageBox, ElNotification } from 'element-plus'

const stats = ref({ total_packets: 0, can_count: 0, eth_count: 0, v2x_count: 0 })
const packets = ref([])
const scenario = ref('mixed')
const simLoading = ref(false)
const detectLoading = ref(false)
const clearLoading = ref(false)
const detectResult = ref(null)
const showPartialClean = ref(false)
const cleanTarget = ref('packets')
const cleanMode = ref('keep_recent')
const keepCount = ref(200)
const cleanProtocol = ref('CAN')
const cleanSeverity = ref('low')
const sourceMode = ref('simulator')
const collectStatus = ref({ running: false, total_collected: 0, total_anomalies: 0 })
const collectLoading = ref(false)
const showImportDialog = ref(false)
const importFilePath = ref('')
const importLoading = ref(false)
let pollTimer = null

const wsState = ref('disconnected')
const realtimeAlerts = ref([])
let rtWs = null

const wsStateTag = computed(() => ({
  connected: 'success', connecting: 'warning', disconnected: 'danger',
}[wsState.value] || 'info'))

const wsStateLabel = computed(() => ({
  connected: 'WS 已连接', connecting: 'WS 连接中', disconnected: 'WS 断开',
}[wsState.value] || 'WS 未知'))

function severityColor(s) {
  return { critical: 'danger', high: 'warning', medium: '', low: 'info' }[s] || 'info'
}

async function loadData() {
  try {
    const [s, p] = await Promise.all([
      trafficApi.getStats(),
      trafficApi.getPackets({ limit: 50 }),
    ])
    stats.value = s.data
    packets.value = p.data
  } catch (e) {
    console.error(e)
  }
}

async function simulateTraffic() {
  simLoading.value = true
  try {
    const res = await trafficApi.simulate(scenario.value, 200)
    const generated = Number(res?.data?.generated || 0)
    ElMessage.success(`已生成 ${generated} 条模拟流量`)
    await loadData()
  } catch (e) {
    ElMessage.error('生成模拟流量失败')
  } finally {
    simLoading.value = false
  }
}

async function runDetection() {
  detectLoading.value = true
  try {
    const res = await anomalyApi.detect(500)
    detectResult.value = res.data
    ElMessage.success(`检测完成，发现 ${res?.data?.detected ?? 0} 个异常`)
  } catch (e) {
    const status = e?.response?.status
    const detail = e?.response?.data?.detail

    if (status === 428) {
      ElMessageBox.alert(
        '检测器当前未完成训练，暂时无法执行异常检测。\n\n请先调用后端训练接口 POST /api/anomaly/train，训练完成后再点击“执行异常检测”。',
        '检测器未训练',
        {
          confirmButtonText: '知道了',
          type: 'warning',
        },
      )
      return
    }

    ElMessage.error(detail || '执行异常检测失败')
  } finally {
    detectLoading.value = false
  }
}

async function clearData() {
  try {
    await ElMessageBox.confirm('确定要清空所有数据吗？此操作不可恢复。', '清空数据', {
      confirmButtonText: '确定清空',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch {
    return
  }

  clearLoading.value = true
  try {
    const res = await systemApi.clearData()
    ElMessage.success(`数据已清空: ${JSON.stringify(res.data.cleared)}`)
    detectResult.value = null
    await loadData()
  } catch (e) {
    ElMessage.error('清空数据失败')
  } finally {
    clearLoading.value = false
  }
}

async function keepRecent(n) {
  try {
    const res = await systemApi.clearPackets({ keep_recent: n })
    ElMessage.success(res.data.message)
    await loadData()
  } catch {
    ElMessage.error('清理失败')
  }
}

async function clearByProtocol(proto) {
  try {
    await ElMessageBox.confirm(
      `确定删除所有 ${proto} 报文吗？`,
      '按协议清理',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }

  try {
    const res = await systemApi.clearPackets({ protocol: proto })
    ElMessage.success(res.data.message)
    await loadData()
  } catch {
    ElMessage.error('清理失败')
  }
}

async function doPartialClean() {
  const params = {}
  if (cleanMode.value === 'keep_recent') {
    params.keep_recent = keepCount.value
  } else if (cleanTarget.value === 'packets') {
    params.protocol = cleanProtocol.value
  } else {
    params.severity = cleanSeverity.value
  }

  try {
    const apiFn = cleanTarget.value === 'packets'
      ? systemApi.clearPackets
      : systemApi.clearAnomalies
    const res = await apiFn(params)
    ElMessage.success(res.data.message)
    showPartialClean.value = false
    await loadData()
  } catch {
    ElMessage.error('清理失败')
  }
}

async function fetchCollectStatus() {
  try {
    const res = await trafficApi.collectStatus()
    collectStatus.value = res.data
  } catch {
    // ignore
  }
}

async function startCollect() {
  collectLoading.value = true
  try {
    const res = await trafficApi.collectStart(sourceMode.value)
    if (res.data.error) {
      ElMessage.warning(res.data.error)
    } else {
      ElMessage.success(`采集已启动 (${sourceMode.value})`)
      collectStatus.value.running = true
    }
  } finally {
    collectLoading.value = false
  }
}

async function stopCollect() {
  collectLoading.value = true
  try {
    await trafficApi.collectStop()
    ElMessage.info('采集已停止')
    collectStatus.value.running = false
    await loadData()
  } finally {
    collectLoading.value = false
  }
}

async function doImportFile() {
  if (!importFilePath.value.trim()) {
    ElMessage.warning('请输入文件路径')
    return
  }

  importLoading.value = true
  try {
    const res = await trafficApi.importFile(importFilePath.value.trim())
    if (res.data.error) {
      ElMessage.error(res.data.error)
    } else {
      ElMessage.success(`成功导入 ${res.data.imported} 条报文`)
      showImportDialog.value = false
      importFilePath.value = ''
      await loadData()
    }
  } catch {
    ElMessage.error('导入失败')
  } finally {
    importLoading.value = false
  }
}

function initWebSocket() {
  rtWs = createRealtimeWs()

  rtWs.on('state', (s) => {
    wsState.value = s
  })

  rtWs.on('stats_update', (data) => {
    collectStatus.value = data
    if (!pollTimer) {
      pollTimer = setInterval(() => loadData(), 5000)
    }
  })

  rtWs.on('alerts', (alerts) => {
    for (const a of alerts) {
      realtimeAlerts.value.unshift(a)
      if (a.severity === 'critical' || a.severity === 'high') {
        ElNotification({
          title: '实时告警',
          message: a.description,
          type: a.severity === 'critical' ? 'error' : 'warning',
          duration: 5000,
        })
      }
    }
    if (realtimeAlerts.value.length > 20) {
      realtimeAlerts.value = realtimeAlerts.value.slice(0, 20)
    }
  })
}

onMounted(async () => {
  await loadData()
  await fetchCollectStatus()
  initWebSocket()
})

onUnmounted(() => {
  if (rtWs) {
    rtWs.close()
    rtWs = null
  }
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
})
</script>

<style scoped>
.dashboard-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.85fr);
  gap: 22px;
}

.panel-header,
.status-line,
.control-actions,
.scenario-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.panel-header {
  justify-content: space-between;
}

.panel-header__title {
  color: var(--gg-text-strong);
  font-size: 20px;
  font-weight: 700;
  font-family: var(--gg-font-display);
}

.panel-header__desc {
  margin-top: 6px;
  color: var(--gg-text-soft);
  font-size: 13px;
}

.status-line {
  flex-wrap: wrap;
  justify-content: flex-end;
}

.control-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 250px;
  gap: 18px;
}

.control-form,
.control-field {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.control-field label,
.scenario-field label {
  color: var(--gg-text-soft);
  font-size: 13px;
}

.control-actions {
  flex-wrap: wrap;
}

.signal-board {
  display: grid;
  gap: 12px;
}

.signal-board__item {
  padding: 16px 18px;
  border-radius: 18px;
  background: linear-gradient(180deg, #f7faff, #eff5ff);
  border: 1px solid rgba(12, 91, 216, 0.08);
}

.signal-board__item span {
  display: block;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.signal-board__item strong {
  display: block;
  margin-top: 8px;
  color: var(--gg-primary-deep);
  font-size: 28px;
  font-family: var(--gg-font-display);
}

.scenario-panel {
  min-height: 100%;
}

.scenario-panel :deep(.el-card__body) {
  height: 100%;
}

.scenario-panel__eyebrow {
  color: rgba(147, 202, 248, 0.86);
  font-size: 12px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.scenario-panel h3 {
  margin: 12px 0 10px;
  font-size: 28px;
  font-family: var(--gg-font-display);
}

.scenario-panel p {
  margin: 0;
  color: rgba(220, 232, 248, 0.8);
  line-height: 1.7;
}

.scenario-field {
  margin-top: 22px;
}

.scenario-actions {
  margin-top: 18px;
  flex-wrap: wrap;
}

.scenario-result,
.scenario-clean {
  margin-top: 18px;
}

.alert-card :deep(.el-card__body) {
  padding-top: 8px;
}

.alert-stream {
  display: grid;
  gap: 14px;
}

.alert-item {
  display: flex;
  gap: 14px;
  padding: 16px 12px;
  border-bottom: 1px solid rgba(16, 62, 121, 0.08);
}

.alert-item:last-child {
  border-bottom: none;
}

.alert-item__marker {
  width: 10px;
  min-width: 10px;
  border-radius: 999px;
  background: #8da4bb;
}

.alert-item__marker.severity-critical,
.alert-item__marker.severity-high {
  background: var(--gg-danger);
}

.alert-item__marker.severity-medium {
  background: var(--gg-gold);
}

.alert-item__marker.severity-low {
  background: var(--gg-accent);
}

.alert-item__body {
  flex: 1;
}

.alert-item__meta {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.alert-item__text {
  margin-top: 8px;
  color: var(--gg-text);
  line-height: 1.7;
}

.packet-summary {
  color: var(--gg-text-soft);
}

.dialog-tip {
  color: var(--gg-text-soft);
  font-size: 12px;
}

@media (max-width: 1080px) {
  .dashboard-grid,
  .control-layout {
    grid-template-columns: 1fr;
  }
}
</style>
