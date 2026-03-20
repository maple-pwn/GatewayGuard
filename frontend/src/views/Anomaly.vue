<template>
  <div class="anomaly-page">
    <section class="section-block anomaly-overview">
      <el-row :gutter="18">
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">事件总量</div>
            <div class="metric-card__value">{{ total }}</div>
            <div class="metric-card__meta">当前筛选条件下的异常事件数量</div>
            <div class="metric-card__accent">Incident Volume</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">高危与严重</div>
            <div class="metric-card__value">{{ highRiskCount }}</div>
            <div class="metric-card__meta">需要优先处置的核心事件集合</div>
            <div class="metric-card__accent">Priority Queue</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">处理中</div>
            <div class="metric-card__value">{{ openCount }}</div>
            <div class="metric-card__meta">待处理与调查中的告警状态</div>
            <div class="metric-card__accent">Investigation</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">AI 可研判</div>
            <div class="metric-card__value">{{ Math.min(events.length, 5) }}</div>
            <div class="metric-card__meta">支持批量分析的事件窗口</div>
            <div class="metric-card__accent">LLM Ready</div>
          </el-card>
        </el-col>
      </el-row>
    </section>

    <section class="section-block anomaly-layout">
      <el-card class="panel-card filter-panel">
        <template #header>
          <div class="panel-header">
            <div>
              <div class="panel-header__title">事件筛选与检索</div>
              <div class="panel-header__desc">按严重程度与状态快速切换当前研判视图。</div>
            </div>
          </div>
        </template>

        <div class="filter-grid">
          <div class="filter-field">
            <label>严重程度</label>
            <el-select v-model="filter.severity" placeholder="严重程度" clearable>
              <el-option label="严重" value="critical" />
              <el-option label="高" value="high" />
              <el-option label="中" value="medium" />
              <el-option label="低" value="low" />
            </el-select>
          </div>
          <div class="filter-field">
            <label>状态</label>
            <el-select v-model="filter.status" placeholder="状态" clearable>
              <el-option label="待处理" value="open" />
              <el-option label="调查中" value="investigating" />
              <el-option label="已解决" value="resolved" />
            </el-select>
          </div>
          <div class="filter-action">
            <el-button type="primary" @click="loadEvents">查询事件</el-button>
          </div>
        </div>
      </el-card>

      <el-card class="panel-card panel-card--dark ai-panel">
        <div class="ai-panel__eyebrow">AI Intelligence</div>
        <h3>让事件中心拥有自动摘要与预警报告</h3>
        <p>把 AI 分析按钮做成一级可见操作，而不是藏在表格里。</p>

        <div class="ai-panel__actions">
          <el-button
            class="ai-panel__action-btn"
            type="warning"
            size="large"
            @click="generateReport"
            :loading="reportLoading"
          >
            生成 AI 预警报告
          </el-button>
          <el-button
            class="ai-panel__action-btn"
            type="danger"
            size="large"
            @click="batchAnalyze"
            :loading="batchLoading"
          >
            批量 AI 分析异常事件
          </el-button>
        </div>
      </el-card>
    </section>

    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">异常事件列表</div>
          <div class="section-head__desc">当前共 {{ total }} 条事件，表格保留原始数据字段与 AI 分析入口。</div>
        </div>
      </div>

      <el-card class="panel-card table-card">
        <el-table :data="events" stripe style="width: 100%">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="anomaly_type" label="类型" width="180" />
          <el-table-column label="严重程度" width="110">
            <template #default="{ row }">
              <el-tag :type="severityColor(row.severity)" size="small">{{ row.severity }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="confidence" label="置信度" width="100">
            <template #default="{ row }">
              {{ ((row.confidence || 0) * 100).toFixed(0) }}%
            </template>
          </el-table-column>
          <el-table-column prop="protocol" label="协议" width="90" />
          <el-table-column prop="source_node" label="源节点" width="120" />
          <el-table-column prop="description" label="描述" min-width="240" show-overflow-tooltip />
          <el-table-column label="操作" width="150" fixed="right">
            <template #default="{ row }">
              <el-button size="small" type="warning" @click="analyzeEvent(row)">
                AI 分析
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </section>

    <el-dialog v-model="showAnalysis" title="AI 语义分析" width="720px">
      <div v-if="analysisLoading" class="dialog-loading">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p>正在调用 LLM 分析...</p>
      </div>
      <div v-else-if="analysisResult && !analysisResult.analyze_raw">
        <el-alert
          v-if="analysisResult.summary"
          :title="analysisResult.summary"
          :type="riskAlertType(analysisResult.risk_level)"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />

        <el-row :gutter="12" style="margin-bottom: 16px">
          <el-col :span="8">
            <div class="info-card">
              <div class="info-label">攻击类型</div>
              <div class="info-value">{{ analysisResult.attack_type || '-' }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="info-card">
              <div class="info-label">风险等级</div>
              <el-tag :type="riskTagType(analysisResult.risk_level)" size="large" effect="dark">
                {{ riskLabel(analysisResult.risk_level) }}
              </el-tag>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="info-card">
              <div class="info-label">攻击意图</div>
              <div class="info-value">{{ analysisResult.attack_intent || '-' }}</div>
            </div>
          </el-col>
        </el-row>

        <el-descriptions :column="1" border style="margin-bottom: 16px">
          <el-descriptions-item label="攻击手法">{{ analysisResult.attack_method || '-' }}</el-descriptions-item>
          <el-descriptions-item label="根因分析">{{ analysisResult.root_cause || '-' }}</el-descriptions-item>
        </el-descriptions>

        <div v-if="analysisResult.affected_scope?.length" style="margin-bottom: 16px">
          <div class="section-title">影响范围</div>
          <el-tag
            v-for="(s, i) in analysisResult.affected_scope"
            :key="i"
            type="warning"
            class="scope-tag"
          >
            {{ s }}
          </el-tag>
        </div>

        <div v-if="analysisResult.recommendations?.length">
          <div class="section-title">处置建议</div>
          <div v-for="(r, i) in analysisResult.recommendations" :key="i" class="rec-item">
            <el-icon><SuccessFilled /></el-icon>
            <span>{{ r }}</span>
          </div>
        </div>
      </div>
      <pre v-else-if="analysisResult" class="raw-block">{{ formatRaw(analysisResult) }}</pre>
    </el-dialog>

    <el-dialog v-model="showReport" title="AI 预警报告" width="800px" top="5vh">
      <div v-if="reportLoading" class="dialog-loading">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p>正在生成预警报告，请稍候...</p>
      </div>
      <div v-else-if="reportResult && !reportResult.report_raw">
        <div class="report-head">
          <h3>{{ reportResult.title || '预警报告' }}</h3>
          <el-tag v-if="reportResult.risk_level" :type="riskTagType(reportResult.risk_level)" size="large" effect="dark">
            {{ riskLabel(reportResult.risk_level) }}
          </el-tag>
        </div>

        <el-alert
          v-if="reportResult.summary"
          :title="reportResult.summary"
          type="info"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />

        <div v-if="reportResult.attack_chain" style="margin-bottom: 16px">
          <div class="section-title">攻击链分析</div>
          <div class="report-text-block">{{ reportResult.attack_chain }}</div>
        </div>

        <div v-if="reportResult.timeline?.length" style="margin-bottom: 16px">
          <div class="section-title">关键事件时间线</div>
          <el-timeline>
            <el-timeline-item
              v-for="(t, i) in reportResult.timeline"
              :key="i"
              :timestamp="'#' + (i + 1)"
              placement="top"
            >
              {{ t }}
            </el-timeline-item>
          </el-timeline>
        </div>

        <div v-if="reportResult.impact_assessment" style="margin-bottom: 16px">
          <div class="section-title">影响评估</div>
          <div class="report-text-block">{{ reportResult.impact_assessment }}</div>
        </div>

        <div v-if="reportResult.recommendations?.length" style="margin-bottom: 16px">
          <div class="section-title">处置建议</div>
          <div v-for="(r, i) in reportResult.recommendations" :key="i" class="rec-item">
            <el-icon><SuccessFilled /></el-icon>
            <span>{{ r }}</span>
          </div>
        </div>

        <el-alert
          v-if="reportResult.conclusion"
          :title="reportResult.conclusion"
          :type="riskAlertType(reportResult.risk_level)"
          show-icon
          :closable="false"
        />
      </div>
      <pre v-else-if="reportResult" class="raw-block">{{ formatRaw(reportResult) }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { Loading, SuccessFilled } from '@element-plus/icons-vue'
import { anomalyApi, llmApi } from '../api/index.js'
import { ElMessage } from 'element-plus'

const events = ref([])
const total = ref(0)
const filter = ref({ severity: '', status: '' })
const reportLoading = ref(false)
const showAnalysis = ref(false)
const analysisLoading = ref(false)
const analysisResult = ref(null)
const batchLoading = ref(false)
const showReport = ref(false)
const reportResult = ref(null)

const highRiskCount = computed(() => (
  events.value.filter((item) => item.severity === 'critical' || item.severity === 'high').length
))

const openCount = computed(() => (
  events.value.filter((item) => item.status === 'open' || item.status === 'investigating').length
))

function severityColor(s) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || 'info'
}

function formatRaw(obj) {
  if (!obj) return ''
  const raw = obj.analyze_raw || obj.report_raw
  if (raw) {
    return raw.replace(/^```json\n?/, '').replace(/\n?```$/, '')
  }
  return JSON.stringify(obj, null, 2)
}

function riskTagType(level) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'success' }[level] || 'info'
}

function riskAlertType(level) {
  return { critical: 'error', high: 'error', medium: 'warning', low: 'success' }[level] || 'info'
}

function riskLabel(level) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危' }[level] || level
}

async function loadEvents() {
  try {
    const params = {}
    if (filter.value.severity) params.severity = filter.value.severity
    if (filter.value.status) params.status = filter.value.status
    const res = await anomalyApi.getEvents(params)
    events.value = res.data.events
    total.value = res.data.total
  } catch (e) {
    console.error(e)
  }
}

async function analyzeEvent(row) {
  showAnalysis.value = true
  analysisLoading.value = true
  analysisResult.value = null
  try {
    const res = await llmApi.analyze(row.id)
    analysisResult.value = res.data.analysis
  } catch (e) {
    ElMessage.error('LLM 分析失败，请检查 API Key 配置')
  } finally {
    analysisLoading.value = false
  }
}

async function generateReport() {
  showReport.value = true
  reportLoading.value = true
  reportResult.value = null
  try {
    const res = await llmApi.report(10)
    reportResult.value = res.data.report
  } catch (e) {
    ElMessage.error('报告生成失败')
    showReport.value = false
  } finally {
    reportLoading.value = false
  }
}

async function batchAnalyze() {
  if (!events.value.length) {
    ElMessage.warning('暂无异常事件可分析')
    return
  }
  batchLoading.value = true
  let success = 0
  let fail = 0
  for (const ev of events.value.slice(0, 5)) {
    try {
      await llmApi.analyze(ev.id)
      success++
    } catch {
      fail++
    }
  }
  batchLoading.value = false
  ElMessage.info(`批量分析完成: 成功 ${success}, 失败 ${fail}`)
}

onMounted(loadEvents)
</script>

<style scoped>
.anomaly-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
  gap: 22px;
}

.filter-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  align-items: end;
}

.filter-field {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.filter-field label {
  color: var(--gg-text-soft);
  font-size: 13px;
}

.ai-panel__eyebrow {
  color: rgba(147, 202, 248, 0.86);
  font-size: 12px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.ai-panel h3 {
  margin: 12px 0 10px;
  font-size: 28px;
  font-family: var(--gg-font-display);
}

.ai-panel p {
  margin: 0;
  color: rgba(220, 232, 248, 0.8);
  line-height: 1.7;
}

.ai-panel__actions {
  display: grid;
  gap: 12px;
  margin-top: 22px;
}

.ai-panel__action-btn {
  width: 100%;
  min-height: 40px;
}

.ai-panel__actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

.dialog-loading {
  padding: 40px;
  text-align: center;
  color: var(--gg-text-soft);
}

.info-card {
  height: 100%;
  padding: 16px;
  border-radius: 18px;
  background: linear-gradient(180deg, #f7faff, #f2f6fc);
  text-align: center;
}

.info-label {
  margin-bottom: 8px;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.info-value {
  color: var(--gg-text-strong);
  font-size: 15px;
  font-weight: 600;
}

.section-title {
  margin-bottom: 10px;
  padding-left: 10px;
  border-left: 3px solid var(--gg-primary);
  color: var(--gg-text-strong);
  font-size: 14px;
  font-weight: 700;
}

.scope-tag {
  margin: 0 8px 8px 0;
}

.rec-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 12px;
  margin-bottom: 8px;
  border-radius: 12px;
  background: #f0f8f2;
  color: var(--gg-text);
  line-height: 1.7;
}

.report-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}

.report-head h3 {
  margin: 0;
  color: var(--gg-text-strong);
  font-size: 18px;
}

.report-text-block,
.raw-block {
  padding: 14px 16px;
  border-radius: 16px;
  background: #f6f9fd;
  color: var(--gg-text);
  line-height: 1.75;
  font-size: 14px;
  white-space: pre-wrap;
}

@media (max-width: 1080px) {
  .anomaly-layout,
  .filter-grid {
    grid-template-columns: 1fr;
  }
}
</style>
