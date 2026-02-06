<template>
  <div>
    <!-- 统计卡片 -->
    <el-row :gutter="16" style="margin-bottom: 20px">
      <el-col :span="6">
        <el-card shadow="hover">
          <div style="text-align: center">
            <div style="font-size: 28px; font-weight: bold; color: #409eff">
              {{ stats.total_packets }}
            </div>
            <div style="color: #999; margin-top: 8px">总报文数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div style="text-align: center">
            <div style="font-size: 28px; font-weight: bold; color: #67c23a">
              {{ stats.can_count }}
            </div>
            <div style="color: #999; margin-top: 8px">CAN 报文</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div style="text-align: center">
            <div style="font-size: 28px; font-weight: bold; color: #e6a23c">
              {{ stats.eth_count }}
            </div>
            <div style="color: #999; margin-top: 8px">以太网报文</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div style="text-align: center">
            <div style="font-size: 28px; font-weight: bold; color: #f56c6c">
              {{ stats.v2x_count }}
            </div>
            <div style="color: #999; margin-top: 8px">V2X 报文</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 实时采集控制 -->
    <el-card style="margin-bottom: 20px">
      <template #header>
        <div style="display: flex; align-items: center; justify-content: space-between">
          <span>数据源与实时采集</span>
          <el-tag :type="collectStatus.running ? 'success' : 'info'" effect="dark">
            {{ collectStatus.running ? '采集中' : '已停止' }}
          </el-tag>
        </div>
      </template>
      <el-row :gutter="16" align="middle">
        <el-col :span="8">
          <span style="margin-right: 8px; color: #606266">数据源模式:</span>
          <el-select v-model="sourceMode" style="width: 160px" :disabled="collectStatus.running">
            <el-option label="模拟器" value="simulator" />
            <el-option label="CAN 总线" value="can" />
            <el-option label="以太网" value="ethernet" />
            <el-option label="PCAP 文件" value="pcap" />
            <el-option label="多源混合" value="multi" />
          </el-select>
        </el-col>
        <el-col :span="8">
          <el-button
            type="success" @click="startCollect" :loading="collectLoading"
            :disabled="collectStatus.running"
          >启动采集</el-button>
          <el-button
            type="danger" @click="stopCollect" :loading="collectLoading"
            :disabled="!collectStatus.running"
          >停止采集</el-button>
          <el-button type="warning" plain @click="showImportDialog = true">
            导入文件
          </el-button>
        </el-col>
        <el-col :span="8" v-if="collectStatus.running">
          <el-descriptions :column="2" size="small" border>
            <el-descriptions-item label="已采集">
              {{ collectStatus.total_collected || 0 }}
            </el-descriptions-item>
            <el-descriptions-item label="异常数">
              {{ collectStatus.total_anomalies || 0 }}
            </el-descriptions-item>
          </el-descriptions>
        </el-col>
      </el-row>
    </el-card>

    <!-- 操作区 -->
    <el-card style="margin-bottom: 20px">
      <template #header>
        <div style="display: flex; align-items: center; justify-content: space-between">
          <span>流量模拟与检测</span>
          <div>
            <el-select v-model="scenario" style="width: 140px; margin-right: 10px">
              <el-option label="正常流量" value="normal" />
              <el-option label="DoS 攻击" value="dos" />
              <el-option label="Fuzzy 攻击" value="fuzzy" />
              <el-option label="Spoofing 攻击" value="spoofing" />
              <el-option label="混合场景" value="mixed" />
            </el-select>
            <el-button type="primary" @click="simulateTraffic" :loading="simLoading">
              生成模拟流量
            </el-button>
            <el-button type="danger" @click="runDetection" :loading="detectLoading">
              执行异常检测
            </el-button>
            <el-dropdown split-button type="info" plain @click="clearData" style="margin-left: 16px">
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
        </div>
      </template>
      <div v-if="detectResult">
        <el-alert
          :title="`检测完成: 发现 ${detectResult.detected} 个异常`"
          :type="detectResult.detected > 0 ? 'warning' : 'success'"
          show-icon
          style="margin-bottom: 12px"
        />
      </div>
    </el-card>

    <!-- 流量记录表 -->
    <el-card>
      <template #header>最近流量记录</template>
      <el-table :data="packets" stripe style="width: 100%" max-height="400">
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="source" label="源节点" width="120" />
        <el-table-column prop="destination" label="目标" width="120" />
        <el-table-column prop="msg_id" label="消息ID" width="140" />
        <el-table-column prop="domain" label="功能域" width="120" />
        <el-table-column label="时间" width="180">
          <template #default="{ row }">
            {{ new Date(row.timestamp * 1000).toLocaleString() }}
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 按条件清理对话框 -->
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

    <!-- 文件导入对话框 -->
    <el-dialog v-model="showImportDialog" title="导入抓包文件" width="480px">
      <el-form label-width="100px">
        <el-form-item label="文件路径">
          <el-input
            v-model="importFilePath"
            placeholder="服务器上的文件路径，如 /data/capture.pcap"
          />
        </el-form-item>
        <el-form-item>
          <span style="color: #909399; font-size: 12px">
            支持格式: .pcap / .pcapng / .blf / .asc
          </span>
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
import { ref, onMounted, onUnmounted } from 'vue'
import { trafficApi, anomalyApi, systemApi } from '../api/index.js'
import { ElMessage, ElMessageBox } from 'element-plus'

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

// 实时采集相关
const sourceMode = ref('simulator')
const collectStatus = ref({ running: false, total_collected: 0, total_anomalies: 0 })
const collectLoading = ref(false)
const showImportDialog = ref(false)
const importFilePath = ref('')
const importLoading = ref(false)
let pollTimer = null

async function loadData() {
  try {
    const [s, p] = await Promise.all([
      trafficApi.getStats(),
      trafficApi.getPackets({ limit: 50 }),
    ])
    stats.value = s.data
    packets.value = p.data
  } catch (e) { console.error(e) }
}

async function simulateTraffic() {
  simLoading.value = true
  try {
    await trafficApi.simulate(scenario.value, 200)
    await loadData()
  } finally { simLoading.value = false }
}

async function runDetection() {
  detectLoading.value = true
  try {
    const res = await anomalyApi.detect(500)
    detectResult.value = res.data
  } finally { detectLoading.value = false }
}

async function clearData() {
  try {
    await ElMessageBox.confirm('确定要清空所有数据吗？此操作不可恢复。', '清空数据', {
      confirmButtonText: '确定清空',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch { return }
  clearLoading.value = true
  try {
    const res = await systemApi.clearData()
    ElMessage.success(`数据已清空: ${JSON.stringify(res.data.cleared)}`)
    detectResult.value = null
    await loadData()
  } catch (e) {
    ElMessage.error('清空数据失败')
  } finally { clearLoading.value = false }
}

async function keepRecent(n) {
  try {
    const res = await systemApi.clearPackets({ keep_recent: n })
    ElMessage.success(res.data.message)
    await loadData()
  } catch { ElMessage.error('清理失败') }
}

async function clearByProtocol(proto) {
  try {
    await ElMessageBox.confirm(
      `确定删除所有 ${proto} 报文吗？`, '按协议清理',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
    )
  } catch { return }
  try {
    const res = await systemApi.clearPackets({ protocol: proto })
    ElMessage.success(res.data.message)
    await loadData()
  } catch { ElMessage.error('清理失败') }
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
  } catch { ElMessage.error('清理失败') }
}

// 实时采集控制
async function fetchCollectStatus() {
  try {
    const res = await trafficApi.collectStatus()
    collectStatus.value = res.data
  } catch { /* ignore */ }
}

async function startCollect() {
  collectLoading.value = true
  try {
    const res = await trafficApi.collectStart(sourceMode.value)
    if (res.data.error) {
      ElMessage.warning(res.data.error)
    } else {
      ElMessage.success(`采集已启动 (${sourceMode.value})`)
      startPolling()
    }
    await fetchCollectStatus()
  } finally { collectLoading.value = false }
}

async function stopCollect() {
  collectLoading.value = true
  try {
    await trafficApi.collectStop()
    ElMessage.info('采集已停止')
    stopPolling()
    await fetchCollectStatus()
    await loadData()
  } finally { collectLoading.value = false }
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
  } catch { ElMessage.error('导入失败') }
  finally { importLoading.value = false }
}

function startPolling() {
  stopPolling()
  pollTimer = setInterval(async () => {
    await fetchCollectStatus()
    await loadData()
  }, 3000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

onMounted(async () => {
  await loadData()
  await fetchCollectStatus()
  if (collectStatus.value.running) {
    startPolling()
  }
})

onUnmounted(() => {
  stopPolling()
})
</script>
