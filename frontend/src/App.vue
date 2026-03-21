<template>
  <div class="app-shell">
    <div class="shell-bg shell-bg-left" />
    <div class="shell-bg shell-bg-right" />

    <header class="topbar">
      <div class="topbar__inner">
        <div class="brand-mark">
          <div class="brand-mark__badge">GG</div>
          <div>
            <div class="brand-mark__title">GatewayGuard</div>
            <div class="brand-mark__subtitle">智能网关网络分析平台</div>
          </div>
        </div>

        <el-menu
          :default-active="route.path"
          mode="horizontal"
          router
          class="topbar__menu"
        >
          <el-menu-item index="/">
            <el-icon><Monitor /></el-icon>
            流量监控
          </el-menu-item>
          <el-menu-item index="/anomaly">
            <el-icon><WarningFilled /></el-icon>
            告警中心
          </el-menu-item>
          <el-menu-item index="/chat">
            <el-icon><ChatDotRound /></el-icon>
            AI 分析
          </el-menu-item>
        </el-menu>

        <div class="topbar__meta">
          <div class="topbar__chip">车载安全运营</div>
          <div class="topbar__chip topbar__chip--accent">7 x 24 在线分析</div>
        </div>
      </div>
    </header>

    <section class="hero-banner">
      <div class="hero-banner__inner">
        <div class="hero-banner__content">
          <div class="eyebrow">{{ pageMeta.eyebrow }}</div>
          <h1>{{ pageMeta.title }}</h1>
          <p>{{ pageMeta.description }}</p>
          <div class="hero-banner__tags">
            <span v-for="item in pageMeta.tags" :key="item">{{ item }}</span>
          </div>
        </div>

        <div class="hero-banner__panel">
          <div class="hero-banner__panel-label">平台能力</div>
          <div class="hero-banner__panel-grid">
            <div v-for="item in heroStats" :key="item.label" class="hero-stat">
              <strong>{{ item.value }}</strong>
              <span>{{ item.label }}</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <main class="page-container">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { ChatDotRound, Monitor, WarningFilled } from '@element-plus/icons-vue'

const route = useRoute()

const pageMetaMap = {
  '/': {
    eyebrow: 'Gateway Telemetry',
    title: '面向车载网关的统一监测与响应视图',
    description: '将 CAN、以太网与 V2X 报文采集、异常检测、实时告警与 AI 研判组织成一套更像安全门户而不是实验台的界面。',
    tags: ['多协议遥测', '实时采集', '攻击模拟', '趋势看板'],
  },
  '/anomaly': {
    eyebrow: 'Threat Intelligence',
    title: '让异常事件以情报视角组织与追踪',
    description: '聚合风险等级、处置状态和 AI 分析结果，形成面向运营和研判的事件中心。',
    tags: ['事件编排', '风险分层', 'AI 报告', '批量分析'],
  },
  '/chat': {
    eyebrow: 'AI Copilot',
    title: '把车载安全助手放进日常分析工作流',
    description: '围绕实时事件、威胁解释和处置建议建立连续会话，让 AI 页面不再像一个简单弹窗。',
    tags: ['安全问答', '事件追问', '上下文会话', '辅助决策'],
  },
}

const pageMeta = computed(() => pageMetaMap[route.path] || pageMetaMap['/'])

const heroStats = [
  { label: '协议域', value: '03' },
  { label: '核心场景', value: '05' },
  { label: '在线页面', value: '03' },
  { label: '分析模式', value: 'LLM +' },
]
</script>
