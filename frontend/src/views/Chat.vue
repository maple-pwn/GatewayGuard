<template>
  <div class="chat-page">
    <section class="section-block chat-layout">
      <el-card class="panel-card panel-card--dark chat-intro">
        <div class="chat-intro__eyebrow">Security Copilot</div>
        <h3>面向告警研判与解释的 AI 会话空间</h3>
        <p>把原来的简单聊天框升级成品牌化分析工作台，强化品牌、上下文和输入引导。</p>

        <div class="chat-intro__stats">
          <div class="chat-intro__stat">
            <span>会话 ID</span>
            <strong>{{ sessionId }}</strong>
          </div>
          <div class="chat-intro__stat">
            <span>消息数</span>
            <strong>{{ messages.length }}</strong>
          </div>
        </div>

        <div class="chat-intro__prompts">
          <button type="button" @click="applyPrompt('最近有哪些高风险异常事件值得优先处理？')">
            最近有哪些高风险异常事件值得优先处理？
          </button>
          <button type="button" @click="applyPrompt('请总结当前平台中最常见的攻击模式和建议措施。')">
            请总结当前平台中最常见的攻击模式和建议措施。
          </button>
          <button type="button" @click="applyPrompt('如果出现 CAN Spoofing，应优先排查哪些 ECU 和指标？')">
            如果出现 CAN Spoofing，应优先排查哪些 ECU 和指标？
          </button>
        </div>
      </el-card>

      <el-card class="panel-card chat-panel">
        <template #header>
          <div class="panel-header">
            <div>
              <div class="panel-header__title">AI 安全分析助手</div>
              <div class="panel-header__desc">支持围绕异常事件、攻击链和处置建议发起多轮追问。</div>
            </div>
            <el-tag type="info" effect="plain">实时会话</el-tag>
          </div>
        </template>

        <div class="chat-panel__body">
          <div ref="msgBox" class="message-list">
            <div v-if="!messages.length" class="chat-empty">
              <div class="chat-empty__title">从一个具体问题开始</div>
              <div class="chat-empty__desc">例如询问近期异常摘要、某个攻击类型的解释，或让 AI 生成排查建议。</div>
            </div>

            <div
              v-for="(msg, i) in messages"
              :key="i"
              class="message-row"
              :class="{ 'message-row--user': msg.role === 'user' }"
            >
              <div class="message-bubble">
                <div class="message-bubble__role">
                  {{ msg.role === 'user' ? 'Analyst' : 'GatewayGuard AI' }}
                </div>
                <div class="message-bubble__text">{{ msg.content }}</div>
              </div>
            </div>

            <div v-if="loading" class="chat-loading">
              <el-icon class="is-loading"><Loading /></el-icon>
              <span>AI 正在分析...</span>
            </div>
          </div>

          <div class="chat-input">
            <el-input
              v-model="input"
              type="textarea"
              :rows="3"
              resize="none"
              placeholder="输入安全分析问题，如：最近有哪些异常事件？"
              @keydown.enter.exact.prevent="sendMessage"
              :disabled="loading"
            />
            <div class="chat-input__footer">
              <span>Enter 发送，Shift + Enter 换行</span>
              <el-button type="primary" @click="sendMessage" :loading="loading">
                发送分析请求
              </el-button>
            </div>
          </div>
        </div>
      </el-card>
    </section>
  </div>
</template>

<script setup>
import { ref, nextTick } from 'vue'
import { Loading } from '@element-plus/icons-vue'
import { llmApi } from '../api/index.js'

const input = ref('')
const messages = ref([])
const loading = ref(false)
const msgBox = ref(null)
const sessionId = ref(Math.random().toString(36).slice(2, 10))

function applyPrompt(text) {
  input.value = text
}

async function sendMessage() {
  const text = input.value.trim()
  if (!text || loading.value) return

  messages.value.push({ role: 'user', content: text })
  input.value = ''
  loading.value = true
  await scrollBottom()

  try {
    const res = await llmApi.chat(text, sessionId.value)
    messages.value.push({
      role: 'assistant',
      content: res.data.response,
    })
  } catch (e) {
    messages.value.push({
      role: 'assistant',
      content: 'LLM 调用失败，请检查后端配置。',
    })
  } finally {
    loading.value = false
    await scrollBottom()
  }
}

async function scrollBottom() {
  await nextTick()
  if (msgBox.value) {
    msgBox.value.scrollTop = msgBox.value.scrollHeight
  }
}
</script>

<style scoped>
.chat-layout {
  display: grid;
  grid-template-columns: minmax(300px, 0.78fr) minmax(0, 1.22fr);
  gap: 22px;
  min-height: 720px;
}

.chat-intro__eyebrow {
  color: rgba(147, 202, 248, 0.86);
  font-size: 12px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.chat-intro h3 {
  margin: 12px 0 10px;
  font-size: 30px;
  font-family: var(--gg-font-display);
}

.chat-intro p {
  margin: 0;
  color: rgba(220, 232, 248, 0.8);
  line-height: 1.7;
}

.chat-intro__stats {
  display: grid;
  gap: 12px;
  margin-top: 24px;
}

.chat-intro__stat {
  padding: 16px 18px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.07);
}

.chat-intro__stat span {
  display: block;
  color: rgba(220, 232, 248, 0.72);
  font-size: 12px;
}

.chat-intro__stat strong {
  display: block;
  margin-top: 8px;
  color: #fff;
  font-size: 24px;
  font-family: var(--gg-font-display);
}

.chat-intro__prompts {
  display: grid;
  gap: 10px;
  margin-top: 24px;
}

.chat-intro__prompts button {
  padding: 14px 16px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.04);
  color: #e4edf8;
  text-align: left;
  cursor: pointer;
}

.chat-panel,
.chat-panel :deep(.el-card__body) {
  height: 100%;
}

.chat-panel__body {
  display: flex;
  height: 100%;
  min-height: 580px;
  flex-direction: column;
}

.message-list {
  flex: 1;
  overflow-y: auto;
  padding-right: 4px;
}

.chat-empty {
  display: grid;
  place-items: center;
  height: 100%;
  min-height: 280px;
  border: 1px dashed rgba(12, 91, 216, 0.18);
  border-radius: 22px;
  background: linear-gradient(180deg, #f7fbff, #f3f7fc);
  text-align: center;
}

.chat-empty__title {
  color: var(--gg-text-strong);
  font-size: 20px;
  font-family: var(--gg-font-display);
}

.chat-empty__desc {
  margin-top: 8px;
  max-width: 420px;
  color: var(--gg-text-soft);
  line-height: 1.7;
}

.message-row {
  display: flex;
  justify-content: flex-start;
  margin-bottom: 14px;
}

.message-row--user {
  justify-content: flex-end;
}

.message-bubble {
  max-width: 76%;
  padding: 14px 16px;
  border-radius: 20px 20px 20px 8px;
  background: #f5f8fd;
  border: 1px solid rgba(16, 62, 121, 0.08);
  box-shadow: 0 10px 20px rgba(10, 33, 68, 0.04);
}

.message-row--user .message-bubble {
  border-radius: 20px 20px 8px 20px;
  background: linear-gradient(135deg, #0c5bd8, #1577f2);
  border-color: transparent;
  color: #fff;
}

.message-bubble__role {
  margin-bottom: 8px;
  color: var(--gg-text-soft);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.04em;
}

.message-row--user .message-bubble__role {
  color: rgba(255, 255, 255, 0.78);
}

.message-bubble__text {
  white-space: pre-wrap;
  line-height: 1.75;
}

.chat-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 0;
  color: var(--gg-text-soft);
}

.chat-input {
  margin-top: 18px;
  padding-top: 18px;
  border-top: 1px solid rgba(16, 62, 121, 0.08);
}

.chat-input__footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 12px;
  color: var(--gg-text-soft);
  font-size: 12px;
}

@media (max-width: 1080px) {
  .chat-layout {
    grid-template-columns: 1fr;
  }

  .message-bubble {
    max-width: 100%;
  }
}
</style>
