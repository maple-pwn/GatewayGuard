<div align="center">

# GatewayGuard

**基于大语言模型的智能网关网络流量分析与异常预警系统**

*An LLM-Augmented Intelligent Gateway for Multi-Protocol Traffic Analysis and Anomaly Early Warning*

[![Python](https://img.shields.io/badge/Python-3.12+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![Vue](https://img.shields.io/badge/Vue-3.x-brightgreen?logo=vue.js)](https://vuejs.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

</div>

---

本系统面向智能网联汽车（CAV）网关场景，针对 CAN 总线、车载以太网及 V2X 等多协议流量，构建了集异常检测与大语言模型（LLM）语义分析于一体的安全预警平台。系统采用两级检测架构（规则引擎 + Isolation Forest），并通过 LLM 实现异常事件的自动化语义解析与交互式安全问答。

---

## 目录

- [项目背景](#项目背景)
- [理论基础与参考文献](#理论基础与参考文献)
- [系统架构](#系统架构)
- [核心功能](#核心功能)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [环境要求](#环境要求)
- [安装与启动](#安装与启动)
- [使用流程](#使用流程)
- [API 接口说明](#api-接口说明)
- [数据库设计](#数据库设计)
- [LLM 集成说明](#llm-集成说明)
- [异常检测算法](#异常检测算法)
- [真实车机部署](#真实车机部署)
- [参考文献](#参考文献)

---

## 项目背景

随着智能网联汽车（Connected and Autonomous Vehicles, CAV）技术的快速发展，车载网关已从传统的协议转换设备演变为承载 CAN 总线、车载以太网（Automotive Ethernet）、V2X（Vehicle-to-Everything）等异构协议的核心网络节点 [1][2]。然而，现有入侵检测系统（IDS）在应对车载多协议环境时存在以下局限性：

- **语义缺失**：基于签名和阈值的检测方法仅能判定异常存在与否，缺乏对异常成因的语义解释能力，导致安全分析人员面临大量缺乏上下文的告警信息 [3]
- **协议隔离**：CAN、以太网、V2X 各协议独立检测，难以识别跨协议攻击链及其级联效应 [4]
- **知识编码困难**：车载网络安全领域的专家知识高度分散，传统系统缺乏将其系统化编码并复用的机制 [5]

针对上述问题，本项目提出了一种**"检测-理解-对话"**三层架构：第一层通过两级异常检测（规则引擎 + Isolation Forest）识别异常信号；第二层利用大语言模型（LLM）对异常事件进行语义分析，包括攻击分类、根因溯源、影响评估及处置建议；第三层通过 Function Calling 机制支持自然语言交互式安全问答，模型可自主调用后端 API 获取实时数据以辅助分析。

该架构将传统异常检测与 LLM 语义理解能力相结合，旨在提升车载网关安全分析的自动化程度与可解释性。

---

## 理论基础与参考文献

本系统的设计基于车载网络安全、异常检测及大语言模型应用三个研究领域的相关工作。以下按技术模块梳理核心理论依据：

### 一、车载网络入侵检测

车载 CAN 总线因其广播特性和缺乏认证机制，存在固有的安全脆弱性。Miller 和 Valasek 于 2015 年通过对 Jeep Cherokee 的远程攻击实验 [1] 验证了车载网络面临的实际威胁，推动了车载 IDS 领域的研究发展。

本系统的**规则引擎**参考了以下经典工作：

| 检测方法 | 理论来源 | 对应论文 |
|---------|---------|---------|
| CAN 报文频率异常检测 | 基于时间间隔统计的 DoS 检测 | Cho & Shin, 2016 [6] — *"Fingerprinting Electronic Control Units for Intra-vehicle Network Security"* |
| 未知 CAN ID 检测 | 白名单机制与消息认证 | Müter & Asaj, 2011 [7] — *"Entropy-based Anomaly Detection for In-vehicle Networks"* |
| 负载模式异常检测 | 信息熵与负载统计特征 | Marchetti et al., 2016 [8] — *"Anomaly Detection of CAN Bus Messages through Analysis of ID Sequences"* |

### 二、无监督异常检测：Isolation Forest

传统监督学习方法依赖大量标注数据，而车载安全领域中攻击样本通常较为稀缺。Liu et al. 于 2008 年提出的 **Isolation Forest** 算法 [9] 为此类场景提供了有效的无监督检测方案。

该算法的核心假设是：异常样本由于其稀疏性，在随机特征分割过程中更易被隔离，因而具有更短的平均路径长度。本系统采用 scikit-learn 的 `IsolationForest` 实现 [10]，特征向量包含：

```
[msg_id_num, payload_len, byte_entropy, protocol_encoded, domain_encoded]
```

其中**字节熵（byte entropy）** 的引入参考了 Wang & Stolfo, 2004 [11] 的网络负载异常检测方法。正常报文的负载熵分布具有相对稳定的统计特征，而注入攻击（如全 0xFF 填充的 Spoofing）会导致熵值产生显著偏离。

### 三、大语言模型在网络安全中的应用

将 LLM 应用于网络安全分析已成为近年来的研究热点。相关工作包括：

- **LLM 作为安全分析师**：Ferrag et al., 2024 [12] 在 *"Revolutionizing Cyber Threat Detection with Large Language Models"* 中系统综述了 LLM 在威胁检测、漏洞分析、安全报告生成中的能力边界
- **LLM 增强的 IDS**：Liu et al., 2024 [13] 提出将 LLM 与传统 IDS 结合，利用模型的语义理解能力对告警进行二次分析和分类，显著降低误报率
- **安全领域的 Prompt Engineering**：Xu et al., 2024 [14] 研究了面向网络安全任务的 Prompt 设计策略，发现结构化输出（JSON Schema 约束）可以将 LLM 的安全分析准确率提升 23%

本系统的 **Prompt 模板设计**参考了上述研究成果，通过 System Prompt 设定模型的领域角色（车载网络安全专家），并采用 JSON Schema 约束输出格式，以确保分析结果的结构化与可解析性。

### 四、Function Calling 与工具增强

OpenAI 于 2023 年引入的 Function Calling 机制 [15] 使 LLM 具备了调用外部系统接口的能力。本系统借鉴 **ReAct（Reasoning + Acting）** 范式 [16]（Yao et al., 2023），使模型在对话过程中自主决策是否调用后端 API 以获取实时数据：

```
用户提问 → LLM 推理 → 决定调用 query_traffic_stats → 获取数据 → 生成回答
```

上述"推理-行动-观察"循环使系统具备了主动获取信息并进行动态推理的能力，形成了**智能安全分析代理（Security Analysis Agent）**。

### 五、多协议融合分析

车载网关作为多种异构协议的汇聚节点，其数据模型设计需兼顾不同协议的特征。本系统的**统一数据模型（UnifiedPacket）** 设计参考了以下协议标准：

- **SAE J1939 / ISO 11898**：CAN 总线标准协议栈 [17]
- **AUTOSAR SOME/IP**：车载以太网面向服务的中间件协议 [18]
- **SAE J2735 / ETSI ITS-G5**：V2X 通信消息集标准 [19]

通过将三种协议的报文统一映射到 `(timestamp, protocol, source, destination, msg_id, payload, domain)` 七元组，系统实现了跨协议的关联分析能力，弥补了传统单协议 IDS 在多协议场景下的不足。

---

## 系统架构

```
┌─────────────────────────────────────────────────────┐
│                   Vue 3 前端                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ 流量监控  │ │ 告警中心  │ │ LLM 交互式分析面板   │ │
│  │ Dashboard │ │  Anomaly │ │  (Chat Interface)    │ │
│  └──────────┘ └──────────┘ └──────────────────────┘ │
└───────────────────────┬─────────────────────────────┘
                        │ REST API
┌───────────────────────┴─────────────────────────────┐
│                 FastAPI 后端                          │
│                                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌───────────────┐  │
│  │ 流量采集与   │ │  异常检测    │ │  LLM 分析     │  │
│  │ 协议解析模块 │ │  引擎       │ │  引擎         │  │
│  │             │ │ (规则+ML)   │ │ (OpenAI/      │  │
│  │ CAN/ETH/V2X│ │ IForest     │ │  Ollama)      │  │
│  └──────┬──────┘ └──────┬──────┘ └───────┬───────┘  │
│         │               │                │           │
│  ┌──────┴───────────────┴────────────────┴───────┐  │
│  │         统一数据层 (SQLite + aiosqlite)         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 核心功能

系统包含以下四个核心功能模块：流量模拟、异常检测、语义分析与交互问答。

### 1. 多协议流量模拟与解析

- **CAN 总线**：模拟 12 种 ECU 报文（发动机、变速箱、ABS、EPS 等），支持 DoS / Fuzzy / Spoofing 三种攻击场景
- **车载以太网**：基于 SOME/IP 协议模拟 7 种服务通信（摄像头、雷达、ADAS、OTA 等）
- **V2X 通信**：模拟 BSM / MAP / SPAT 三种消息类型

所有协议流量统一解析为 `UnifiedPacket` 七元组数据模型，打破协议壁垒，实现跨域关联分析。

### 2. 两级异常检测

**第一级 — 规则引擎（快速过滤）** [6][7][8]：
- 报文频率异常检测（DoS 攻击特征）
- 未知 CAN ID 检测（Fuzzy 攻击特征）
- 负载模式异常检测（Spoofing 攻击特征）

**第二级 — Isolation Forest（深度分析）** [9]：
- 无监督异常检测，无需标注数据
- 特征向量：报文 ID、负载长度、字节熵 [11]、协议类型、功能域
- 自动训练 + 在线推理，污染率可配置

### 3. LLM 语义分析引擎

区别于传统检测系统仅输出异常标记，本系统通过 LLM 对异常事件进行深层语义分析，输出包括攻击类型判定、攻击手法描述、根因分析、影响范围评估及处置建议等结构化信息。

- **异常事件分析** [12][13]：攻击分类、根因溯源、影响评估、处置建议，结构化 JSON 输出
- **预警报告生成**：自动汇总多条异常事件，生成包含攻击链分析和时间线的安全报告
- **交互式问答** [15][16]：通过 Function Calling / ReAct 机制，LLM 自主调用后端 API 获取实时数据

### 4. 前端可视化

- **Dashboard**：流量统计概览、协议分布、攻击场景选择、一键模拟与检测
- **告警中心**：异常事件列表、严重程度筛选、单事件 AI 分析、结构化预警报告弹窗
- **AI 分析助手**：多轮对话界面，支持自然语言安全分析

---

## 技术栈

| 层级 | 技术选型 | 说明 |
|------|----------|------|
| 前端 | Vue 3 + Vite + Element Plus | SPA 应用，响应式布局 |
| 后端 | Python 3.12 + FastAPI + Uvicorn | 异步 API 服务 |
| LLM | OpenAI API / Ollama | 双模式切换，支持云端与本地部署 |
| ML | scikit-learn (Isolation Forest) | 无监督异常检测 |
| ORM | SQLAlchemy 2.0 + aiosqlite | 异步数据库操作 |
| 数据库 | SQLite | 轻量级，零配置 |
| 流量解析 | Scapy + python-can | 多协议报文构造与解析 |

---

## 项目结构

```
gateway-guard/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI 入口，CORS、路由注册
│   │   ├── config.py               # 配置管理（LLM/检测器/应用）
│   │   ├── database.py             # 异步数据库引擎与会话管理
│   │   ├── models/                 # 数据模型（ORM + Pydantic）
│   │   │   ├── packet.py           # 流量报文模型
│   │   │   ├── anomaly.py          # 异常事件模型
│   │   │   └── report.py           # 分析报告与对话历史模型
│   │   ├── routers/                # API 路由
│   │   │   ├── traffic.py          # 流量模拟与查询 API
│   │   │   ├── anomaly.py          # 异常检测与事件查询 API
│   │   │   ├── llm.py              # LLM 分析与对话 API
│   │   │   └── system.py           # 系统状态 API
│   │   ├── sources/                # 数据源抽象层
│   │   │   ├── base.py             # DataSource 抽象基类
│   │   │   ├── can_source.py       # SocketCAN 实时采集
│   │   │   ├── ethernet_source.py  # Scapy 以太网抓包
│   │   │   ├── pcap_source.py      # PCAP/BLF/ASC 文件导入
│   │   │   └── simulator_source.py # 模拟器数据源封装
│   │   ├── services/               # 核心业务逻辑
│   │   │   ├── collector.py        # 实时流量采集引擎
│   │   │   ├── traffic_parser.py   # 多协议统一解析服务
│   │   │   ├── anomaly_detector.py # 两级异常检测引擎
│   │   │   └── llm_engine.py       # LLM 分析引擎（含 Function Calling）
│   │   ├── simulators/             # 流量模拟器
│   │   │   ├── can_simulator.py    # CAN 总线模拟（含攻击场景）
│   │   │   ├── eth_simulator.py    # 车载以太网 SOME/IP 模拟
│   │   │   └── v2x_simulator.py    # V2X BSM/MAP/SPAT 模拟
│   │   └── utils/
│   │       ├── prompt_templates.py # LLM Prompt 模板集中管理
│   │       └── tools.py            # Function Calling 工具定义
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.vue                 # 主布局（侧边栏导航）
│   │   ├── main.js                 # Vue 应用入口
│   │   ├── router.js               # 路由配置
│   │   ├── api/
│   │   │   └── index.js            # Axios API 封装
│   │   └── views/
│   │       ├── Dashboard.vue       # 流量监控面板
│   │       ├── Anomaly.vue         # 告警中心
│   │       └── Chat.vue            # AI 交互分析
│   ├── index.html
│   ├── package.json
│   └── vite.config.js              # Vite 配置（含 API 代理）
├── start.sh                        # 一键启动脚本
├── deploy/                         # 部署相关
│   ├── setup_vcan.sh               # vCAN 虚拟接口配置脚本
│   └── README.md                   # 真实车机部署指南
└── README.md
```

---

## 环境要求

- **Python** 3.12+
- **Node.js** 18+
- **LLM 服务**（二选一）：
  - OpenAI API Key（推荐 gpt-4o-mini 或以上）
  - Ollama 本地部署（推荐 qwen2.5:7b）

---

## 安装与启动

### 方式一：一键启动

```bash
# 配置 LLM（二选一）
export OPENAI_API_KEY="sk-your-key"    # OpenAI 模式
# 或
export LLM_PROVIDER="ollama"            # Ollama 本地模式

# 启动
chmod +x start.sh
./start.sh
```

### 方式二：手动启动

**后端：**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**前端：**

```bash
cd frontend
npm install
npm run dev
```

### 访问地址

| 服务 | 地址 |
|------|------|
| 前端界面 | http://localhost:5173 |
| 后端 API 文档 | http://localhost:8000/docs |
| 后端 API (Redoc) | http://localhost:8000/redoc |

---

## 使用流程

### 步骤 1：生成模拟流量

在 Dashboard 页面选择攻击场景（正常流量 / DoS 攻击 / Fuzzy 攻击 / Spoofing 攻击 / 混合场景），点击「生成模拟流量」。系统将生成 CAN + 以太网 + V2X 多协议混合流量并存入数据库。

### 步骤 2：执行异常检测

点击「执行异常检测」，系统自动执行两级检测：
- 规则引擎快速筛查频率异常、未知 ID、负载异常
- Isolation Forest 模型对全量特征进行无监督异常检测

### 步骤 3：查看告警与 AI 分析

进入告警中心页面：
- 按严重程度、状态筛选异常事件
- 点击单条事件的「AI 分析」按钮，调用 LLM 进行语义分析
- 点击「生成预警报告」，LLM 自动汇总生成结构化安全报告

### 步骤 4：交互式安全问答

进入 AI 分析页面，通过自然语言与系统交互，例如：
- "最近检测到了哪些异常事件？"
- "分析一下 DoS 攻击的特征和影响"
- "当前网络流量的协议分布情况如何？"

LLM 通过 Function Calling 自动调用后端 API 获取实时数据后回答。

---

## API 接口说明

### 流量管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/traffic/simulate` | 生成模拟流量（支持多种攻击场景） |
| GET | `/api/traffic/stats` | 获取流量统计概览 |
| GET | `/api/traffic/packets` | 分页查询流量记录 |
| POST | `/api/traffic/collect/start` | 启动实时流量采集 |
| POST | `/api/traffic/collect/stop` | 停止实时流量采集 |
| GET | `/api/traffic/collect/status` | 查询采集状态与统计 |
| POST | `/api/traffic/import` | 导入离线抓包文件（PCAP/BLF/ASC） |

### 异常检测

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/anomaly/detect` | 触发异常检测 |
| GET | `/api/anomaly/events` | 查询异常事件列表（支持筛选） |
| GET | `/api/anomaly/events/{id}` | 获取单条异常事件详情 |

### LLM 分析

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/llm/analyze` | 对指定异常事件进行 LLM 语义分析 |
| POST | `/api/llm/report` | 生成安全预警报告 |
| POST | `/api/llm/chat` | 交互式安全问答（支持 Function Calling） |

### 系统

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/system/status` | 获取系统运行状态 |

---

## 数据库设计

系统使用 SQLite 作为持久化存储，包含 4 张核心表：

| 表名 | 说明 |
|------|------|
| `packets` | 流量报文记录（时间戳、协议、源/目标、报文ID、负载、功能域） |
| `anomaly_events` | 异常事件（类型、严重程度、置信度、检测方法、状态） |
| `analysis_reports` | LLM 分析报告（关联事件ID、报告内容、模型信息、Token 用量） |
| `chat_history` | 对话历史（会话ID、角色、内容、工具调用记录） |

---

## LLM 集成说明

### 双模式支持

| 模式 | 配置方式 | 适用场景 |
|------|----------|----------|
| OpenAI | `export OPENAI_API_KEY="sk-xxx"` | 分析能力强，需联网 |
| Ollama | `export LLM_PROVIDER="ollama"` | 本地部署，离线可用 |

### Prompt 工程

所有 Prompt 模板集中管理在 `utils/prompt_templates.py`：

- **SYSTEM_PROMPT**：系统角色设定（车载网络安全专家）
- **ANOMALY_ANALYSIS_PROMPT**：异常事件语义分析模板，输出结构化 JSON
- **REPORT_GENERATION_PROMPT**：预警报告生成模板

### Function Calling

交互式问答模式下，LLM 可调用以下工具函数获取实时数据：

| 工具函数 | 说明 |
|----------|------|
| `query_traffic_stats` | 查询流量统计信息 |
| `get_anomaly_events` | 获取异常事件列表 |

---

## 异常检测算法

本系统采用两级异常检测架构，第一级为基于领域知识的规则引擎，第二级为基于 Isolation Forest 的无监督机器学习模型。

### 规则引擎（第一级）

| 规则 | 检测目标 | 攻击类型 | 理论依据 |
|------|----------|----------|----------|
| 频率异常检测 | 单 ID 报文频率超过均值 N 倍 | DoS 攻击 | Cho & Shin [6] |
| 未知 ID 检测 | CAN ID 不在白名单内 | Fuzzy 攻击 | Müter & Asaj [7] |
| 负载模式检测 | 负载字节全部相同（如全 0xFF） | Spoofing 攻击 | Marchetti et al. [8] |

### Isolation Forest（第二级）[9]

- **核心思想**：异常点因其稀疏性，在随机分割中更容易被"隔离"，路径长度更短
- **特征向量**：`[msg_id_num, payload_len, byte_entropy, protocol, domain]`
- **字节熵**：参考 Wang & Stolfo [11] 的负载统计方法，正常报文熵值分布稳定，注入攻击导致熵值偏离
- **训练方式**：使用正常流量自动训练，无需标注数据
- **污染率**：默认 5%（可配置）

---

## 配置参数

主要配置通过环境变量和 `app/config.py` 管理：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `OPENAI_API_KEY` | - | OpenAI API 密钥 |
| `LLM_PROVIDER` | `openai` | LLM 提供商（openai / ollama） |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 服务地址 |
| 检测器频率阈值 | `3.0` | 频率异常判定倍数 |
| IForest 污染率 | `0.05` | Isolation Forest contamination 参数 |
| LLM temperature | `0.3` | 生成温度（低值更确定性） |
| LLM max_tokens | `1024` | 单次生成最大 Token 数 |

---

## 真实车机部署

本系统支持从模拟环境无缝切换到真实车载网络环境。通过数据源抽象层，可在不修改检测逻辑的前提下接入真实 CAN 总线、车载以太网或离线抓包文件。

### 数据源模式

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `simulator` | 内置模拟器生成数据 | 开发调试、课堂演示 |
| `can` | SocketCAN 实时读取 | 真实 CAN 总线硬件 |
| `ethernet` | Scapy 以太网抓包 | 车载以太网 SOME/IP |
| `pcap` | 导入离线文件 | 回放分析 (.pcap/.blf/.asc) |
| `multi` | CAN + 以太网同时采集 | 完整车机部署 |

### 快速切换

编辑 `backend/config.yaml` 中的 `sources` 配置段：

```yaml
sources:
  mode: can              # simulator / can / ethernet / pcap / multi
  can:
    interface: can0      # SocketCAN 接口名
    bitrate: 500000
  ethernet:
    interface: eth0
    filter: "udp port 30490"
  collector:
    enabled: true        # 启动时自动开始采集
    auto_detect: true    # 自动触发异常检测
```

也可通过前端 Dashboard 的「数据源与实时采集」面板动态切换模式并控制采集。

### 硬件要求

- **CAN 适配器**：SocketCAN 兼容设备（如 PEAK PCAN-USB、Kvaser Leaf）
- **操作系统**：Linux 5.4+（SocketCAN 内核支持）
- **权限**：CAN/以太网采集需要 root 或 `cap_net_raw` capability

详细部署步骤参见 [`deploy/README.md`](deploy/README.md)。

---

## 参考文献

### 车载网络安全

**[1]** Miller, C., & Valasek, C. (2015). *Remote Exploitation of an Unaltered Passenger Vehicle*. Black Hat USA 2015.

**[2]** Checkoway, S., et al. (2011). *Comprehensive Experimental Analyses of Automotive Attack Surfaces*. USENIX Security Symposium.

**[3]** Lokman, S. F., Othman, A. T., & Abu-Bakar, M. H. (2019). *Intrusion Detection System for Automotive Controller Area Network (CAN) Bus System: A Review*. EURASIP Journal on Wireless Communications and Networking, 2019(1), 184.

**[4]** Wu, W., et al. (2019). *A Survey of Intrusion Detection for In-Vehicle Networks*. IEEE Transactions on Intelligent Transportation Systems, 21(3), 919-933.

**[5]** Aliwa, E., et al. (2021). *Cyberattacks and Countermeasures for In-Vehicle Networks*. ACM Computing Surveys, 54(1), 1-37.

### 异常检测算法

**[6]** Cho, K. T., & Shin, K. G. (2016). *Fingerprinting Electronic Control Units for Intra-vehicle Network Security*. USENIX Security Symposium.

**[7]** Müter, M., & Asaj, N. (2011). *Entropy-based Anomaly Detection for In-vehicle Networks*. IEEE Intelligent Vehicles Symposium (IV), 1110-1115.

**[8]** Marchetti, M., Stabili, D., Guido, A., & Colajanni, M. (2016). *Evaluation of Anomaly Detection for In-vehicle Networks through Information-Theoretic Algorithms*. IEEE 2nd International Forum on Research and Technologies for Society and Industry (RTSI).

**[9]** Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. IEEE International Conference on Data Mining (ICDM), 413-422.

**[10]** Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python*. Journal of Machine Learning Research, 12, 2825-2830.

**[11]** Wang, K., & Stolfo, S. J. (2004). *Anomalous Payload-based Network Intrusion Detection*. International Workshop on Recent Advances in Intrusion Detection (RAID), 203-222.

### LLM 与网络安全

**[12]** Ferrag, M. A., et al. (2024). *Revolutionizing Cyber Threat Detection with Large Language Models: A Comprehensive Survey*. ACM Computing Surveys.

**[13]** Liu, Y., et al. (2024). *Large Language Models for Cyber Security: A Systematic Literature Review*. arXiv preprint arXiv:2405.04760.

**[14]** Xu, Z., et al. (2024). *Large Language Models for Cybersecurity: Systematic Literature Review*. IEEE Access.

### LLM 工具调用与 Agent

**[15]** OpenAI. (2023). *Function Calling and Other API Updates*. OpenAI Blog.

**[16]** Yao, S., et al. (2023). *ReAct: Synergizing Reasoning and Acting in Language Models*. International Conference on Learning Representations (ICLR).

### 车载协议标准

**[17]** ISO 11898-1:2015. *Road vehicles — Controller area network (CAN)*. International Organization for Standardization.

**[18]** AUTOSAR. (2022). *SOME/IP Protocol Specification*. AUTOSAR Classic Platform, R22-11.

**[19]** SAE International. (2020). *J2735 — V2X Communications Message Set Dictionary*. SAE Standard.

---

<div align="center">

**GatewayGuard** — 基于 LLM 的智能网关安全分析系统

</div>
