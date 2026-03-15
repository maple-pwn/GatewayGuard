# GatewayGuard：LLM增强的智能网关多协议流量分析与异常预警系统

<div style="text-align: center; margin: 60px 0;">

**项目技术文档**

版本：v1.0

日期：2026年2月

</div>

<div style="page-break-after: always;"></div>

## 目录

- [第一章 绪论](#第一章-绪论)
  - [1.1 研究背景与意义](#11-研究背景与意义)
  - [1.2 国内外研究现状](#12-国内外研究现状)
  - [1.3 系统目标与创新点](#13-系统目标与创新点)
  - [1.4 文档组织结构](#14-文档组织结构)
- [第二章 需求分析](#第二章-需求分析)
  - [2.1 功能需求](#21-功能需求)
  - [2.2 非功能需求](#22-非功能需求)
  - [2.3 用例分析](#23-用例分析)
- [第三章 系统总体设计](#第三章-系统总体设计)
  - [3.1 系统架构概览](#31-系统架构概览)
  - [3.2 技术选型](#32-技术选型)
  - [3.3 模块划分](#33-模块划分)
  - [3.4 数据流设计](#34-数据流设计)
- [第四章 多协议流量模拟子系统](#第四章-多协议流量模拟子系统)
  - [4.1 CAN总线模拟器](#41-can总线模拟器)
  - [4.2 车载以太网模拟器](#42-车载以太网模拟器)
  - [4.3 V2X通信模拟器](#43-v2x通信模拟器)
  - [4.4 攻击场景模拟](#44-攻击场景模拟)
- [第五章 统一数据模型与解析层](#第五章-统一数据模型与解析层)
  - [5.1 UnifiedPacket七元组模型](#51-unifiedpacket七元组模型)
  - [5.2 多协议解析服务](#52-多协议解析服务)
  - [5.3 数据源抽象层](#53-数据源抽象层)
- [第六章 两级异常检测引擎](#第六章-两级异常检测引擎)
  - [6.1 检测架构设计](#61-检测架构设计)
  - [6.2 规则引擎](#62-规则引擎)
  - [6.3 Isolation Forest无监督检测](#63-isolation-forest无监督检测)
  - [6.4 检测服务统一入口](#64-检测服务统一入口)
- [第七章 LLM语义分析引擎](#第七章-llm语义分析引擎)
  - [7.1 LLM集成架构](#71-llm集成架构)
  - [7.2 Prompt工程设计](#72-prompt工程设计)
  - [7.3 Function Calling交互式分析](#73-function-calling交互式分析)
  - [7.4 双模式支持](#74-双模式支持)
- [第八章 实时采集与WebSocket推送](#第八章-实时采集与websocket推送)
  - [8.1 采集引擎设计](#81-采集引擎设计)
  - [8.2 WebSocket实时推送](#82-websocket实时推送)
  - [8.3 前端实时更新机制](#83-前端实时更新机制)
- [第九章 数据持久化层](#第九章-数据持久化层)
  - [9.1 数据库设计](#91-数据库设计)
  - [9.2 ORM模型定义](#92-orm模型定义)
  - [9.3 异步数据库操作](#93-异步数据库操作)
- [第十章 RESTful API设计](#第十章-restful-api设计)
  - [10.1 API总览](#101-api总览)
  - [10.2 流量管理API](#102-流量管理api)
  - [10.3 异常检测API](#103-异常检测api)
  - [10.4 LLM分析API](#104-llm分析api)
  - [10.5 系统管理API](#105-系统管理api)
- [第十一章 前端可视化系统](#第十一章-前端可视化系统)
  - [11.1 前端架构](#111-前端架构)
  - [11.2 流量监控面板](#112-流量监控面板)
  - [11.3 告警中心](#113-告警中心)
  - [11.4 AI交互分析](#114-ai交互分析)
- [第十二章 测试与质量保障](#第十二章-测试与质量保障)
  - [12.1 测试策略](#121-测试策略)
  - [12.2 单元测试](#122-单元测试)
  - [12.3 集成测试](#123-集成测试)
  - [12.4 测试结果](#124-测试结果)
- [第十三章 部署与运维](#第十三章-部署与运维)
  - [13.1 开发环境部署](#131-开发环境部署)
  - [13.2 真实车机部署](#132-真实车机部署)
  - [13.3 配置管理](#133-配置管理)
- [第十四章 总结与展望](#第十四章-总结与展望)
  - [14.1 工作总结](#141-工作总结)
  - [14.2 不足与改进方向](#142-不足与改进方向)
- [参考文献](#参考文献)
- [附录](#附录)

<div style="page-break-after: always;"></div>
## 第一章 绪论

### 1.1 研究背景与意义

随着智能网联汽车技术的快速发展，现代汽车已从传统的机械系统演变为高度互联的"车轮上的计算机"。一辆典型的智能网联汽车内部包含70-100个电子控制单元（ECU），通过CAN总线、车载以太网、LIN等多种总线协议进行通信，同时通过V2X（Vehicle-to-Everything）技术与外部基础设施、其他车辆及云端服务进行数据交互。

然而，这种高度互联也带来了严峻的网络安全挑战。近年来，车载网络安全事件频发：2015年Charlie Miller和Chris Valasek远程入侵Jeep Cherokee，通过CAN总线注入攻击控制了车辆的转向和制动系统；2020年Tencent Keen Lab披露了多款车型的CAN总线漏洞；2023年以来，针对V2X通信的中间人攻击和GPS欺骗攻击案例持续增长。这些安全事件表明，车载网关作为连接车内各域网络与外部通信的核心节点，其安全防护能力直接关系到车辆和乘员的安全。

> **[图片位置1]** 建议插入：智能网联汽车网络架构示意图，展示CAN总线、车载以太网、V2X等多协议通信拓扑，以及网关在其中的核心位置。

传统的车载入侵检测系统（IDS）主要依赖预定义规则或简单的统计阈值，存在以下局限性：

1. **规则滞后性**：基于已知攻击特征的规则库难以应对零日攻击和新型攻击变种
2. **跨协议盲区**：针对单一协议的检测方案无法发现跨CAN/以太网/V2X的协同攻击
3. **告警可解释性差**：传统检测系统产生的告警缺乏语义层面的分析，安全运维人员难以快速理解攻击意图和影响范围
4. **实时性不足**：离线分析模式无法满足车载场景对毫秒级响应的需求

基于上述背景，本项目设计并实现了GatewayGuard——一个LLM增强的智能网关多协议流量分析与异常预警系统。该系统创新性地将大语言模型（LLM）的语义理解能力与传统机器学习检测方法相结合，构建了"规则引擎 + Isolation Forest + LLM语义分析"的三层防御体系，实现了对CAN总线、车载以太网（SOME/IP）和V2X通信的统一监控与智能预警。

### 1.2 国内外研究现状

#### 1.2.1 车载入侵检测技术

车载入侵检测系统（IDS）的研究可追溯至2010年前后。Hoppe等人（2011）首次提出了基于CAN报文频率分析的异常检测方法。此后，研究者们从多个维度推进了该领域的发展：

**基于规则的检测方法**：Müter等人（2011）提出了基于CAN报文ID白名单和周期性检查的规则引擎，能够有效检测未授权ID注入和DoS攻击。该方法计算开销小、实时性好，但对未知攻击的检测能力有限。

**基于机器学习的检测方法**：Song等人（2020）将深度学习引入CAN IDS，使用LSTM网络建模报文时序特征，在HCRL数据集上取得了99%以上的检测率。Taylor等人（2016）采用Isolation Forest算法进行无监督异常检测，无需标注数据即可发现偏离正常模式的异常流量。

**基于信息熵的检测方法**：Muter等人（2011）提出利用CAN报文负载的信息熵变化检测Fuzzy攻击和Spoofing攻击，该方法对负载篡改类攻击具有较好的检测效果。

#### 1.2.2 大语言模型在安全领域的应用

2023年以来，大语言模型在网络安全领域的应用成为研究热点。Microsoft Security Copilot将GPT-4集成到安全运营中心（SOC），实现了告警分类、事件摘要和响应建议的自动化生成。Google的SecPaLM模型专门针对安全日志分析进行了微调，能够从非结构化日志中提取攻击链信息。

在车载安全领域，LLM的应用尚处于探索阶段。现有研究主要集中在利用LLM辅助漏洞分析和安全策略生成，将LLM直接集成到车载IDS的实时分析流程中的工作较少。本项目在这一方向上进行了有益的探索。

#### 1.2.3 多协议统一分析

传统车载安全方案通常针对单一协议设计检测算法。随着车载网络架构向域控制器（Domain Controller）演进，网关需要同时处理CAN、以太网和V2X等多种协议的流量。Iehira等人（2018）提出了跨协议关联分析的概念，但缺乏统一的数据模型支撑。本项目设计的UnifiedPacket七元组模型为多协议统一分析提供了数据基础。

### 1.3 系统目标与创新点

#### 1.3.1 系统目标

GatewayGuard系统的核心目标是构建一个面向智能网联汽车网关的多协议流量分析与异常预警平台，具体包括：

1. **多协议统一采集与解析**：支持CAN总线、车载以太网（SOME/IP）和V2X通信三种协议的实时流量采集，并将异构数据统一为标准化的七元组模型
2. **两级异常检测**：结合规则引擎的快速筛查和Isolation Forest的无监督学习，实现对DoS、Fuzzy、Spoofing等典型攻击的高效检测
3. **LLM语义增强分析**：利用大语言模型对检测到的异常事件进行深度语义分析，自动生成攻击意图判断、影响评估和处置建议
4. **实时监控与预警**：通过WebSocket实时推送机制，实现亚秒级的告警通知和流量状态更新
5. **可视化交互平台**：提供直观的Web界面，支持流量监控、告警管理和AI交互式安全分析

#### 1.3.2 创新点

本系统的主要创新点包括：

1. **三层检测架构**：首次将"规则引擎 + Isolation Forest + LLM语义分析"三种方法有机结合，兼顾检测速度、未知攻击发现能力和告警可解释性
2. **UnifiedPacket七元组模型**：设计了跨CAN/ETH/V2X的统一数据模型，为多协议关联分析奠定基础
3. **Function Calling交互式分析**：利用OpenAI Function Calling机制，实现LLM与后端数据的动态交互，使安全分析师能够通过自然语言查询实时流量数据
4. **WebSocket实时推送架构**：采用异步非阻塞的采集-检测-推送流水线，实现毫秒级的告警响应
5. **双模式LLM支持**：同时支持OpenAI云端API和Ollama本地部署，兼顾分析能力和数据隐私

### 1.4 文档组织结构

本文档共分为十四章，组织结构如下：

- **第一章 绪论**：介绍研究背景、国内外现状、系统目标与创新点
- **第二章 需求分析**：详细阐述功能需求、非功能需求和用例分析
- **第三章 系统总体设计**：描述系统架构、技术选型、模块划分和数据流设计
- **第四章 多协议流量模拟子系统**：介绍CAN/ETH/V2X模拟器和攻击场景模拟的实现
- **第五章 统一数据模型与解析层**：阐述UnifiedPacket七元组模型和多协议解析服务
- **第六章 两级异常检测引擎**：详细描述规则引擎和Isolation Forest检测器的设计与实现
- **第七章 LLM语义分析引擎**：介绍LLM集成架构、Prompt工程和Function Calling机制
- **第八章 实时采集与WebSocket推送**：描述采集引擎和实时推送架构
- **第九章 数据持久化层**：介绍数据库设计和异步ORM操作
- **第十章 RESTful API设计**：详细列出所有API端点的设计
- **第十一章 前端可视化系统**：描述前端架构和各功能面板的实现
- **第十二章 测试与质量保障**：介绍测试策略和测试结果
- **第十三章 部署与运维**：描述开发环境和真实车机的部署方案
- **第十四章 总结与展望**：总结工作成果并展望未来改进方向

<div style="page-break-after: always;"></div>
## 第二章 需求分析

### 2.1 功能需求

#### 2.1.1 多协议流量采集与模拟

| 编号 | 需求描述 | 优先级 |
|------|---------|--------|
| FR-01 | 支持CAN总线实时流量采集（SocketCAN接口） | 高 |
| FR-02 | 支持车载以太网流量采集（原始套接字/BPF过滤） | 高 |
| FR-03 | 支持V2X通信数据采集（PC5/Uu接口） | 中 |
| FR-04 | 支持PCAP/BLF/ASC离线文件导入 | 中 |
| FR-05 | 提供CAN/ETH/V2X多协议流量模拟器 | 高 |
| FR-06 | 支持DoS、Fuzzy、Spoofing攻击场景模拟 | 高 |
| FR-07 | 支持混合场景（正常+攻击）流量生成 | 中 |

#### 2.1.2 异常检测

| 编号 | 需求描述 | 优先级 |
|------|---------|--------|
| FR-08 | 基于规则的快速异常检测（频率、ID白名单、负载） | 高 |
| FR-09 | 基于Isolation Forest的无监督异常检测 | 高 |
| FR-10 | 支持在线训练（用正常流量自动训练ML模型） | 中 |
| FR-11 | 异常事件分级（critical/high/medium/low） | 高 |
| FR-12 | 手动触发检测和自动实时检测两种模式 | 高 |

#### 2.1.3 LLM语义分析

| 编号 | 需求描述 | 优先级 |
|------|---------|--------|
| FR-13 | 对异常事件进行LLM语义分析（攻击类型、意图、建议） | 高 |
| FR-14 | 基于多事件生成预警报告 | 中 |
| FR-15 | 交互式安全问答（支持Function Calling） | 高 |
| FR-16 | 支持OpenAI API和Ollama本地模型双模式 | 中 |

#### 2.1.4 实时监控与可视化

| 编号 | 需求描述 | 优先级 |
|------|---------|--------|
| FR-17 | 实时流量统计面板（总量、分协议计数、速率） | 高 |
| FR-18 | WebSocket实时告警推送 | 高 |
| FR-19 | 流量记录分页查询与筛选 | 中 |
| FR-20 | 异常事件列表与详情查看 | 高 |
| FR-21 | AI交互分析界面 | 中 |
| FR-22 | 数据清理与管理功能 | 低 |

### 2.2 非功能需求

| 类别 | 需求描述 | 指标 |
|------|---------|------|
| 性能 | 流量采集吞吐量 | ≥ 5000 pkt/s |
| 性能 | 规则检测延迟 | ≤ 10ms / 批次 |
| 性能 | WebSocket推送延迟 | ≤ 100ms |
| 可靠性 | 系统连续运行时间 | ≥ 24小时无崩溃 |
| 可靠性 | WebSocket自动重连 | 断线后指数退避重连 |
| 可扩展性 | 新协议接入 | 实现DataSource接口即可 |
| 可扩展性 | 新检测规则 | 在RuleBasedDetector中添加方法 |
| 安全性 | LLM API密钥管理 | 环境变量注入，不硬编码 |
| 安全性 | 数据库访问 | 参数化查询，防SQL注入 |
| 兼容性 | 运行环境 | Linux（x86_64/ARM64） |
| 兼容性 | 浏览器支持 | Chrome/Firefox/Edge最新版 |

### 2.3 用例分析

> **[图片位置2]** 建议插入：系统用例图（UML Use Case Diagram），展示安全分析师、系统管理员两类角色与各功能模块的交互关系。

#### 用例1：实时流量监控

- **参与者**：安全分析师
- **前置条件**：系统已启动，数据源已配置
- **主要流程**：
  1. 分析师打开Dashboard页面
  2. 选择数据源模式（模拟器/CAN/以太网/PCAP/多源混合）
  3. 点击"启动采集"
  4. 系统通过WebSocket实时推送流量统计和采集状态
  5. 分析师在流量记录表中查看最新报文
- **后置条件**：流量数据持续采集并存入数据库

#### 用例2：异常检测与告警

- **参与者**：安全分析师
- **前置条件**：数据库中已有流量数据
- **主要流程**：
  1. 系统在采集过程中自动触发批量检测（每200条报文）
  2. 检测引擎执行规则检查和ML模型预测
  3. 发现异常时，通过WebSocket实时推送告警
  4. 高危告警（critical/high）触发桌面通知
  5. 分析师在告警中心查看详情
- **替代流程**：分析师手动点击"执行异常检测"触发一次性检测

#### 用例3：AI辅助安全分析

- **参与者**：安全分析师
- **前置条件**：存在已检测到的异常事件
- **主要流程**：
  1. 分析师选择一个异常事件，点击"AI分析"
  2. LLM引擎接收事件上下文，生成语义分析报告
  3. 报告包含：攻击类型判断、攻击手法、根因分析、影响范围、处置建议
  4. 分析师可进入交互式对话，通过自然语言追问
  5. LLM通过Function Calling查询实时数据辅助回答
- **后置条件**：分析报告存入数据库

#### 用例4：预警报告生成

- **参与者**：安全分析师
- **前置条件**：存在多个异常事件
- **主要流程**：
  1. 分析师点击"生成预警报告"
  2. 系统汇总最近的异常事件
  3. LLM生成包含时间线、攻击链分析、影响评估和建议的综合报告
  4. 报告以结构化JSON格式返回并展示

## 第三章 系统总体设计

### 3.1 系统架构概览

GatewayGuard采用经典的前后端分离架构，整体分为四个层次：数据采集层、业务逻辑层、API服务层和前端展示层。

> **[图片位置3]** 建议插入：系统总体架构图，展示四层架构（数据采集层→业务逻辑层→API服务层→前端展示层）及各层的核心组件。

**架构层次说明：**

```
┌─────────────────────────────────────────────────────┐
│                   前端展示层                          │
│   Vue 3 + Element Plus + ECharts + WebSocket Client  │
├─────────────────────────────────────────────────────┤
│                   API服务层                           │
│   FastAPI (REST + WebSocket) + CORS + 路由分发        │
├─────────────────────────────────────────────────────┤
│                   业务逻辑层                          │
│  ┌──────────┐ ┌──────────────┐ ┌──────────────────┐ │
│  │ 流量解析  │ │ 异常检测引擎  │ │ LLM语义分析引擎  │ │
│  │ 服务     │ │ (规则+ML)    │ │ (OpenAI/Ollama)  │ │
│  └──────────┘ └──────────────┘ └──────────────────┘ │
│  ┌──────────┐ ┌──────────────┐ ┌──────────────────┐ │
│  │ 采集引擎  │ │ WebSocket    │ │ 流量模拟器       │ │
│  │ Collector │ │ Manager      │ │ (CAN/ETH/V2X)   │ │
│  └──────────┘ └──────────────┘ └──────────────────┘ │
├─────────────────────────────────────────────────────┤
│                   数据采集层                          │
│  ┌──────────┐ ┌──────────┐ ┌──────┐ ┌────────────┐ │
│  │SocketCAN │ │Raw Socket│ │ V2X  │ │ PCAP/BLF   │ │
│  │ (vcan0)  │ │ (eth0)   │ │(PC5) │ │ 文件导入    │ │
│  └──────────┘ └──────────┘ └──────┘ └────────────┘ │
├─────────────────────────────────────────────────────┤
│                   持久化层                           │
│            SQLite + SQLAlchemy (异步)                 │
└─────────────────────────────────────────────────────┘
```

### 3.2 技术选型

| 层次 | 技术 | 版本 | 选型理由 |
|------|------|------|---------|
| 后端框架 | FastAPI | 0.100+ | 原生异步支持、自动OpenAPI文档、WebSocket内置支持 |
| ORM | SQLAlchemy | 2.0+ | 异步引擎支持、成熟的ORM映射、灵活的查询构建 |
| 数据库 | SQLite + aiosqlite | - | 零配置部署、适合嵌入式场景、异步驱动 |
| 数据验证 | Pydantic | 2.0+ | FastAPI原生集成、类型安全、JSON序列化 |
| ML框架 | scikit-learn | 1.3+ | Isolation Forest实现成熟、API简洁 |
| 数值计算 | NumPy | 1.24+ | 特征向量计算、信息熵计算 |
| LLM客户端 | openai (Python SDK) | 1.0+ | 统一的OpenAI/Ollama接口、异步支持 |
| CAN接口 | python-can | 4.0+ | SocketCAN驱动、多平台支持 |
| 网络抓包 | scapy | 2.5+ | 原始套接字、BPF过滤、PCAP解析 |
| 配置管理 | PyYAML + dataclass | - | 层次化配置、环境变量覆盖 |
| 前端框架 | Vue 3 | 3.3+ | Composition API、响应式系统、轻量级 |
| UI组件库 | Element Plus | 2.4+ | 企业级组件、表格/表单/对话框丰富 |
| 构建工具 | Vite | 5.0+ | 极速HMR、ESM原生支持 |
| HTTP客户端 | Axios | 1.6+ | Promise封装、拦截器、请求取消 |

### 3.3 模块划分

> **[图片位置4]** 建议插入：模块依赖关系图，展示各Python模块之间的import依赖和调用关系。

后端代码按照功能职责划分为以下模块：

```
backend/
├── app/
│   ├── main.py              # FastAPI应用入口、生命周期管理
│   ├── config.py            # 配置管理（YAML + 环境变量）
│   ├── database.py          # 异步数据库引擎与会话工厂
│   ├── models/              # 数据模型层
│   │   ├── packet.py        #   UnifiedPacket + PacketORM
│   │   ├── anomaly.py       #   AnomalyEvent + AnomalyEventORM
│   │   └── report.py        #   AnalysisReportORM + ChatHistoryORM
│   ├── routers/             # API路由层
│   │   ├── traffic.py       #   流量管理API（/api/traffic/*）
│   │   ├── anomaly.py       #   异常检测API（/api/anomaly/*）
│   │   ├── llm.py           #   LLM分析API（/api/llm/*）
│   │   ├── system.py        #   系统管理API（/api/system/*）
│   │   └── ws.py            #   WebSocket端点（/ws/realtime）
│   ├── services/            # 业务服务层
│   │   ├── anomaly_detector.py  # 两级异常检测引擎
│   │   ├── llm_engine.py       # LLM分析引擎
│   │   ├── traffic_parser.py   # 多协议解析服务
│   │   ├── collector.py        # 实时采集引擎
│   │   └── ws_manager.py       # WebSocket连接管理器
│   ├── simulators/          # 流量模拟器
│   │   ├── can_simulator.py    # CAN总线模拟
│   │   ├── eth_simulator.py    # 车载以太网模拟
│   │   └── v2x_simulator.py   # V2X通信模拟
│   ├── sources/             # 数据源抽象层
│   │   ├── base.py             # DataSource抽象基类
│   │   ├── can_source.py       # CAN总线数据源
│   │   ├── ethernet_source.py  # 以太网数据源
│   │   ├── pcap_source.py      # PCAP文件数据源
│   │   └── simulator_source.py # 模拟器数据源
│   └── utils/               # 工具模块
│       ├── tools.py            # Function Calling工具定义
│       └── prompt_templates.py # LLM Prompt模板
├── tests/                   # 测试套件
├── config.yaml              # 配置文件
└── requirements.txt         # Python依赖
```

### 3.4 数据流设计

> **[图片位置5]** 建议插入：系统数据流图（DFD），展示从数据采集到告警推送的完整数据流转过程。

系统的核心数据流如下：

**实时采集模式数据流：**

```
数据源(CAN/ETH/V2X/PCAP)
    │
    ▼
CollectorService._collect_loop()  ──── 10ms轮询间隔
    │
    ▼
缓冲区(deque, maxlen=10000)
    │
    ▼ (每200条触发)
_persist_and_detect()  ──── asyncio.create_task() 非阻塞
    │
    ├──▶ PacketORM 批量写入 SQLite
    │
    ├──▶ AnomalyDetectorService.detect()
    │       ├── RuleBasedDetector.check()     ← 规则检测
    │       └── IsolationForestDetector.predict() ← ML检测
    │
    ├──▶ AnomalyEventORM 写入数据库
    │
    └──▶ ws_manager.broadcast()  ──── 实时推送告警
            │
            ▼
        WebSocket Client (Dashboard.vue)
            │
            ├── stats_update → 更新采集状态面板
            └── alerts → 实时告警时间线 + 桌面通知
```

**LLM分析数据流：**

```
用户触发分析请求
    │
    ▼
/api/llm/analyze 或 /api/llm/chat
    │
    ▼
LLMEngine._call_llm()
    │
    ├── OpenAI模式: AsyncOpenAI → api.openai.com
    └── Ollama模式: AsyncOpenAI → localhost:11434/v1
    │
    ▼
响应解析 (JSON / Function Calling)
    │
    ├── 语义分析结果 → AnalysisReportORM
    └── 对话记录 → ChatHistoryORM
```

<div style="page-break-after: always;"></div>
## 第四章 多协议流量模拟子系统

### 4.1 CAN总线模拟器

CAN总线模拟器（`simulators/can_simulator.py`）负责生成符合真实车载CAN网络特征的模拟流量。模拟器预定义了12种常见的CAN报文类型，覆盖动力域、底盘域、车身域和信息娱乐域四大功能域。

#### 4.1.1 正常报文定义

| CAN ID | 源ECU | 功能域 | 周期(ms) | DLC | 信号描述 |
|--------|-------|--------|---------|-----|---------|
| 0x0C0 | ECM | powertrain | 10 | 8 | 发动机转速/扭矩 |
| 0x0C8 | ECM | powertrain | 20 | 8 | 发动机温度 |
| 0x130 | TCM | powertrain | 20 | 8 | 变速箱档位 |
| 0x180 | ABS | chassis | 10 | 8 | 轮速 |
| 0x1A0 | ESP | chassis | 20 | 8 | 横摆角速度 |
| 0x200 | EPS | chassis | 10 | 8 | 转向角 |
| 0x260 | BCM | body | 100 | 8 | 车灯/车门状态 |
| 0x280 | BCM | body | 200 | 4 | 空调状态 |
| 0x320 | ICM | infotainment | 50 | 8 | 仪表盘显示 |
| 0x3E0 | HU | infotainment | 100 | 8 | 主机指令 |
| 0x7DF | DIAG | body | 非周期 | 8 | OBD诊断广播 |
| 0x7E0 | DIAG | powertrain | 非周期 | 8 | 诊断请求 |

#### 4.1.2 正常流量生成

`generate_normal_can(count, base_time)` 函数从上述12种报文中随机选取，生成指定数量的正常CAN报文。每条报文的时间戳按10ms间隔递增，负载为随机字节。对于发动机转速报文（0x0C0），模拟器还实现了信号解码逻辑：

```python
# 发动机转速解码：前两字节组合 × 0.25 = RPM
rpm = ((byte0 << 8) | byte1) * 0.25
```

#### 4.1.3 关键实现代码

```python
NORMAL_CAN_MESSAGES = [
    ("0x0C0", "ECM", "powertrain", 10, 8),   # 发动机转速/扭矩
    ("0x0C8", "ECM", "powertrain", 20, 8),   # 发动机温度
    # ... 共12种报文类型
]

def generate_normal_can(count=100, base_time=None):
    packets = []
    for i in range(count):
        msg = random.choice(NORMAL_CAN_MESSAGES)
        msg_id, src, domain, _, dlc = msg
        payload = _random_payload(dlc)
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.01,
            protocol="CAN", source=src, destination="BROADCAST",
            msg_id=msg_id, payload_hex=payload,
            domain=domain,
            metadata={"bus": "CAN-H", "bitrate": 500000},
        ))
    return packets
```

### 4.2 车载以太网模拟器

车载以太网模拟器（`simulators/eth_simulator.py`）模拟基于SOME/IP协议的车载以太网通信。SOME/IP（Scalable service-Oriented MiddlewarE over IP）是AUTOSAR定义的车载以太网中间件协议，广泛应用于ADAS、信息娱乐和诊断等高带宽场景。

#### 4.2.1 SOME/IP服务定义

| Service ID | Method ID | 源节点 | 目标节点 | 功能域 | 描述 |
|-----------|-----------|--------|---------|--------|------|
| 0x0100 | 0x0001 | HU | ADAS | infotainment | 主机→ADAS请求1 |
| 0x0100 | 0x0002 | HU | ADAS | infotainment | 主机→ADAS请求2 |
| 0x0200 | 0x0001 | ADAS | GW | chassis | ADAS→网关数据 |
| 0x0300 | 0x0001 | TBOX | GW | body | T-BOX→网关 |
| 0x0300 | 0x0002 | TBOX | CLOUD | body | T-BOX→云端 |
| 0x0400 | 0x0001 | GW | BCM | body | 网关→车身控制 |
| 0x0500 | 0x0001 | DIAG_ETH | GW | body | 以太网诊断 |

#### 4.2.2 关键实现

```python
def generate_normal_eth(count=80, base_time=None):
    packets = []
    for i in range(count):
        svc = random.choice(SOMEIP_SERVICES)
        service_id, method_id, src, dst, domain = svc
        payload_len = random.randint(8, 128)
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.02,
            protocol="ETH", source=src, destination=dst,
            msg_id=f"{service_id}.{method_id}",
            payload_decoded={
                "service_id": service_id, "method_id": method_id,
                "msg_type": "REQUEST", "return_code": "E_OK",
            },
            domain=domain,
            metadata={"eth_type": "SOME/IP", "vlan": 10},
        ))
    return packets
```

### 4.3 V2X通信模拟器

V2X模拟器（`simulators/v2x_simulator.py`）模拟车辆与外部环境的通信，支持V2V（车对车）和V2I（车对基础设施）两种通信模式。

#### 4.3.1 V2X消息类型

| 消息类型 | 通信模式 | 描述 | 典型频率 |
|---------|---------|------|---------|
| BSM | V2V | 基本安全消息（位置、速度、航向） | 10Hz |
| MAP | V2I | 地图/道路拓扑数据 | 1Hz |
| SPAT | V2I | 信号灯相位与时序 | 1Hz |
| RSI | V2I | 路侧信息（施工、事故等） | 事件触发 |

#### 4.3.2 模拟数据特征

V2X模拟器生成的BSM消息包含以下关键字段：
- **位置信息**：以上海市中心（31.2304°N, 121.4737°E）为基准，添加±0.01°的随机偏移
- **速度**：0-120 km/h随机分布
- **航向**：0-359°随机分布
- **通信参数**：PC5直连通信信道，5.9GHz频段

### 4.4 攻击场景模拟

系统实现了三种典型的车载网络攻击模拟，用于验证异常检测引擎的有效性。

#### 4.4.1 DoS攻击模拟

```python
def generate_dos_attack(count=500, base_time=None):
    """高频发送同一ID报文淹没总线"""
    target_id = "0x000"  # 最高优先级ID
    for i in range(count):
        # 时间间隔仅0.2ms，远超正常10ms周期
        timestamp = base_time + i * 0.0002
        # 源标记为ATTACKER，域标记为unknown
```

**攻击特征**：使用最高优先级ID（0x000），以0.2ms间隔（5000 pkt/s）发送，是正常频率的50-500倍。

#### 4.4.2 Fuzzy攻击模拟

```python
def generate_fuzzy_attack(count=200, base_time=None):
    """随机ID和随机负载的模糊测试攻击"""
    rand_id = f"0x{random.randint(0, 0x7FF):03X}"  # 随机11位CAN ID
    rand_dlc = random.randint(1, 8)                  # 随机DLC
```

**攻击特征**：随机生成0x000-0x7FF范围内的CAN ID，大量ID不在合法白名单中，DLC随机变化。

#### 4.4.3 Spoofing攻击模拟

```python
def generate_spoofing_attack(count=100, base_time=None):
    """伪装合法ECU发送篡改报文"""
    target = random.choice(NORMAL_CAN_MESSAGES)  # 选择一个合法报文
    payload_hex = "FF" * dlc                      # 负载全为0xFF
```

**攻击特征**：使用合法的CAN ID和源ECU名称，但负载全部填充为0xFF，模拟ECU被劫持后发送异常数据。

#### 4.4.4 混合场景

`simulate_traffic` API支持`mixed`场景，同时生成正常流量和三种攻击流量，模拟真实环境中攻击与正常通信并存的情况：

| 流量类型 | 数量比例 | 说明 |
|---------|---------|------|
| 正常CAN | count | 基准正常流量 |
| DoS攻击 | count/3 | 高频洪泛 |
| Fuzzy攻击 | count/3 | 随机探测 |
| Spoofing攻击 | count/3 | 伪装篡改 |
| 正常ETH | count/3 | 以太网背景流量 |
| 正常V2X | count/4 | V2X背景流量 |

## 第五章 统一数据模型与解析层

### 5.1 UnifiedPacket七元组模型

UnifiedPacket是GatewayGuard系统的核心数据模型，将CAN、以太网和V2X三种异构协议的报文统一抽象为七元组结构。这一设计使得上层的异常检测和LLM分析模块无需关心底层协议差异，实现了真正的跨协议统一分析。

> **[图片位置6]** 建议插入：UnifiedPacket七元组模型示意图，展示七个字段及其在CAN/ETH/V2X三种协议中的映射关系。

#### 5.1.1 七元组定义

```python
class UnifiedPacket(BaseModel):
    timestamp: float        # 时间戳（Unix epoch秒）
    protocol: str           # 协议类型: CAN / ETH / V2X
    source: str             # 源节点标识
    destination: str        # 目标节点标识
    msg_id: str             # 消息标识符
    payload_hex: str = ""   # 原始负载（十六进制字符串）
    payload_decoded: dict = {}  # 解码后的结构化负载
    domain: str = ""        # 功能域: powertrain/chassis/body/infotainment/v2x
    metadata: dict = {}     # 扩展元数据
```

#### 5.1.2 跨协议字段映射

| 七元组字段 | CAN总线 | 车载以太网(SOME/IP) | V2X |
|-----------|---------|-------------------|-----|
| timestamp | 报文接收时间 | 报文接收时间 | 报文接收时间 |
| protocol | "CAN" | "ETH" | "V2X" |
| source | ECU名称(ECM/ABS等) | 源节点(HU/ADAS等) | OBU_xxx / RSU_xx |
| destination | "BROADCAST" | 目标节点(GW/BCM等) | "BROADCAST" / OBU_001 |
| msg_id | CAN ID(0x0C0等) | ServiceID.MethodID | 消息类型(BSM/MAP等) |
| payload_hex | 原始字节十六进制 | SOME/IP负载十六进制 | 空（结构化数据） |
| payload_decoded | 信号解码结果 | 服务调用参数 | 位置/速度/航向等 |
| domain | 由CAN ID查表确定 | 由服务类型确定 | "v2x" |
| metadata | bus/bitrate | eth_type/vlan | channel/frequency |

#### 5.1.3 ORM持久化模型

UnifiedPacket的持久化通过PacketORM实现，映射到SQLite的`packets`表：

```python
class PacketORM(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, index=True)
    source = Column(String(64))
    destination = Column(String(64))
    msg_id = Column(String(32))
    payload = Column(LargeBinary)          # 二进制存储原始负载
    payload_decoded = Column(Text)          # JSON字符串存储解码结果
    domain = Column(String(32))
    metadata_json = Column(Text)            # JSON字符串存储元数据
    created_at = Column(DateTime, default=datetime.utcnow)
```

关键设计决策：
- `timestamp`和`protocol`字段建立索引，加速时间范围查询和协议过滤
- `payload`使用`LargeBinary`类型存储原始二进制数据，避免编码转换开销
- `payload_decoded`和`metadata_json`使用`Text`类型存储JSON字符串，保持灵活性

### 5.2 多协议解析服务

TrafficParserService（`services/traffic_parser.py`）提供统一的多协议解析入口，将原始数据转换为UnifiedPacket。

#### 5.2.1 CAN报文解析器

CANParser维护了一个CAN ID知识库，包含12个已知ID到ECU名称、功能域和信号类型的映射：

```python
class CANParser:
    KNOWN_IDS = {
        "0x0C0": ("ECM", "powertrain", "engine_rpm_torque"),
        "0x0C8": ("ECM", "powertrain", "engine_temp"),
        "0x130": ("TCM", "powertrain", "gear_status"),
        "0x180": ("ABS", "chassis", "wheel_speed"),
        "0x1A0": ("ESP", "chassis", "yaw_rate"),
        "0x200": ("EPS", "chassis", "steering_angle"),
        "0x260": ("BCM", "body", "light_door_status"),
        "0x280": ("BCM", "body", "ac_status"),
        "0x320": ("ICM", "infotainment", "dashboard"),
        "0x3E0": ("HU", "infotainment", "head_unit_cmd"),
        "0x7DF": ("DIAG", "body", "obd_broadcast"),
        "0x7E0": ("DIAG", "powertrain", "diag_request"),
    }
```

对于发动机转速报文（0x0C0），解析器实现了信号级解码：

```python
if msg_id == "0x0C0" and dlc >= 2:
    b0 = int(payload_hex[0:2], 16)
    b1 = int(payload_hex[2:4], 16)
    decoded["rpm"] = round(((b0 << 8) | b1) * 0.25, 1)
```

#### 5.2.2 以太网(SOME/IP)解析器

EthernetParser将SOME/IP报文解析为UnifiedPacket，msg_id格式为`ServiceID.MethodID`：

```python
class EthernetParser:
    def parse(self, service_id, method_id, src, dst, payload_hex, timestamp=None):
        return UnifiedPacket(
            protocol="ETH",
            msg_id=f"{service_id}.{method_id}",
            payload_decoded={
                "service_id": service_id, "method_id": method_id,
                "msg_type": "REQUEST", "return_code": "E_OK",
            },
            metadata={"eth_type": "SOME/IP", "vlan": 10},
        )
```

#### 5.2.3 批量解析入口

TrafficParserService.parse_batch()根据`protocol`字段自动分发到对应的解析器：

```python
class TrafficParserService:
    def parse_batch(self, raw_records: List[dict]) -> List[UnifiedPacket]:
        for rec in raw_records:
            proto = rec.get("protocol", "").upper()
            if proto == "CAN":
                pkt = self.can_parser.parse(...)
            elif proto == "ETH":
                pkt = self.eth_parser.parse(...)
            elif proto == "V2X":
                pkt = UnifiedPacket(protocol="V2X", ...)
```

### 5.3 数据源抽象层

数据源抽象层（`sources/base.py`）定义了统一的DataSource接口，使采集引擎能够透明地切换不同的数据来源。

#### 5.3.1 DataSource抽象基类

```python
class DataSource(ABC):
    @abstractmethod
    async def start(self) -> None:
        """初始化数据源连接"""

    @abstractmethod
    async def stop(self) -> None:
        """释放数据源资源"""

    @abstractmethod
    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        """读取一批报文"""

    async def read_stream(self):
        """异步生成器，持续产出报文"""
        while True:
            batch = await self.read()
            for pkt in batch:
                yield pkt
```

#### 5.3.2 数据源实现

| 数据源 | 类名 | 底层技术 | 适用场景 |
|--------|------|---------|---------|
| CAN总线 | CANSource | python-can + SocketCAN | 真实车机CAN采集 |
| 以太网 | EthernetSource | scapy + 原始套接字 | 真实车载以太网采集 |
| PCAP文件 | PcapSource | scapy.rdpcap | 离线抓包文件分析 |
| 模拟器 | SimulatorSource | 内置模拟器 | 开发测试环境 |

<div style="page-break-after: always;"></div>

- [第一章 绪论](#第一章-绪论)
  - [1.1 研究背景与意义](#11-研究背景与意义)
  - [1.2 国内外研究现状](#12-国内外研究现状)
  - [1.3 系统目标与创新点](#13-系统目标与创新点)
  - [1.4 文档组织结构](#14-文档组织结构)
- [第二章 需求分析](#第二章-需求分析)
  - [2.1 功能需求](#21-功能需求)
  - [2.2 非功能需求](#22-非功能需求)
  - [2.3 用例分析](#23-用例分析)
- [第三章 系统总体设计](#第三章-系统总体设计)
  - [3.1 系统架构概览](#31-系统架构概览)
  - [3.2 技术选型](#32-技术选型)
  - [3.3 模块划分](#33-模块划分)
  - [3.4 数据流设计](#34-数据流设计)
- [第四章 多协议流量模拟子系统](#第四章-多协议流量模拟子系统)
  - [4.1 CAN总线模拟器](#41-can总线模拟器)
  - [4.2 车载以太网模拟器](#42-车载以太网模拟器)
  - [4.3 V2X通信模拟器](#43-v2x通信模拟器)
  - [4.4 攻击场景模拟](#44-攻击场景模拟)
- [第五章 统一数据模型与解析层](#第五章-统一数据模型与解析层)
  - [5.1 UnifiedPacket七元组模型](#51-unifiedpacket七元组模型)
  - [5.2 多协议解析服务](#52-多协议解析服务)
  - [5.3 数据源抽象层](#53-数据源抽象层)
- [第六章 两级异常检测引擎](#第六章-两级异常检测引擎)
  - [6.1 检测架构设计](#61-检测架构设计)
  - [6.2 规则引擎](#62-规则引擎)
  - [6.3 Isolation Forest无监督检测](#63-isolation-forest无监督检测)
  - [6.4 检测服务统一入口](#64-检测服务统一入口)
- [第七章 LLM语义分析引擎](#第七章-llm语义分析引擎)
  - [7.1 LLM集成架构](#71-llm集成架构)
  - [7.2 Prompt工程设计](#72-prompt工程设计)
  - [7.3 Function Calling交互式分析](#73-function-calling交互式分析)
  - [7.4 双模式支持](#74-双模式支持)
- [第八章 实时采集与WebSocket推送](#第八章-实时采集与websocket推送)
  - [8.1 采集引擎设计](#81-采集引擎设计)
  - [8.2 WebSocket实时推送](#82-websocket实时推送)
  - [8.3 前端实时更新机制](#83-前端实时更新机制)
- [第九章 数据持久化层](#第九章-数据持久化层)
  - [9.1 数据库设计](#91-数据库设计)
  - [9.2 ORM模型定义](#92-orm模型定义)
  - [9.3 异步数据库操作](#93-异步数据库操作)
- [第十章 RESTful API设计](#第十章-restful-api设计)
  - [10.1 API总览](#101-api总览)
  - [10.2 流量管理API](#102-流量管理api)
  - [10.3 异常检测API](#103-异常检测api)
  - [10.4 LLM分析API](#104-llm分析api)
  - [10.5 系统管理API](#105-系统管理api)
- [第十一章 前端可视化系统](#第十一章-前端可视化系统)
  - [11.1 前端架构](#111-前端架构)
  - [11.2 流量监控面板](#112-流量监控面板)
  - [11.3 告警中心](#113-告警中心)
  - [11.4 AI交互分析](#114-ai交互分析)
- [第十二章 测试与质量保障](#第十二章-测试与质量保障)
  - [12.1 测试策略](#121-测试策略)
  - [12.2 单元测试](#122-单元测试)
  - [12.3 集成测试](#123-集成测试)
  - [12.4 测试结果](#124-测试结果)
- [第十三章 部署与运维](#第十三章-部署与运维)
  - [13.1 开发环境部署](#131-开发环境部署)
  - [13.2 真实车机部署](#132-真实车机部署)
  - [13.3 配置管理](#133-配置管理)
- [第十四章 总结与展望](#第十四章-总结与展望)
  - [14.1 工作总结](#141-工作总结)
  - [14.2 不足与改进方向](#142-不足与改进方向)
- [参考文献](#参考文献)
- [附录](#附录)

<div style="page-break-after: always;"></div>

## 第六章 两级异常检测引擎

### 6.1 检测架构设计

GatewayGuard的异常检测引擎采用两级架构，将规则引擎的快速筛查能力与Isolation Forest的无监督学习能力相结合，实现了对已知攻击模式和未知异常行为的全面覆盖。

> **[图片位置7]** 建议插入：两级检测架构流程图，展示报文从输入到规则检测、ML检测、告警输出的完整流程。

**两级检测架构：**

```
输入报文批次 (List[UnifiedPacket])
    │
    ▼
┌─────────────────────────────────────┐
│         AnomalyDetectorService      │
│                                     │
│  ┌─────────────────────────────┐    │
│  │   第一级：RuleBasedDetector  │    │
│  │                             │    │
│  │  ├── _check_frequency()     │    │  ← 频率异常检测（DoS）
│  │  ├── _check_unknown_id()    │    │  ← ID白名单检测（Fuzzy）
│  │  └── _check_payload()       │    │  ← 负载异常检测（Spoofing）
│  └─────────────────────────────┘    │
│                                     │
│  ┌─────────────────────────────┐    │
│  │ 第二级：IsolationForestDetector│  │
│  │                             │    │
│  │  ├── extract_features()     │    │  ← 5维特征提取
│  │  ├── fit()                  │    │  ← 在线训练
│  │  └── predict()              │    │  ← 异常预测
│  └─────────────────────────────┘    │
│                                     │
│  alerts.sort(confidence DESC)       │  ← 按置信度排序
└─────────────────────────────────────┘
    │
    ▼
List[AnomalyEvent]  ──→  数据库持久化 + WebSocket推送
```

**两级检测的互补关系：**

| 维度 | 规则引擎（第一级） | Isolation Forest（第二级） |
|------|-------------------|--------------------------|
| 检测速度 | 极快（O(n)遍历） | 较快（特征提取+模型推理） |
| 已知攻击 | 精确匹配 | 可能检出 |
| 未知攻击 | 无法检测 | 可发现偏离正常模式的异常 |
| 误报率 | 低（规则精确） | 中等（需调节contamination） |
| 可解释性 | 高（规则语义明确） | 低（异常分数） |
| 训练需求 | 无需训练 | 需要正常流量训练 |


### 6.2 规则引擎

RuleBasedDetector（`services/anomaly_detector.py`）实现了三类基于领域知识的检测规则，针对CAN总线最常见的三种攻击模式。

#### 6.2.1 频率异常检测

频率异常检测用于发现DoS攻击。其核心思想是：计算每个CAN ID在时间窗口内的报文频率，与所有ID的平均频率进行比较，超出阈值倍数则判定为异常。

**检测算法：**

```python
def _check_frequency(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
    time_span = packets[-1].timestamp - packets[0].timestamp
    id_counts = Counter(p.msg_id for p in packets if p.protocol == "CAN")
    avg_per_id_freq = sum(id_counts.values()) / len(id_counts) / time_span

    for msg_id, count in id_counts.items():
        freq = count / time_span
        if freq > avg_per_id_freq * self.freq_threshold:
            ratio = freq / (avg_per_id_freq * self.freq_threshold)
            # ratio > 3.0 → critical, > 1.5 → high, else → medium
```

**严重程度分级逻辑：**

| 频率超标比率 | 严重程度 | 典型场景 |
|------------|---------|---------|
| > 3.0x | critical | 高强度DoS洪泛 |
| > 1.5x | high | 中等强度DoS |
| > 1.0x | medium | 轻微频率异常 |

#### 6.2.2 ID白名单检测

ID白名单检测用于发现Fuzzy攻击。系统维护了12个合法CAN ID的白名单，任何不在白名单中的CAN ID都被视为可疑：

```python
VALID_CAN_IDS = {
    "0x0C0", "0x0C8", "0x130", "0x180", "0x1A0", "0x200",
    "0x260", "0x280", "0x320", "0x3E0", "0x7DF", "0x7E0",
}

def _check_unknown_id(self, packets):
    for p in packets:
        if p.protocol == "CAN" and p.msg_id not in self.VALID_CAN_IDS:
            # severity="high", confidence=0.8
```

该规则使用`seen_unknown`集合进行去重，避免同一未知ID在同一批次中产生重复告警。

#### 6.2.3 负载异常检测

负载异常检测用于发现Spoofing攻击。当CAN报文的负载全部由同一字节值填充（如全0xFF或全0x00）时，判定为负载异常：

```python
def _check_payload(self, packets):
    unique_bytes = set(payload_hex[i:i+2] for i in range(0, len(payload_hex), 2))
    if len(unique_bytes) == 1 and len(payload_hex) >= 8:
        byte_val = list(unique_bytes)[0]
        if byte_val in ("ff", "FF", "00"):
            severity = "critical"   # 全FF/全00 → critical
        else:
            severity = "low"        # 其他单字节填充 → low
```

**检测逻辑说明：**
- 仅对CAN协议报文进行检查
- 要求负载长度≥4字节（`len(payload_hex) >= 8`，因为每字节占2个十六进制字符）
- 全0xFF和全0x00被视为高危（常见的Spoofing特征），其他单字节填充为低危


### 6.3 Isolation Forest无监督检测

IsolationForestDetector（`services/anomaly_detector.py`）采用scikit-learn的Isolation Forest算法，通过学习正常流量的特征分布，自动发现偏离正常模式的异常报文。

#### 6.3.1 特征工程

检测器从每条UnifiedPacket中提取5维数值特征向量：

| 特征维度 | 提取方法 | 取值范围 | 检测意义 |
|---------|---------|---------|---------|
| msg_id_num | CAN ID转整数 / hash取模 | 0-4095 | 异常ID识别 |
| payload_len | payload_hex长度/2 | 0-128 | 异常包长检测 |
| payload_entropy | Shannon信息熵 | 0.0-8.0 | 负载随机性检测 |
| proto_num | 协议编码(CAN=0,ETH=1,V2X=2) | 0-3 | 协议类型特征 |
| domain_num | 功能域编码 | 0-5 | 功能域特征 |

**信息熵计算：**

```python
@staticmethod
def _byte_entropy(hex_str: str) -> float:
    byte_vals = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
    counts = Counter(byte_vals)
    total = len(byte_vals)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            entropy -= p * np.log2(p)
    return entropy
```

信息熵是衡量数据随机性的重要指标。正常CAN报文的负载通常具有特定的结构和模式，信息熵相对稳定；而Fuzzy攻击生成的随机负载信息熵较高，Spoofing攻击的全FF负载信息熵为0。

#### 6.3.2 模型训练与预测

**在线训练机制：**

系统采用在线训练策略，在采集引擎的`_persist_and_detect()`方法中自动完成模型训练：

```python
# 在 CollectorService._persist_and_detect() 中
if not self._detector.ml_detector.is_fitted:
    normal = [pk for pk in packets if not pk.metadata.get("attack")]
    if len(normal) > 20:
        self._detector.train(normal)
```

当ML模型尚未训练且正常报文数量超过20条时，自动触发训练。训练完成后，后续的检测批次将同时执行规则检测和ML检测。

**模型参数配置：**

| 参数 | 值 | 说明 |
|------|-----|------|
| n_estimators | 100 | 隔离树数量 |
| contamination | 0.05 | 预期异常比例（5%） |
| random_state | 42 | 随机种子（可复现） |

**异常分数与严重程度映射：**

| 异常分数(score) | 严重程度 | 说明 |
|----------------|---------|------|
| < -0.05 | critical | 严重偏离正常模式 |
| < -0.03 | high | 明显异常 |
| < -0.02 | medium | 轻度异常 |
| ≥ -0.02 | low | 边界异常 |


### 6.4 检测服务统一入口

AnomalyDetectorService作为两级检测的统一入口，协调规则引擎和ML模型的执行：

```python
class AnomalyDetectorService:
    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = IsolationForestDetector()

    def train(self, normal_packets: List[UnifiedPacket]):
        self.ml_detector.fit(normal_packets)

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        if settings.detector.rule_enabled:
            alerts.extend(self.rule_detector.check(packets))
        if settings.detector.ml_enabled and self.ml_detector.is_fitted:
            alerts.extend(self.ml_detector.predict(packets))
        alerts.sort(key=lambda a: a.confidence, reverse=True)
        return alerts
```

**关键设计决策：**

1. **可配置的检测级别**：通过`settings.detector.rule_enabled`和`settings.detector.ml_enabled`配置项，可以独立启用/禁用规则检测和ML检测
2. **置信度排序**：所有告警按置信度降序排列，确保最可信的告警优先展示
3. **渐进式ML训练**：ML模型在首次收集到足够正常流量后自动训练，无需人工干预

<div style="page-break-after: always;"></div>


## 第七章 LLM语义分析引擎

### 7.1 LLM集成架构

LLM语义分析引擎（`services/llm_engine.py`）是GatewayGuard系统的核心创新模块，负责对异常检测引擎产生的告警进行深度语义分析，自动生成攻击意图判断、影响评估和处置建议。

> **[图片位置8]** 建议插入：LLM集成架构图，展示OpenAI/Ollama双模式切换、Prompt模板、Function Calling的交互流程。

**LLM引擎架构：**

```
┌─────────────────────────────────────────────┐
│              LLMEngine                       │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │         _init_client()              │    │
│  │                                     │    │
│  │  provider == "openai"?              │    │
│  │    ├── Yes → AsyncOpenAI(api.openai)│    │
│  │    └── No  → AsyncOpenAI(localhost) │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│  │ analyze  │ │ generate │ │  chat()  │    │
│  │_anomaly()│ │_report() │ │+tools   │    │
│  └──────────┘ └──────────┘ └──────────┘    │
│       │            │            │           │
│       ▼            ▼            ▼           │
│  ┌─────────────────────────────────────┐    │
│  │         _call_llm(messages)         │    │
│  │  → client.chat.completions.create() │    │
│  └─────────────────────────────────────┘    │
│       │                                     │
│       ▼                                     │
│  ┌─────────────────────────────────────┐    │
│  │     _parse_json_response()          │    │
│  │  → 去除markdown包裹 → json.loads()  │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

**客户端初始化逻辑：**

```python
class LLMEngine:
    def _init_client(self):
        cfg = settings.llm
        if cfg.provider == "ollama":
            self.client = AsyncOpenAI(
                base_url=f"{cfg.ollama_base_url}/v1",
                api_key="ollama",  # Ollama不需要真实API Key
            )
            self.model = cfg.ollama_model
        else:
            self.client = AsyncOpenAI(
                base_url=cfg.openai_base_url,
                api_key=cfg.openai_api_key,
            )
            self.model = cfg.openai_model
```

关键设计：利用OpenAI Python SDK的`base_url`参数，将Ollama的兼容API端点（`localhost:11434/v1`）统一到同一个AsyncOpenAI客户端接口下，实现了零代码切换。


### 7.2 Prompt工程设计

Prompt模板（`utils/prompt_templates.py`）是LLM分析质量的关键。系统设计了三类Prompt模板，分别用于系统角色设定、异常事件分析和预警报告生成。

#### 7.2.1 系统Prompt

```
你是车载网络安全分析专家，精通CAN总线、车载以太网、V2X协议及常见攻击手法。
请用中文简洁回答，直接输出JSON，不要用markdown代码块包裹。
```

系统Prompt简洁明确，设定了三个关键约束：
1. **角色定位**：车载网络安全专家，确保回答的专业性
2. **语言要求**：中文输出，符合目标用户群体
3. **格式约束**：直接输出JSON，便于程序解析

#### 7.2.2 异常分析Prompt

异常分析Prompt采用结构化模板，将异常事件的关键字段注入到提示中：

```
分析以下网关异常事件：

- 协议: {protocol} | 类型: {anomaly_type} | 严重程度: {severity}
- 置信度: {confidence} | 源: {source_node} | 目标: {target_node}
- 检测方法: {detection_method}
- 描述: {description}

直接输出JSON：
{"attack_type":"攻击类型","attack_method":"手法(50字内)",
 "root_cause":"根因(50字内)","affected_scope":["受影响范围"],
 "attack_intent":"意图(30字内)","risk_level":"high/medium/low",
 "recommendations":["建议1","建议2"],"summary":"一句话总结"}
```

**Prompt设计要点：**
- 使用字数限制（如"50字内"）控制输出长度，避免LLM生成冗长内容
- 提供JSON Schema示例，引导LLM输出结构化数据
- 包含`risk_level`枚举值约束，确保输出可被程序处理

#### 7.2.3 预警报告Prompt

预警报告Prompt接收多个异常事件的JSON数组，要求LLM生成包含时间线、攻击链分析和处置建议的综合报告：

```
基于以下异常事件生成预警报告：
{events_json}

直接输出JSON：
{"title":"报告标题","summary":"摘要(100字内)",
 "timeline":["关键事件"],"attack_chain":"攻击链分析(100字内)",
 "impact_assessment":"影响评估(80字内)",
 "risk_level":"critical/high/medium/low",
 "recommendations":["建议1","建议2","建议3"],
 "conclusion":"结论(50字内)"}
```

#### 7.2.4 JSON响应解析

由于LLM可能在JSON外层包裹markdown代码块（如\`\`\`json ... \`\`\`），系统实现了自动去除包裹的解析逻辑：

```python
@staticmethod
def _parse_json_response(content: str) -> dict:
    text = content.strip()
    m = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if m:
        text = m.group(1).strip()
    return json.loads(text)
```


### 7.3 Function Calling交互式分析

Function Calling是GatewayGuard系统的重要创新点，使LLM能够在对话过程中动态查询后端数据，实现真正的交互式安全分析。

#### 7.3.1 工具定义

系统定义了两个Function Calling工具（`utils/tools.py`）：

| 工具名称 | 功能 | 参数 |
|---------|------|------|
| query_traffic_stats | 查询流量统计信息 | protocol(CAN/ETH/V2X/ALL), minutes |
| get_anomaly_events | 获取异常事件列表 | severity(critical/high/medium/low/all), limit |

**工具定义示例：**

```python
CHAT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_traffic_stats",
            "description": "查询指定时间范围和协议的流量统计信息",
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "enum": ["CAN", "ETH", "V2X", "ALL"],
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "查询最近N分钟的数据",
                    },
                },
                "required": ["protocol"],
            },
        },
    },
    # ... get_anomaly_events 工具定义
]
```

#### 7.3.2 交互流程

Function Calling的交互流程如下：

```
用户: "最近5分钟CAN总线有什么异常？"
    │
    ▼
LLMEngine.chat(messages, use_tools=True)
    │
    ▼
LLM决定调用工具: get_anomaly_events(severity="all", limit=10)
    │
    ▼
后端执行工具调用，返回异常事件数据
    │
    ▼
LLM基于工具返回的数据生成自然语言回答
    │
    ▼
用户: "0x000这个ID是什么攻击？"
    │
    ▼
LLM调用: query_traffic_stats(protocol="CAN", minutes=5)
    │
    ▼
LLM综合分析后回答
```

#### 7.3.3 chat()方法实现

```python
async def chat(self, messages: List[dict], use_tools: bool = True) -> dict:
    full_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        *messages,
    ]
    kwargs = {}
    if use_tools:
        kwargs["tools"] = CHAT_TOOLS

    resp = await self._call_llm(full_messages, **kwargs)
    choice = resp.choices[0]

    result = {
        "content": choice.message.content or "",
        "tool_calls": None,
        "usage": {
            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,
        },
    }
    if choice.message.tool_calls:
        result["tool_calls"] = [
            {"name": tc.function.name,
             "arguments": json.loads(tc.function.arguments)}
            for tc in choice.message.tool_calls
        ]
    return result
```


### 7.4 双模式支持

系统同时支持OpenAI云端API和Ollama本地部署两种LLM后端，通过配置文件一键切换。

| 特性 | OpenAI模式 | Ollama模式 |
|------|-----------|-----------|
| 部署方式 | 云端API | 本地部署 |
| 模型 | gpt-4o-mini / gpt-4o | qwen2.5:7b等 |
| 分析质量 | 高 | 中等（取决于模型） |
| 响应速度 | 依赖网络 | 本地推理，低延迟 |
| 数据隐私 | 数据上传云端 | 数据不出本地 |
| 成本 | 按Token计费 | 仅硬件成本 |
| Function Calling | 完整支持 | 部分模型支持 |

**配置切换示例（config.yaml）：**

```yaml
llm:
  # 切换为 "openai" 或 "ollama"
  provider: "openai"

  # OpenAI配置
  openai_api_key: "${OPENAI_API_KEY}"
  openai_base_url: "https://api.openai.com/v1"
  openai_model: "gpt-4o-mini"

  # Ollama配置
  ollama_base_url: "http://localhost:11434"
  ollama_model: "qwen2.5:7b"

  # 通用参数
  temperature: 0.3
  max_tokens: 2000
```

**安全性考虑：**
- OpenAI API Key通过环境变量`${OPENAI_API_KEY}`注入，不硬编码在配置文件中
- Ollama模式下数据完全在本地处理，适合对数据隐私要求严格的车企场景
- `temperature`设为0.3，降低输出随机性，提高分析结果的一致性

<div style="page-break-after: always;"></div>


## 第八章 实时采集与WebSocket推送

### 8.1 采集引擎设计

CollectorService（`services/collector.py`）是系统的实时数据采集核心，采用异步协程架构，实现了从数据源读取、缓冲、持久化到异常检测的完整流水线。

> **[图片位置9]** 建议插入：采集引擎状态机图，展示Collector的启动、运行、停止状态转换及各状态下的行为。

#### 8.1.1 采集引擎架构

```python
class CollectorService:
    def __init__(self):
        self._sources: List[DataSource] = []      # 数据源列表
        self._task: Optional[asyncio.Task] = None  # 采集协程任务
        self._detector = AnomalyDetectorService()  # 异常检测器
        self._running = False                       # 运行状态标志
        self._pending: deque = deque(maxlen=10000) # 报文缓冲区
```

**核心组件说明：**

| 组件 | 类型 | 作用 |
|------|------|------|
| _sources | List[DataSource] | 支持多数据源并行采集 |
| _task | asyncio.Task | 后台采集协程，通过cancel()停止 |
| _detector | AnomalyDetectorService | 两级异常检测引擎 |
| _pending | deque(maxlen=10000) | 有界缓冲区，防止内存溢出 |
| _stats | dict | 采集统计信息（总量、异常数、启动时间） |


#### 8.1.2 采集主循环

采集主循环`_collect_loop()`以配置的轮询间隔（默认10ms）持续从所有数据源读取报文：

```python
async def _collect_loop(self) -> None:
    while self._running:
        for src in self._sources:
            batch = await src.read(max_count=self._detect_batch)
            if batch:
                self._pending.extend(batch)
                self._stats["total_collected"] += len(batch)

        # 缓冲区达到批次阈值时触发异步检测
        if self._auto_detect and len(self._pending) >= self._detect_batch:
            asyncio.create_task(self._persist_and_detect())

        # 节流广播统计信息（最多1次/秒）
        await ws_manager.broadcast_throttled({
            "type": "stats_update",
            "data": self.stats,
        }, min_interval=1.0)

        await asyncio.sleep(self._interval)
```

**关键设计决策：**

1. **非阻塞检测**：使用`asyncio.create_task()`将持久化和检测操作放入独立协程，不阻塞采集主循环
2. **批量触发**：当缓冲区积累到`detect_batch_size`（默认200条）时才触发检测，平衡实时性和效率
3. **节流广播**：统计信息广播使用`broadcast_throttled()`限制为最多1次/秒，避免WebSocket消息风暴
4. **优雅停止**：通过`CancelledError`异常捕获实现协程的优雅退出

#### 8.1.3 持久化与检测流水线

`_persist_and_detect()`方法实现了存库→训练→检测→推送的完整流水线：

```
从缓冲区取出 detect_batch_size 条报文
    │
    ├──▶ PacketORM 批量写入 SQLite
    │
    ├──▶ ML模型未训练？ → 用正常报文自动训练
    │
    ├──▶ AnomalyDetectorService.detect()
    │       ├── 规则检测
    │       └── ML检测
    │
    ├──▶ AnomalyEventORM 写入数据库
    │
    └──▶ ws_manager.broadcast() → 实时推送告警
```

#### 8.1.4 多数据源支持

采集引擎支持`multi`模式，同时从多个数据源采集：

```python
async def start(self, mode: Optional[str] = None) -> dict:
    mode = mode or settings.sources.mode
    if mode == "multi":
        for m in ("can", "ethernet"):
            try:
                src = _create_source(m)
                self._sources.append(src)
            except Exception as e:
                logger.warning("Skip source %s: %s", m, e)
    else:
        self._sources = [_create_source(mode)]
```


### 8.2 WebSocket实时推送

WebSocket推送机制是GatewayGuard实现亚秒级告警响应的关键技术。系统采用ConnectionManager单例模式管理所有WebSocket连接，提供广播和点对点消息能力。

#### 8.2.1 ConnectionManager设计

```python
class ConnectionManager:
    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._last_broadcast: float = 0.0
        self._min_interval: float = 0.1  # 最小广播间隔100ms

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        payload = json.dumps(message, ensure_ascii=False, default=str)
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)
```

**关键设计特性：**

| 特性 | 实现方式 | 作用 |
|------|---------|------|
| 连接管理 | Set集合存储 | O(1)添加/删除 |
| 断线清理 | 广播时自动检测dead连接 | 防止连接泄漏 |
| 节流广播 | broadcast_throttled() | 限制最小间隔100ms |
| 点对点消息 | send_personal() | 连接初始化时推送状态快照 |

#### 8.2.2 WebSocket端点

```python
@router.websocket("/ws/realtime")
async def realtime_ws(ws: WebSocket):
    await ws_manager.connect(ws)

    # 连接后立即推送当前状态快照
    await ws_manager.send_personal(ws, {
        "type": "stats_update",
        "data": collector.stats,
    })

    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            if msg.get("type") == "ping":
                await ws_manager.send_personal(ws, {"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(ws)
```

**消息类型定义：**

| 消息类型 | 方向 | 数据内容 |
|---------|------|---------|
| stats_update | Server→Client | 采集统计（总量、异常数、运行状态） |
| alerts | Server→Client | 异常告警列表（类型、严重程度、描述） |
| ping/pong | 双向 | 心跳保活 |


### 8.3 前端实时更新机制

前端通过封装的WebSocket客户端（`frontend/src/api/ws.js`）与后端建立持久连接，实现实时数据更新。

#### 8.3.1 WebSocket客户端封装

前端WebSocket客户端实现了以下关键特性：

- **自动重连**：连接断开后采用指数退避策略自动重连（1s → 2s → 4s → ... → 30s）
- **心跳保活**：每30秒发送ping消息，检测连接存活状态
- **事件分发**：根据消息类型（stats_update/alerts）分发到对应的处理函数
- **状态管理**：维护连接状态，供UI组件展示连接指示器

#### 8.3.2 Dashboard实时更新

Dashboard.vue组件通过WebSocket接收两类实时数据：

1. **stats_update**：更新采集状态面板（总采集量、异常数、运行时间、数据源模式）
2. **alerts**：追加到实时告警时间线，高危告警（critical/high）触发浏览器桌面通知

```
WebSocket消息 → onMessage回调
    │
    ├── type: "stats_update"
    │   └── 更新统计面板数据（响应式绑定自动刷新UI）
    │
    └── type: "alerts"
        ├── 追加到告警列表（最新在前）
        ├── 更新告警计数徽标
        └── severity ∈ {critical, high}
            └── Notification.requestPermission() → 桌面通知
```

<div style="page-break-after: always;"></div>


## 第九章 数据持久化层

### 9.1 数据库设计

GatewayGuard采用SQLite作为持久化存储，通过SQLAlchemy 2.0的异步引擎实现非阻塞数据库操作。SQLite的零配置特性使系统能够在嵌入式车载环境中即开即用。

> **[图片位置10]** 建议插入：数据库ER图，展示packets、anomaly_events、analysis_reports、chat_history四张表的字段和关系。

**数据库表结构总览：**

| 表名 | 用途 | 主要字段 | 索引 |
|------|------|---------|------|
| packets | 流量报文存储 | timestamp, protocol, source, msg_id, payload | timestamp, protocol |
| anomaly_events | 异常事件记录 | timestamp, anomaly_type, severity, confidence | timestamp, severity |
| analysis_reports | LLM分析报告 | event_id, report_json, model_used | event_id |
| chat_history | 对话历史 | session_id, role, content | session_id |


### 9.2 ORM模型定义

#### 9.2.1 PacketORM

```python
class PacketORM(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, index=True)
    source = Column(String(64))
    destination = Column(String(64))
    msg_id = Column(String(32))
    payload = Column(LargeBinary)
    payload_decoded = Column(Text)
    domain = Column(String(32))
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
```

#### 9.2.2 AnomalyEventORM

```python
class AnomalyEventORM(Base):
    __tablename__ = "anomaly_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    anomaly_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(Float)
    protocol = Column(String(16))
    source_node = Column(String(64))
    target_node = Column(String(64))
    description = Column(Text)
    detection_method = Column(String(32))
    status = Column(String(16), default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
```

#### 9.2.3 AnalysisReportORM与ChatHistoryORM

```python
class AnalysisReportORM(Base):
    __tablename__ = "analysis_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, index=True)
    report_json = Column(Text)
    model_used = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow)

class ChatHistoryORM(Base):
    __tablename__ = "chat_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), index=True)
    role = Column(String(16))
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
```


### 9.3 异步数据库操作

#### 9.3.1 异步引擎初始化

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

engine = create_async_engine(settings.db_url, echo=settings.debug)
async_session = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)
```

**关键配置说明：**
- `create_async_engine`：使用aiosqlite驱动，实现SQLite的异步I/O
- `expire_on_commit=False`：提交后不自动过期对象属性，避免后续访问触发额外查询
- `echo=settings.debug`：调试模式下输出SQL语句，便于开发调试

#### 9.3.2 数据库初始化

```python
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
```

`init_db()`在FastAPI应用启动时调用（通过lifespan事件），自动创建所有表结构。使用`run_sync()`将同步的DDL操作包装为异步执行。

#### 9.3.3 会话依赖注入

```python
async def get_db():
    async with async_session() as session:
        yield session
```

`get_db()`作为FastAPI的Depends依赖，为每个请求提供独立的数据库会话，请求结束后自动关闭。

<div style="page-break-after: always;"></div>


## 第十章 RESTful API设计

### 10.1 API总览

GatewayGuard后端基于FastAPI框架，提供四组RESTful API和一个WebSocket端点。所有API均遵循统一的响应格式，支持自动生成OpenAPI文档。

**API分组总览：**

| 分组 | 路径前缀 | 功能 | 端点数 |
|------|---------|------|--------|
| 流量管理 | /api/traffic | 流量采集、模拟、查询 | 7 |
| 异常检测 | /api/anomaly | 异常事件管理与检测 | 3 |
| LLM分析 | /api/llm | AI语义分析与对话 | 3 |
| 系统管理 | /api/system | 系统状态与数据清理 | 4 |
| WebSocket | /ws | 实时数据推送 | 1 |


### 10.2 流量管理API

#### GET /api/traffic/stats

获取流量统计信息，包括总报文数、分协议计数和采集状态。

**响应示例：**
```json
{
  "total_packets": 15000,
  "by_protocol": {"CAN": 10000, "ETH": 3500, "V2X": 1500},
  "collection_status": "running",
  "anomaly_count": 42
}
```

#### GET /api/traffic/packets

分页查询流量记录，支持按协议和时间范围过滤。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| protocol | string | 否 | 协议过滤(CAN/ETH/V2X) |
| limit | int | 否 | 每页数量，默认50 |
| offset | int | 否 | 偏移量，默认0 |

#### POST /api/traffic/simulate

触发流量模拟，生成指定场景的模拟流量并存入数据库。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| scenario | string | 是 | 场景(normal/dos/fuzzy/spoofing/mixed) |
| count | int | 否 | 生成数量，默认100 |

#### POST /api/traffic/collect/start

启动实时采集引擎。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| mode | string | 否 | 数据源模式(simulator/can/ethernet/pcap/multi) |

#### POST /api/traffic/collect/stop

停止实时采集引擎，返回采集统计摘要。

#### GET /api/traffic/collect/status

查询采集引擎当前状态（运行中/已停止、已采集数量、异常数量等）。

#### POST /api/traffic/import

导入PCAP/BLF离线抓包文件。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| file | UploadFile | 是 | PCAP格式抓包文件 |


### 10.3 异常检测API

#### GET /api/anomaly/events

分页查询异常事件列表，支持按严重程度过滤。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| severity | string | 否 | 严重程度过滤(critical/high/medium/low) |
| limit | int | 否 | 每页数量，默认50 |
| offset | int | 否 | 偏移量，默认0 |

**响应示例：**
```json
{
  "events": [
    {
      "id": 1,
      "timestamp": 1706000000.0,
      "anomaly_type": "frequency_anomaly",
      "severity": "critical",
      "confidence": 0.95,
      "protocol": "CAN",
      "source_node": "0x000",
      "description": "报文 0x000 频率异常: 5000.0 pkt/s",
      "detection_method": "rule_frequency",
      "status": "open"
    }
  ],
  "total": 42
}
```

#### GET /api/anomaly/events/{id}

获取单个异常事件的详细信息。

#### POST /api/anomaly/detect

手动触发一次异常检测，对数据库中最近的报文执行两级检测。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| limit | int | 否 | 检测报文数量，默认200 |


### 10.4 LLM分析API

#### POST /api/llm/analyze

对指定异常事件进行LLM语义分析，返回结构化分析报告。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| event_id | int | 是 | 异常事件ID |

**响应示例：**
```json
{
  "attack_type": "DoS攻击",
  "attack_method": "使用最高优先级CAN ID 0x000以5000pkt/s频率洪泛总线",
  "root_cause": "攻击者通过物理接入或远程漏洞向CAN总线注入高频报文",
  "affected_scope": ["CAN总线通信", "动力域ECU", "底盘域ECU"],
  "attack_intent": "瘫痪车载CAN总线通信",
  "risk_level": "high",
  "recommendations": [
    "立即启用CAN ID过滤规则，阻断0x000报文",
    "检查OBD-II接口和网关物理安全",
    "部署基于优先级的总线仲裁保护"
  ],
  "summary": "检测到针对CAN总线的DoS洪泛攻击，攻击者使用最高优先级ID抢占总线带宽"
}
```

#### POST /api/llm/report

基于多个异常事件生成综合预警报告。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| event_ids | List[int] | 否 | 指定事件ID列表，为空则使用最近事件 |
| limit | int | 否 | 最近事件数量，默认10 |

#### POST /api/llm/chat

交互式安全分析对话，支持Function Calling。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| messages | List[dict] | 是 | 对话消息列表 |
| use_tools | bool | 否 | 是否启用Function Calling，默认true |


### 10.5 系统管理API

#### GET /api/system/status

获取系统运行状态，包括数据库统计、采集状态和LLM配置信息。

**响应示例：**
```json
{
  "status": "running",
  "database": {
    "total_packets": 15000,
    "total_anomalies": 42,
    "total_reports": 5
  },
  "collector": {
    "running": true,
    "source_mode": "simulator",
    "total_collected": 8000
  },
  "llm": {
    "provider": "openai",
    "model": "gpt-4o-mini"
  }
}
```

#### DELETE /api/system/clear-data

清除所有数据（报文、异常事件、分析报告、对话历史）。

#### DELETE /api/system/clear-packets

仅清除流量报文数据。

#### DELETE /api/system/clear-anomalies

仅清除异常事件数据。

<div style="page-break-after: always;"></div>


## 第十一章 前端可视化系统

### 11.1 前端架构

GatewayGuard前端采用Vue 3 + Element Plus + ECharts技术栈，通过Vite构建工具实现极速开发体验。

> **[图片位置11]** 建议插入：前端页面截图，展示Dashboard主界面的流量统计面板、实时告警时间线和流量记录表格。

**前端目录结构：**

```
frontend/src/
├── main.js              # 应用入口
├── App.vue              # 根组件（路由视图容器）
├── router/
│   └── index.js         # Vue Router路由配置
├── api/
│   ├── index.js         # Axios HTTP客户端封装
│   └── ws.js            # WebSocket客户端封装
├── views/
│   ├── Dashboard.vue    # 流量监控主面板
│   ├── Alerts.vue       # 告警中心
│   └── AIAnalysis.vue   # AI交互分析
└── assets/              # 静态资源
```

**技术栈说明：**

| 技术 | 版本 | 用途 |
|------|------|------|
| Vue 3 | 3.3+ | 响应式UI框架，Composition API |
| Element Plus | 2.4+ | 企业级UI组件库 |
| ECharts | 5.4+ | 数据可视化图表 |
| Vue Router | 4.x | 单页应用路由 |
| Axios | 1.6+ | HTTP请求客户端 |
| Vite | 5.0+ | 构建工具，极速HMR |


### 11.2 流量监控面板

Dashboard.vue是系统的核心页面，集成了数据源控制、实时统计、流量记录和告警时间线四大功能区域。

#### 11.2.1 数据源控制区

提供数据源模式选择和采集控制：

- **模式选择**：下拉框选择数据源（模拟器/CAN/以太网/PCAP/多源混合）
- **启动/停止**：一键启停采集引擎
- **模拟触发**：选择攻击场景（正常/DoS/Fuzzy/Spoofing/混合）生成模拟流量
- **手动检测**：对已有数据执行一次性异常检测

#### 11.2.2 实时统计面板

通过WebSocket接收`stats_update`消息，实时展示：

| 统计项 | 展示方式 | 数据来源 |
|--------|---------|---------|
| 总采集量 | 数字卡片 | stats.total_collected |
| 异常数量 | 数字卡片（红色高亮） | stats.total_anomalies |
| 运行时间 | 计时器 | stats.started_at |
| 数据源模式 | 标签 | stats.source_mode |
| 协议分布 | ECharts饼图 | /api/traffic/stats |

#### 11.2.3 流量记录表格

使用Element Plus的`el-table`组件展示最新流量记录：

| 列名 | 字段 | 说明 |
|------|------|------|
| 时间 | timestamp | 格式化为HH:mm:ss.SSS |
| 协议 | protocol | CAN/ETH/V2X标签 |
| 源 | source | ECU名称或节点ID |
| 目标 | destination | 目标节点 |
| 消息ID | msg_id | CAN ID或ServiceID.MethodID |
| 负载 | payload_hex | 十六进制字符串（截断显示） |
| 功能域 | domain | 彩色标签 |


### 11.3 告警中心

Alerts.vue页面提供异常事件的集中管理和查看功能。

#### 11.3.1 告警列表

- **分页展示**：支持按页浏览异常事件，每页50条
- **严重程度过滤**：下拉框筛选critical/high/medium/low级别
- **颜色编码**：critical红色、high橙色、medium黄色、low灰色
- **详情展开**：点击行展开异常事件的完整描述和检测方法

#### 11.3.2 告警详情

每条告警展示以下信息：

| 字段 | 说明 |
|------|------|
| 异常类型 | frequency_anomaly / unknown_can_id / payload_anomaly / ml_anomaly |
| 严重程度 | critical / high / medium / low |
| 置信度 | 0.0-1.0 的浮点数 |
| 协议 | CAN / ETH / V2X |
| 源节点 | 产生异常的ECU或节点 |
| 检测方法 | rule_frequency / rule_id_whitelist / rule_payload / isolation_forest |
| 描述 | 人类可读的异常描述 |
| 状态 | open / investigating / resolved |

#### 11.3.3 一键AI分析

告警列表中每条记录提供"AI分析"按钮，点击后调用`/api/llm/analyze`接口，将LLM生成的语义分析报告以对话框形式展示。


### 11.4 AI交互分析

AIAnalysis.vue页面提供基于LLM的交互式安全分析功能，支持自然语言对话和预警报告生成。

#### 11.4.1 对话式分析

- **聊天界面**：类似即时通讯的对话气泡布局
- **消息输入**：支持多行文本输入，Enter发送
- **流式展示**：LLM回复逐步渲染，提升用户体验
- **历史记录**：对话历史持久化到数据库，支持会话恢复

#### 11.4.2 预警报告

- **一键生成**：点击"生成预警报告"按钮，系统自动汇总最近异常事件
- **结构化展示**：报告以卡片形式展示标题、摘要、时间线、攻击链分析、影响评估和处置建议
- **风险等级**：报告顶部以醒目颜色标注整体风险等级

#### 11.4.3 Function Calling可视化

当LLM在对话中调用后端工具时，前端展示工具调用过程：

```
用户: "最近有什么高危告警？"
    │
    ▼
[工具调用] get_anomaly_events(severity="high", limit=5)
    │
    ▼
[工具结果] 返回5条高危异常事件
    │
    ▼
AI: "最近检测到5条高危告警，主要包括..."
```

<div style="page-break-after: always;"></div>


## 第十二章 测试与质量保障

### 12.1 测试策略

GatewayGuard采用分层测试策略，覆盖单元测试、集成测试和端到端测试三个层次，确保系统各模块的正确性和整体协作的可靠性。

> **[图片位置12]** 建议插入：测试金字塔图，展示单元测试（底层，数量最多）、集成测试（中层）、E2E测试（顶层）的分层结构。

**测试框架与工具：**

| 工具 | 用途 |
|------|------|
| pytest | Python测试框架 |
| pytest-asyncio | 异步测试支持 |
| httpx | FastAPI异步测试客户端 |
| unittest.mock | Mock对象和补丁 |

**测试目录结构：**

```
backend/tests/
├── test_anomaly_detector.py   # 异常检测引擎测试
├── test_traffic_parser.py     # 流量解析服务测试
├── test_simulators.py         # 模拟器测试
├── test_ws.py                 # WebSocket推送测试
├── test_api_traffic.py        # 流量API集成测试
├── test_api_anomaly.py        # 异常检测API集成测试
└── conftest.py                # 测试夹具（fixtures）
```


### 12.2 单元测试

#### 12.2.1 异常检测引擎测试

针对RuleBasedDetector和IsolationForestDetector的核心检测逻辑编写了全面的单元测试：

```python
class TestRuleBasedDetector:
    def test_frequency_anomaly_detection(self):
        """测试DoS攻击的频率异常检测"""
        # 生成高频报文（同一ID在短时间内大量出现）
        packets = generate_dos_attack(count=500)
        detector = RuleBasedDetector()
        alerts = detector.check(packets)
        assert len(alerts) > 0
        assert any(a.anomaly_type == "frequency_anomaly" for a in alerts)

    def test_unknown_id_detection(self):
        """测试Fuzzy攻击的未知ID检测"""
        packets = generate_fuzzy_attack(count=100)
        alerts = detector.check(packets)
        assert any(a.anomaly_type == "unknown_can_id" for a in alerts)

    def test_payload_anomaly_detection(self):
        """测试Spoofing攻击的负载异常检测"""
        packets = generate_spoofing_attack(count=50)
        alerts = detector.check(packets)
        assert any(a.anomaly_type == "payload_anomaly" for a in alerts)

    def test_normal_traffic_no_alerts(self):
        """测试正常流量不产生误报"""
        packets = generate_normal_can(count=200)
        alerts = detector.check(packets)
        assert len(alerts) == 0
```

#### 12.2.2 Isolation Forest测试

```python
class TestIsolationForestDetector:
    def test_feature_extraction(self):
        """测试5维特征提取的正确性"""
        packets = generate_normal_can(count=10)
        features = detector.extract_features(packets)
        assert features.shape == (10, 5)

    def test_byte_entropy(self):
        """测试信息熵计算"""
        assert detector._byte_entropy("FFFFFFFF") == 0.0  # 全FF熵为0
        assert detector._byte_entropy("") == 0.0           # 空串熵为0
        assert detector._byte_entropy("0123456789ABCDEF") > 0  # 随机数据熵>0

    def test_train_and_predict(self):
        """测试训练后能检测异常"""
        normal = generate_normal_can(count=500)
        detector.fit(normal)
        attack = generate_dos_attack(count=100)
        alerts = detector.predict(attack)
        assert len(alerts) > 0
```


### 12.3 集成测试

#### 12.3.1 WebSocket推送测试

WebSocket测试验证了实时推送机制的正确性：

```python
class TestWebSocket:
    async def test_connect_and_receive_snapshot(self):
        """测试连接后立即收到状态快照"""
        async with client.websocket_connect("/ws/realtime") as ws:
            data = await ws.receive_json()
            assert data["type"] == "stats_update"

    async def test_broadcast_alerts(self):
        """测试告警广播到所有连接"""
        async with client.websocket_connect("/ws/realtime") as ws1:
            async with client.websocket_connect("/ws/realtime") as ws2:
                await ws_manager.broadcast({"type": "alerts", "data": [...]})
                msg1 = await ws1.receive_json()
                msg2 = await ws2.receive_json()
                assert msg1["type"] == "alerts"
                assert msg2["type"] == "alerts"

    async def test_ping_pong(self):
        """测试心跳保活机制"""
        async with client.websocket_connect("/ws/realtime") as ws:
            await ws.send_json({"type": "ping"})
            resp = await ws.receive_json()
            assert resp["type"] == "pong"
```

#### 12.3.2 API集成测试

API集成测试使用httpx的AsyncClient对FastAPI应用进行端到端请求测试：

```python
class TestTrafficAPI:
    async def test_simulate_and_query(self):
        """测试模拟流量生成并查询"""
        # 生成模拟流量
        resp = await client.post("/api/traffic/simulate",
                                 json={"scenario": "normal", "count": 50})
        assert resp.status_code == 200

        # 查询流量记录
        resp = await client.get("/api/traffic/packets?limit=10")
        assert resp.status_code == 200
        assert len(resp.json()["packets"]) <= 10

    async def test_detect_anomalies(self):
        """测试异常检测API"""
        # 先生成攻击流量
        await client.post("/api/traffic/simulate",
                          json={"scenario": "dos", "count": 200})
        # 触发检测
        resp = await client.post("/api/anomaly/detect")
        assert resp.status_code == 200
        assert resp.json()["anomaly_count"] > 0
```
