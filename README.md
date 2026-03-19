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

在智能网联汽车中，车载网关既是 CAN、车载以太网与 V2X 等异构协议的汇聚点，也是攻击从外部入口扩散到关键功能域的关键通道。围绕这一核心位置，GatewayGuard 构建了一个集异常检测、事件聚合与大语言模型（LLM）语义分析于一体的网关安全预警平台。

系统采用 **CAN-first 的 Profile-First 检测架构**：当前异常检测主路径聚焦 CAN/CAN-FD 的 ID 行为、时序、载荷、序列与轻量语义一致性检测，车载以太网与 V2X 已统一接入采集、存储、可视化与 LLM 上下文分析链路，并通过 LLM 实现异常事件的自动化语义解析与交互式安全问答。

---

## 目录

- [研究主线](#研究主线)
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

随着智能网联汽车（Connected and Autonomous Vehicles, CAV）技术的快速发展，车载网关已从传统的协议转换设备演变为承载 CAN 总线、车载以太网（Automotive Ethernet）、V2X（Vehicle-to-Everything）等异构协议的核心网络节点 [1][2]。在这一场景下，攻击面不再局限于单一 ECU 或单一总线，而是表现为“远程入口 -> 网关横向移动 -> 关键域注入/重放/语义篡改”的链式风险 [3-5]。因此，网关侧 IDS 的核心问题不只是“能否报出异常”，而是“能否在资源受限、标签稀缺、协议异构的约束下稳定发现异常，并给出可操作的解释”。

### 1. 现有工作的典型路线与局限

现有车载 IDS 大致可以归纳为四条路线：

| 路线 | 代表思想 | 优势 | 局限 |
|------|----------|------|------|
| 规则/白名单/规范方法 | 基于 CAN ID 白名单、DLC 约束、固定阈值、有限状态规则 | 实时性高、实现简单 | 对零日攻击、合法帧内语义篡改和跨车型迁移不够友好 |
| 单视角统计方法 | 仅看频率、仅看时间间隔、仅看熵或 ID 序列 | 可解释、部署轻量 | 容易被“合法 ID + 合法节拍 + 异常载荷”类攻击绕过 |
| 监督/深度学习方法 | CNN/LSTM/AE/GNN/Transformer 等 | 建模复杂模式能力强 | 往往依赖标注数据、DBC/信号逆向、较强算力或较高迁移成本 |
| 多协议孤岛式检测 | CAN、ETH、V2X 分别建模 | 每个协议内可以单独优化 | 难以在网关侧形成统一事件视图和统一解释接口 |

进一步看，现有工作在车载网关场景下通常存在五类共性问题：

- **异常检测与异常解释脱节**：多数 IDS 只能输出“某条报文异常/某个窗口越界”，很难进一步说明攻击类型、根因、影响范围与处置建议。
- **合法帧攻击识别困难**：合法 ID、合法 DLC、近似合法节拍下的语义篡改、重放与状态伪造，常常绕过单一视角检测器。
- **对标签和先验依赖偏重**：高级深度学习方法常要求高质量标注、CAN DBC 或信号逆向，增加了车型迁移与工程落地成本。
- **多协议场景缺乏统一分析接口**：即便底层完成了 ETH/V2X 采集，告警模型和研判流程仍常停留在单协议层面。
- **专家知识难形成闭环**：检测规则、上下文判断和处置经验分散在人工经验中，难以沉淀为“检测 -> 解释 -> 追问 -> 报告”的完整流程。

### 2. 研究思路与技术路线

针对上述问题，GatewayGuard 采用 **Profile-First + Tool-Augmented LLM** 的分层技术路线，形成 **MVPF-SR（Multi-View Profile-First Security Reasoning）** 框架。

形式化地，设网关侧观测到的异构报文流为

```text
X = {p_t}_{t=1}^T,  p_t = (tau_t, proto_t, src_t, dst_t, id_t, x_t, dom_t)
```

其中 `tau_t` 为时间戳，`proto_t` 为协议类型，`id_t` 为报文标识，`x_t` 为原始载荷，`dom_t` 为功能域。系统首先在正常样本子集 `X_train` 上学习每个 `id_t` 对应的正常性画像 `P_i`，随后在在线阶段对待测流 `X_det` 计算多视角异常证据向量

```text
E_t = <e_id, e_time, e_payload, e_seq, e_sem, e_aux>
```

为适配 GitHub README 渲染，本文中的形式化表达统一使用 ASCII 代码块记法：

```text
X = {p_t | t = 1..T}
p_t = (tau_t, pi_t, s_t, d_t, i_t, x_t, delta_t)
E_t = [e_id(t), e_time(t), e_payload(t), e_seq(t), e_sem(t), e_aux(t)]
```

并通过层级式证据融合算子 `Phi(.)` 生成包级告警集合 `A_pkt`，再经时间窗聚合算子 `G_Delta(.)` 生成事件级告警集合 `A_evt`。该过程对应“**画像学习 -> 多视角判别 -> 证据去重 -> 事件聚合 -> 语义解释**”的分层安全分析链。

```text
A_pkt = Phi(E_t, P_{i_t}, C_t)
A_evt = G_Delta(A_pkt)
```

| 局限 | 本方案的应对方式 |
|------|------------------|
| 固定阈值难迁移 | 通过显式训练从正常流量学习每个 ID 的节拍、负载、重复率、熵与数值变化基线，减少硬编码阈值依赖 |
| 单视角易漏检 | 将 **ID 行为、时序画像、载荷画像、序列新鲜度、轻量语义一致性** 组合为主路径，形成多视角互证 |
| 重模型落地成本高 | 主路径以可解释的统计画像和轻量序列规则为主，默认不依赖大规模标注数据或嵌入式 GPU 推理 |
| 多协议数据难统一 | 通过 `UnifiedPacket` 七元组统一 CAN / ETH / V2X 数据结构，为网关侧统一存储、检索和 LLM 上下文提供基础 |
| 告警缺乏语义解释 | 通过 LLM 输出攻击分类、根因分析、影响评估和处置建议，并支持工具调用获取实时数据 |

### 3. 系统设计

工程实现上，系统采用“**训练基线 -> 在线检测 -> 事件聚合 -> 语义分析**”四阶段流水线：

- **显式训练闭环**：检测前必须先调用 `POST /api/anomaly/train` 完成训练，系统从正常流量中学习每个 `msg_id` 的 `DLC`、周期、间隙分位数、字节统计量、熵、重复率、数值变化等画像。
- **Profile-First 主路径**：`IDBehaviorDetector`、`TimingProfileDetector`、`PayloadProfileDetector`、`ReplaySequenceDetector`、`RPMDetector`、`GearDetector` 共同构成在线主判链路，其中时序检测使用 median / MAD / 分位数等鲁棒统计量建模节拍偏差，载荷检测结合稳定字节掩码、`3-sigma` 区间、熵漂移和唯一比漂移建模负载异常。
- **IForest 辅助定位**：`IForestAuxDetector` 仅在 `enable_iforest_aux=true` 时启用，基于 15 维基线感知统计特征提供无监督旁证，用于补充而非取代画像主链路。
- **事件级聚合**：`AlertAggregator` 在时间窗口内将 packet-level alert 聚合为 event-level alert，降低告警噪声，并为后续报告生成提供稳定输入。
- **LLM 语义层**：LLM 不直接替代底层检测器，而是消费结构化告警证据，执行攻击解释、影响评估、问答和报告生成。

### 4. 系统边界

- 当前可训练的 Profile-First 主检测链路主要覆盖 **CAN / CAN-FD** 报文。
- 车载以太网与 V2X 已完成统一采集、解析、存储、可视化与 LLM 上下文接入，为后续多协议联合检测预留了数据面与接口面。
- 因而本项目的系统定位为：**多协议网关安全分析平台 + CAN-first 异常检测内核**。

上述背景部分回答了系统为何必须从网关位置出发重新组织异常检测与语义分析链路。沿着这一问题链，下一节进一步说明系统的方法学骨架如何从这些约束中被构造出来。

---

## 理论基础与参考文献

本系统以车载 IDS 中具有较强稳定性的**画像学习思想**为骨架，以鲁棒时序、载荷与序列检测为主体，以轻量无监督模型为旁证，并以 LLM 作为解释与交互层。基于上述设计，系统可抽象为 **MVPF-SR（Multi-View Profile-First Security Reasoning）** 框架。

### 一、方法抽象：MVPF-SR

在训练阶段，系统从正常 CAN/CAN-FD 流量中为每个 `msg_id` 学习正常性画像：

```text
P_i = {
  common_dlc, frequency, gap_median, gap_std, gap_p10, gap_p90,
  payload_constant_ratio, payload_zero_ff_ratio,
  byte_stability_mask, byte_min, byte_max, byte_mean, byte_std,
  byte_entropy_mean, byte_entropy_std,
  payload_unique_ratio_mean, repeat_ratio,
  payload_change_mean, payload_change_std,
  value_delta_mean, value_delta_std
}
```

```text
P_i = {
  D_i, lambda_i, g_tilde_i, sigma_g_i, q0.1_i, q0.9_i,
  mu_H_i, sigma_H_i, rho_rep_i, mu_chg_i, mu_val_i
}

g_tilde_i = median(Delta tau^(i))
lambda_i = N_i / T_i
rho_rep_i = (1 / (N_i - 1)) * sum_{k=2..N_i} 1[x_k^(i) = x_(k-1)^(i)]
```

在检测阶段，系统围绕单条报文及其上下文构造多视角异常证据：

```text
p -> {s_id, s_time, s_payload, s_seq, s_signal, s_aux}
```

其中：

- `s_id`：ID 白名单、DLC 合规性、突发频率、未知 ID flooding 等行为偏差。
- `s_time`：节拍收缩、总线负载因子、MAD 鲁棒偏差、重复停滞等时序偏差。
- `s_payload`：稳定字节掩码、字节统计区间、熵漂移、唯一比漂移、常量负载等载荷偏差。
- `s_seq`：子序列复用、计数器回滚、模式陈旧化等重放/新鲜度偏差。
- `s_signal`：RPM / Gear 等关键动力总成信号的轻量语义一致性偏差。
- `s_aux`：Isolation Forest 的无监督辅助异常分数。

工程实现上，系统并未强行训练一个 end-to-end 黑盒模型，而是采用“**多检测器独立产证据 -> 去重 -> 事件聚合 -> LLM 解释**”的层级式决策流程。这种设计更符合车载网关场景对**轻量部署、标签节约、解释充分**的要求。

进一步地，系统的在线判别过程可写为：

```text
S_t = <s_id(t), s_time(t), s_payload(t), s_seq(t), s_sem(t), s_aux(t)>
A_pkt = Phi(S_t, P_i, C_t)
A_evt = G_Delta(A_pkt)
```

其中 `C_t` 表示滑动上下文窗口，`Phi(.)` 并不是单一分类器，而是由多个检测器分别输出证据项、置信度和检测方法后形成的层级式融合机制；`G_Delta(.)` 则对应基于时间窗和目标节点的一致性事件聚合机制。

### 二、与代码实现的对应关系

| 方法学组件 | 工程实现 | 核心机制 |
|-----------|----------|----------|
| 正常性画像学习 | `ProfileManager` | 学习每个 ID 的周期、分位数、字节统计量、熵、重复率、变化率 |
| ID 行为建模 | `IDBehaviorDetector` | 未知 ID、DLC 异常、突发频率、unknown-id flood |
| 鲁棒时序检测 | `TimingProfileDetector` | `gap ratio`、`load factor`、MAD 鲁棒偏差、重复停滞 |
| 载荷画像检测 | `PayloadProfileDetector` | 稳定字节掩码、`3-sigma` 范围、熵漂移、唯一比漂移、常量负载 |
| 序列新鲜度检测 | `ReplaySequenceDetector` | rolling hash、窗口复用、payload reuse、counter rollback |
| 轻量语义一致性 | `RPMDetector` / `GearDetector` | 转速超限/突变、档位非法跳变与上下文校验 |
| 无监督辅助分支 | `IForestAuxDetector` | 15 维基线感知统计特征上的 Isolation Forest 旁证 |
| 事件级融合 | `AlertAggregator` | 时间窗内的 packet-level -> event-level 聚合 |
| 语义解释与交互 | `LLMEngine` | 结构化告警解释、报告生成、工具调用问答 |

### 三、与经典车载 IDS 工作的对应关系

本系统的主链路与经典文献之间存在清晰映射关系：

| 本项目模块 | 研究脉络 | 代表工作 |
|-----------|----------|----------|
| 周期/时序画像 | 基于 ECU 周期性与时间指纹的异常检测 | Cho & Shin, 2016 [6] |
| 未知 ID / 统计偏差 | 白名单、熵与统计行为建模 | Müter & Asaj, 2011 [7] |
| 载荷与序列异常 | 信息论、ID 序列与负载模式分析 | Marchetti et al., 2016 [8] |
| 无监督旁证 | 孤立思想驱动的异常样本快速分离 | Liu et al., 2008 [9] |
| 负载熵特征 | 基于 payload entropy 的异常建模 | Wang & Stolfo, 2004 [11] |

### 四、相关高水平研究与项目定位

与本项目直接相关的高水平研究如下：

| 高水平工作 | 核心思想 | 与本项目的关系 |
|-----------|----------|----------------|
| Graph-Based IDS for CANs [20] | 用图结构建模 CAN 报文之间的关系 | 本项目当前以统计画像和事件聚合实现轻量关系建模，可作为图建模的工程前身 |
| CANShield [21] | 在信号层使用多尺度 AE 集成检测语义级注入 | 本项目的载荷画像 + RPM/Gear 语义检测属于不依赖重模型的轻量替代方案 |
| X-CANIDS [22] | 利用 CAN 数据库把载荷拆解为可解释信号，实现 signal-aware explainable IDS | 本项目已具备 evidence 字段和 LLM 解释层，可自然演进到 signal-aware explainability 路线 |
| SEID / Graph Transformer [23] | 用 GNN + Transformer 建模信号关系与时空依赖 | 本项目的 `UnifiedPacket` 数据面和 Replay/Timing/Payload 特征可作为后续图模型输入 |
| Stateful Behavior Inference [24] | 用状态机与行为推断实现更强的运行时行为约束 | 本项目的 Replay/RPM/Gear 检测器可视为向 stateful IDS 迈出的轻量一步 |

总体上，GatewayGuard 不采用重型端到端黑盒模型作为默认方案，而是以**可解释、可部署、可迁移的 Profile-First 多视角画像主链路**作为核心检测机制，并在此基础上向 signal-aware、graph-aware、state-aware 的高级检测范式演进。

### 五、大语言模型与工具增强分析

将 LLM 应用于网络安全分析已成为近年来的重要趋势。系统综述表明，LLM 在安全场景中的价值主要体现在：告警解释、上下文整合、报告生成和交互式研判 [12][13]。与此同时，Toolformer [14]、Function Calling [15] 与 ReAct [16] 证明了模型可以在推理过程中调用外部工具，从而弥补静态语言模型在实时数据获取上的不足。

本系统的 LLM 层并不直接判定底层异常，而是消费检测器输出的结构化证据，执行：

- 攻击类型归纳与语义解释；
- 根因、影响范围与处置建议生成；
- 面向分析人员的多轮问答；
- 面向运维流程的结构化预警报告生成。

### 六、多协议统一建模

车载网关作为异构协议的汇聚节点，其数据模型必须兼顾不同协议的共同字段与差异字段。本系统的**统一数据模型（UnifiedPacket）** 设计参考了以下协议标准：

- **SAE J1939 / ISO 11898**：CAN 总线标准协议栈 [17]
- **AUTOSAR SOME/IP**：车载以太网面向服务的中间件协议 [18]
- **SAE J2735 / ETSI ITS-G5**：V2X 通信消息集标准 [19]

通过将不同协议的报文统一映射到 `(timestamp, protocol, source, destination, msg_id, payload, domain)` 七元组，系统实现了统一存储、统一查询和统一 LLM 上下文接入；当前异常检测主路径聚焦 CAN/CAN-FD，而 ETH/V2X 已在数据面和分析面完成统一抽象。

### 七、核心论文脉络

围绕本项目的方法形成过程，可以将最直接相关的核心论文归纳为以下七条主线：

| 核心论文 | 关键贡献 | 与本项目的关系 |
|----------|----------|----------------|
| Koscher et al., 2010 [25] | 通过真实车辆实验系统性揭示现代汽车内部网络的脆弱性，奠定车载网络安全研究问题域 | 支撑“为什么网关侧安全检测必须被认真建模”的问题起点 |
| Cho & Shin, 2016 [6] | 基于 ECU 时钟偏移与周期性消息建立 CIDS，代表时序画像与发送源行为建模路线 | 对应本项目的 `TimingProfileDetector` 与画像学习思想 |
| Müter & Asaj, 2011 [7]；Marchetti et al., 2016 [8] | 代表熵与信息论统计检测路线，强调对 CAN 报文分布结构进行轻量建模 | 对应本项目的熵漂移、唯一比漂移、局部统计约束 |
| Choi et al., 2018 [30] | 以低层电压/物理信号特征进行 ECU 指纹识别，代表物理层源识别方向 | 说明车载 IDS 可进一步向 sender-aware / physical-aware 能力扩展 |
| Shahriar et al., 2023 [21]；Jeong et al., 2024 [22] | 分别代表 signal-level 深度检测与 signal-aware explainable IDS 路线 | 对应本项目在轻量统计画像之上向 signal-aware explainability 的演进方向 |
| Serag et al., 2023 [26]；Shin et al., 2023 [27]；Desai et al., 2025 [24] | 从 CAN 防御构造、攻击源定位到状态机运行时约束，形成“检测之后如何响应”的闭环 | 对应本项目从检测、聚合到解释，再向 enforcement / response 延展的系统化方向 |
| Gao et al., 2025 [23]；Zhou et al., 2025 [29] | 使用图结构、Graph Transformer 和 signal relation 建模 CAN 消息之间的关系 | 对应本项目当前 Replay/Timing/Payload 特征向 graph-aware 检测范式的自然延展 |

从这一文献脉络看，GatewayGuard 的方法位置相对清晰：它不直接走重型端到端模型作为默认路径，而是首先立足于 **统计画像 + 序列新鲜度 + 轻量语义一致性 + LLM 语义分析** 的可部署主链路；同时，其统一数据面、证据结构和事件聚合机制又为后续吸纳 signal-aware、graph-aware、state-aware 与 response-aware 的高级检测范式预留了明确接口。

---

## 系统架构

当 MVPF-SR 从方法学抽象进入工程实现时，系统被组织为“统一数据进入、检测器产出证据、聚合器形成事件、LLM 给出解释、前端完成交互”的分层结构。其整体架构如下：

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
│  │             │ │ Profile-First│ │ (OpenAI/      │  │
│  │ CAN/ETH/V2X│ │ + Aggregator │ │  Ollama)      │  │
│  └──────┬──────┘ └──────┬──────┘ └───────┬───────┘  │
│         │               │                │           │
│  ┌──────┴───────────────┴────────────────┴───────┐  │
│  │         统一数据层 (SQLite + aiosqlite)         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 核心功能

围绕上述架构，系统的运行路径可以概括为“数据进入 -> 检测产证据 -> 语义层解释 -> 前端交互呈现”。因此，对外能力被组织为以下四个核心功能模块：流量模拟、异常检测、语义分析与交互问答。

### 1. 多协议流量模拟与解析

- **CAN 总线**：模拟 12 种 ECU 报文（发动机、变速箱、ABS、EPS 等），支持 DoS / Fuzzy / Spoofing 三种攻击场景
- **车载以太网**：基于 SOME/IP 协议模拟 7 种服务通信（摄像头、雷达、ADAS、OTA 等）
- **V2X 通信**：模拟 BSM / MAP / SPAT 三种消息类型

所有协议流量统一解析为 `UnifiedPacket` 七元组数据模型，打破协议壁垒，实现跨域关联分析。

### 2. Profile-First 异常检测

**显式训练闭环**：
- 检测前必须先调用 `POST /api/anomaly/train` 完成训练
- 训练数据按时间戳排序，建立各检测器的正常行为基线
- 未训练时调用检测接口将返回 428 Precondition Required

**主路径 — 三类画像检测（在线主判）**：
- **ID 行为检测**：未知 CAN ID、DLC 异常、单 ID 突发频率异常
- **时序画像检测**：节拍突变、重放型重复模式、总线级 DoS/Flooding（基于训练基线的速率/主导性/间隙压缩检测）
- **载荷画像检测**：字节稳定性掩码验证、字节统计范围检测（3-sigma）、载荷唯一比漂移、熵漂移、常量载荷异常
- **序列/语义检测**：Replay 检测器负责子序列复用和计数器回滚，RPM / Gear 检测器负责关键动力信号的轻量语义一致性约束
- **当前边界**：当前版本主检测器重点覆盖 CAN / CAN-FD，ETH / V2X 主要提供统一采集、存储、检索和 LLM 分析上下文

**辅助路径 — IForest Auxiliary（可开关）**：
- 仅在 `enable_iforest_aux=true` 时启用
- 作为补充信号，不作为默认主检测链路

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
| ML | scikit-learn (Isolation Forest Auxiliary) | 辅助异常检测（非默认主链路） |
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
│   │   │   ├── anomaly_detector.py # Profile-First 检测编排服务
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

点击「执行异常检测」，系统自动执行 Profile-First 检测：
- ID 行为、时序画像、载荷画像作为主路径
- IForest 作为可选辅助检测（默认关闭）

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
| POST | `/api/anomaly/train` | 训练检测器（必须先训练才能检测） |
| POST | `/api/anomaly/detect` | 触发异常检测（未训练时返回 428） |
| GET | `/api/anomaly/events` | 查询异常事件列表（支持筛选） |
| GET | `/api/anomaly/events/{id}` | 获取单条异常事件详情（`id` 为数据库主键） |

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

如果说前文完成了“问题定义 -> 方法抽象 -> 系统落地”的展开，那么这一节进一步聚焦最核心的检测内核。本系统采用 Profile-First 异常检测架构，主检测链路由画像模型驱动，Isolation Forest 仅作为辅助模块。

### 方法学表述

本检测内核定义为：

> **层级式多视角正常性画像融合检测器（Hierarchical Multi-View Profile Fusion Detector）**

其核心思想是：首先从正常流量中学习每个 CAN ID 的周期、负载、重复率、数值变化与局部序列新鲜度画像；随后在在线阶段从 **ID 行为、时序、载荷、序列、轻量语义** 五个视角独立产出异常证据；最后通过去重与事件聚合形成稳定告警。该机制在工程实现上对应模块化检测器编排，在方法层面可归纳为“多视角画像学习 + 层级融合决策”。

| 抽象层 | 工程实现 | 典型证据 |
|-------|----------|----------|
| 正常性基线学习 | `ProfileManager` | gap 分位数、熵均值/方差、稳定字节掩码、repeat ratio |
| 行为偏差检测 | `IDBehaviorDetector` | unknown ID、DLC anomaly、burst frequency |
| 鲁棒时序检测 | `TimingProfileDetector` | burst ratio、load factor、MAD robust gap deviation |
| 载荷约束检测 | `PayloadProfileDetector` | stable byte violation、3-sigma range、entropy drift |
| 序列新鲜度检测 | `ReplaySequenceDetector` | repeated subsequence、counter rollback、stale reuse |
| 信号语义检测 | `RPMDetector` / `GearDetector` | rpm spike、rpm out-of-range、gear transition mismatch |
| 无监督旁证 | `IForestAuxDetector` | iforest score、gap ratio、rate ratio、repeat run |
| 事件级融合 | `AlertAggregator` | time-window event clustering |

该架构**不采用**单一黑盒深度模型作为默认判定器，而是采用适配网关侧部署约束的可解释检测体系：画像检测器承担主判，IForest 提供旁证，LLM 负责解释、交互与报告生成，不直接替代底层异常判定。

### 1. 鲁棒时序异常建模

对任意 CAN ID `i`，系统在训练阶段估计其典型发送间隙画像 `P_i^time = {g50_i, sigma_g_i, g10_i, g90_i}`，其中 `g50_i` 为中位间隙，`g10_i/g90_i` 为分位数边界。在线阶段，在局部窗口 `W_i(t)` 上计算：

```text
r_gap(t)   = g50_i / median(Delta tau in W_i(t))
r_load(t)  = lambda_i(t) / lambda_i^base
z_mad(t)   = |median(Delta tau in W_i(t)) - g50_i| / (1.4826 * MAD(W_i(t)))
```

```text
g_obs_i(t) = median({Delta tau_k^(i) : k in W_i(t)})
r_gap(t)   = g_tilde_i / (g_obs_i(t) + eps)
r_load(t)  = lambda_obs_i(t) / (lambda_base_i + eps)
z_MAD(t)   = abs(g_obs_i(t) - g_tilde_i) / (1.4826 * MAD(W_i(t)) + eps)
```

其中 `r_gap(t)` 描述节拍压缩强度，`r_load(t)` 描述局部负载膨胀倍数，`z_mad(t)` 描述相对于鲁棒尺度估计的时序偏离强度。由于当前实现采用中位数、MAD 与分位数而非均值阈值，故对瞬时抖动、个别乱序与非高斯波动具有更强鲁棒性。DoS/Flooding 检测并不是独立的总线负载模块，而是通过 `gap ratio + load factor + robust gap deviation` 的联合证据在 `TimingProfileDetector` 内部完成基线感知判别。

### 2. 载荷分布画像与局部流形约束

对于每个 `msg_id=i`，系统从训练样本中学习字节级统计画像 `P_i^payload`，包括稳定字节掩码 `M_i^stab`、按字节统计区间、载荷熵分布和唯一比统计。在线阶段，`PayloadProfileDetector` 同时检查：

```text
M_i^stab(x_t)          -> 稳定字节是否越界
R_i^3sigma(x_t)        -> 字节值是否超出统计范围
z_H(t) = |H(x_t)-mu_H,i| / sigma_H,i
d_uniq(t) = |rho_uniq(x_t)-rho_uniq,i|
```

```text
H(x_t) = - sum_{b in B(x_t)} p(b) * log2 p(b)
rho_uniq(x_t) = |uniq(x_t)| / |x_t|
delta_chg(t) = (1 / m) * sum_{j=1..m} 1[x_t^(j) != x_(t-1)^(j)]
z_H(t) = abs(H(x_t) - mu_H_i) / (sigma_H_i + eps)
d_uniq(t) = abs(rho_uniq(x_t) - rho_uniq_i)
```

其中 `H(x_t)` 为字节熵，`rho_uniq(x_t)` 为载荷唯一字节占比。该设计本质上是在离散字节空间上构造一种轻量级“局部统计流形约束”：稳定字节用于描述强约束维度，`3-sigma` 区间用于描述弱约束维度，熵漂移和唯一比漂移则用于描述整体分布结构偏离。对于合法 ID 下的 Spoofing、Fuzzy 和常量载荷注入，该机制较单一阈值或单一熵特征具有更强覆盖能力。

### 3. 序列新鲜度与重放判别

`ReplaySequenceDetector` 采用基于局部序列哈希与计数器行为挖掘的状态化检测机制。设长度为 `w` 的局部载荷窗口为 `Q_t^w = [x_{t-w+1}, ..., x_t]`，则窗口指纹定义为：

```text
h_t^w = MD5(x_{t-w+1} || ... || x_t)
```

```text
Q_t^(w) = [x_{t-w+1}, x_{t-w+2}, ..., x_t]
h_t^(w) = MD5(x_{t-w+1} || ... || x_t)
Delta c_t = (c_t - c_(t-1)) mod M
rollback if Delta c_t not in S_counter_i
```

训练阶段，系统学习每个 ID 的：

- 精确载荷复用率与其 `p95` 复用时间；
- 窗口级子序列复用率、`p95` 复用时间与 `p95` 包间距；
- 候选计数器字节位置、主导步长与有效回绕模式。

在线阶段，系统联合以下证据完成 Replay 判别：

- **repeated subsequence**：窗口指纹重复出现，但复用年龄与包间距超出正常画像；
- **exact payload reuse**：动态 ID 在异常短的时间尺度上重现相同载荷；
- **counter rollback / stagnation**：计数器字节出现非正常回退或停滞；
- **stale pattern reuse**：低复用 ID 在异常长时间后重现历史模式。

相较仅使用 ID 序列频率或固定计数器规则的方案，该机制同时利用了**序列结构、时间年龄与字节行为**三类信息，更适合识别“合法 ID + 合法节拍 + 历史载荷重放”的隐蔽型攻击。

### 4. 轻量语义一致性建模

`RPMDetector` 与 `GearDetector` 对动力总成关键报文构建语义一致性约束。训练阶段，系统自动推断 RPM 解码模型、档位状态模型、档位条件 RPM 区间以及允许的状态转移图；在线阶段，分别检查：

```text
rpm(t) > rpm_max
|rpm(t) - rpm(t-1)| / Delta tau > rate_limit
(gear_{t-1}, gear_t) notin T_allowed
rpm(t) notin [l_gear, u_gear]
```

其中 `T_allowed` 为训练阶段学得的档位转移图，`[l_gear, u_gear]` 为给定档位下 RPM 的条件区间。该机制并不依赖完整 DBC 语义知识，而是通过轻量上下文关联实现对“合法帧内语义篡改”的约束，从而弥补纯报文字节统计无法覆盖的动力域攻击。

### 主检测链路（Profile-First）

| 模块 | 检测目标 | 典型攻击 |
|------|----------|----------|
| IDBehaviorDetector | 未知 ID、DLC 异常、突发频率 | Fuzzy / DoS |
| TimingProfileDetector | 时序突变、重复重放 | DoS / Replay |
| PayloadProfileDetector | 与基线偏离的载荷模式 | Spoofing |
| RPMDetector | RPM 超限、RPM 突变 | Spoofing / Fuzzy |
| GearDetector | 非法档位状态 | Spoofing |
| ReplaySequenceDetector | 序列重放、计数器回滚 | Replay |

### 辅助检测链路（IForest Auxiliary）

- 配置项：`enable_iforest_aux`
- 默认关闭，开启后对主链路结果提供补充告警
- 特征向量采用 15 维统计编码：

```text
[
  log1p(msg_id_num), payload_len, byte_entropy, protocol, domain,
  log1p(delta_t_us), payload_delta, value_delta,
  gap_ratio, id_rate_ratio, global_rate_ratio, id_window_share,
  repeat_run_norm, zero_ff_flag, known_id
]
```

- 阈值采用训练分数分位自校准策略：以训练集 `decision_function` 的低分位统计量确定主阈值，并对 unknown-id 样本保留相对宽松的触发边界。
- 对已知 ID，IForest 分支不会单独作为主判据，而是要求与 burst/flood 类显式信号形成共证后才输出辅助告警。

### 5. 分层证据融合与事件级输出

系统并不将多视角特征压缩为单一全局分数，而是保留 detector-level evidence。各检测器输出的 `anomaly_type`、`confidence`、`detection_method` 与 `evidence` 先经重复告警抑制，再在时间窗内执行事件聚合：

```text
A_evt = G_Delta(A_pkt; anomaly_type, target_node, [t, t+Delta])
```

```text
E_k = G_Delta(A_pkt; type, node, [tau, tau + Delta])
Conf(E_k) = (sum_j c_j * n_j) / (sum_j n_j)
```

该设计使最终结果同时具有**包级敏感性**与**事件级稳定性**：前者用于定位细粒度异常瞬时点，后者用于支持运营视角的时间线分析、聚合统计与 LLM 报告生成。

### Legacy 退役计划

- 历史实现保留在 `backend/app/services/anomaly_detector_old.py`，仅用于兼容回溯，不参与默认运行路径。
- 后续将按里程碑移除：先冻结 legacy 功能，再在完成一轮版本观察后删除旧实现与对应文档。

### 运行时契约（P0）

- `/api/anomaly/detect` 与采集器自动检测路径均不再隐式训练检测器。
- 若检测器尚未训练，接口返回 **HTTP 428 Precondition Required** 状态码，要求先调用 `POST /api/anomaly/train` 执行显式训练流程。
- 检测处理前按时间升序执行（oldest -> newest），避免时序特征在逆序输入下失真。

### 事件持久化语义

- 包级告警（packet-level alert）持续写入 `anomaly_events`，并保留 `event_id` / `packet_count` 关联字段。
- 开启聚合时，会额外写入事件级记录（`detection_method=event_aggregation`），用于事件视角检索与统计。
- API 返回同时包含 `detected`（包级告警数）与 `aggregated_events`（事件级结果）。

---

## 配置参数

主要配置通过环境变量和 `app/config.py` 管理：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `OPENAI_API_KEY` | - | OpenAI API 密钥 |
| `LLM_PROVIDER` | `openai` | LLM 提供商（openai / ollama） |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 服务地址 |
| 检测器频率阈值 | `3.0` | 频率异常判定倍数 |
| IForest 污染率 | `0.05` | IForest Auxiliary contamination 参数 |
| LLM temperature | `0.3` | 生成温度（低值更确定性） |
| LLM max_tokens | `1024` | 单次生成最大 Token 数 |

检测相关关键配置（`backend/config.yaml`）：

- `detector.enable_iforest_aux`：是否启用 IForest 辅助检测。
- `detector.enable_event_aggregation`：是否启用事件聚合输出与事件级持久化。
- `detector.enable_rpm_detector`：是否启用 RPM 检测器（超限/突变）。
- `detector.enable_gear_detector`：是否启用档位状态检测器（非法档位）。
- `detector.enable_replay_detector`：是否启用序列重放检测器（重放/计数器回滚）。
- `detector.min_train_packets`：显式训练所需最小样本数。
- `detector.temporal_window_size` / `detector.event_window_ms`：时序检测与事件聚合窗口。

---

## 外部数据集评估

方法能否成立，最终仍需通过公开数据集评测闭环加以验证。为验证 Profile-First 主检测链路在公开 CAN / CAN-FD 数据上的可迁移性与工程稳定性，项目在 `reports/` 目录下维护独立的离线评测结果。当前发布版结论以 [`reports/dataset_survey_and_evaluation.md`](reports/dataset_survey_and_evaluation.md) 为准，其评测口径对应 `2026-03-19` 的最新结果整理。

### 发布版评测口径

当前发布版正式展示范围包括 `4` 个开源数据集的 `4` 个正常流量窗口与 `11` 个攻击 case，不纳入发布版展示的对象包括：

- `OTIDS-2nd`
- `RA8P1` 相关本地文件
- 本地真实流量采集结果
- 合成 / 混合 JSONL 独立测试文件

评测协议定义如下：

- 每个开源数据集单独训练一次检测器，不跨数据集混合建模。
- 训练阶段使用该数据集的正常流量窗口构建 `ProfileManager` 基线。
- 测试阶段分别在 `normal_eval` 与攻击窗口上执行检测。
- 大规模数据集统一截断到最多 `100000` 条训练、`100000` 条正常测试、`100000` 条攻击测试。
- 评测主指标采用 `ML precision / recall / f1 / false_positive_rate`，`stock_alerts_total` 仅表示系统总告警强度。

若记第 `k` 个攻击 case 的攻击样本数为 `a_k`、对应 `F1` 为 `F1_k`，则发布版总体攻击检测指标记为：

```text
WeightedF1_release = (sum_{k=1..K} a_k * F1_k) / (sum_{k=1..K} a_k)
K = 11
```

在当前发布版口径下，`WeightedF1_release = 0.9617`。

相较上一轮发布口径使用的 `reports/external_can_eval_current_run.json`，攻击 case 加权 `weighted_f1` 由 `0.8860` 提升至 `0.9617`。

### 发布版总体结果

| 指标 | 结果 |
|------|------|
| 纳入发布版的数据集数 | `4` |
| 正常流量窗口数 | `4` |
| 攻击 case 数 | `11` |
| 发布版攻击加权 `weighted_f1` | `0.9617` |
| 上一轮发布口径攻击加权 `weighted_f1` | `0.8860` |
| 正常流量新增回归 | `0` |
| 正常段 `ML` 误报 | 仅 `B-CAN normal_eval` 保留 `5` 条，`FPR = 0.0001` |

本轮修复收益主要集中在 `B-CAN ddos_tail`、`CAN-FD malfunction`、`Car-Hacking rpm_tail` 与 `Car-Hacking gear_tail` 四个原先薄弱场景。

### 正常流量结果

| 数据集 | 样本数 | 唯一 ID 数 | 总告警 | Rule/Profile | ML | ML FPR | 主要告警类型 |
|--------|--------|------------|--------|--------------|----|--------|--------------|
| B-CAN | 100000 | 180 | 520 | 515 | 5 | 0.0001 | `payload_anomaly:481`, `temporal_anomaly:15`, `rpm_spike:8` |
| M-CAN | 100000 | 54 | 5 | 5 | 0 | 0.0000 | `rpm_rate_anomaly:3`, `bus_load_anomaly:1`, `temporal_anomaly:1` |
| Car-Hacking | 100000 | 27 | 174 | 174 | 0 | 0.0000 | `payload_anomaly:167`, `replay_suspected:6`, `bus_load_anomaly:1` |
| CAN-FD | 100000 | 54 | 36 | 36 | 0 | 0.0000 | `payload_anomaly:29`, `gear_shift_anomaly:7` |

发布版正常流量结果表明，纳入展示的 `4` 个公开数据集在 `normal_eval` 上均未引入新增回归，主检测链路仍保持低误报运行状态。

### 攻击流量结果

| 数据集 | Case | 攻击样本数 | Precision | Recall | F1 | 主要告警类型 |
|--------|------|------------|-----------|--------|----|--------------|
| B-CAN | `ddos_tail` | 16000 | 0.9997 | 0.9001 | 0.9473 | `payload_anomaly:14628`, `ml_auxiliary:14407` |
| B-CAN | `fuzzing_tail` | 3000 | 1.0000 | 0.8413 | 0.9138 | `ml_auxiliary:2524`, `unknown_can_id:2031` |
| M-CAN | `ddos_tail` | 37587 | 1.0000 | 0.8847 | 0.9388 | `ml_auxiliary:33254`, `unknown_id_flood:32906` |
| M-CAN | `fuzzing_tail` | 11455 | 1.0000 | 0.8409 | 0.9135 | `ml_auxiliary:9632`, `unknown_can_id:3812` |
| Car-Hacking | `dos_tail` | 23673 | 1.0000 | 1.0000 | 1.0000 | `ml_auxiliary:23672`, `unknown_id_flood:20107` |
| Car-Hacking | `fuzzy_tail` | 12021 | 0.9986 | 0.9415 | 0.9692 | `ml_auxiliary:11334`, `payload_anomaly:9063` |
| Car-Hacking | `rpm_tail` | 18952 | 0.9144 | 1.0000 | 0.9553 | `rpm_mode_anomaly:18952`, `rpm_rate_anomaly:2983` |
| Car-Hacking | `gear_tail` | 18817 | 0.8118 | 1.0000 | 0.8962 | `gear_state_out_of_profile:18879`, `gear_shift_anomaly:4299` |
| CAN-FD | `flooding` | 43070 | 1.0000 | 1.0000 | 1.0000 | `ml_auxiliary:43069`, `unknown_id_flood:42449` |
| CAN-FD | `fuzzing` | 28156 | 0.9984 | 0.9992 | 0.9988 | `payload_anomaly:28285`, `ml_auxiliary:28178` |
| CAN-FD | `malfunction` | 8212 | 0.8125 | 0.9974 | 0.8955 | `temporal_anomaly:10040`, `payload_anomaly:51809` |

从攻击结果看，当前版本已经覆盖公开展示口径下的全部 `11` 个攻击 case，且不再存在 `Recall = 0` 的展示项。其中：

- `Car-Hacking dos_tail` 与 `CAN-FD flooding` 达到 `F1 = 1.0000`
- `CAN-FD fuzzing` 达到 `F1 = 0.9988`
- `Car-Hacking fuzzy_tail`、`Car-Hacking rpm_tail`、`B-CAN ddos_tail` 分别达到 `0.9692`、`0.9553`、`0.9473`
- 相对偏弱但已具备可用性的场景为 `CAN-FD malfunction (0.8955)`、`Car-Hacking gear_tail (0.8962)`、`B-CAN fuzzing_tail (0.9138)` 与 `M-CAN fuzzing_tail (0.9135)`

### 评测工具链

当前评估工具链支持“基准评估 + 迁移评估 + 结果对比”三类离线实验，默认以 Profile-First 主路径为核心，并可通过参数开启 IForest Auxiliary 辅助检测。

- `backend/scripts/evaluate_external_can_datasets.py`：对外部 CAN/RA8P1 数据集执行标准离线评估，输出包级与事件级指标（Precision / Recall / F1）及检测器分布统计。
- `backend/scripts/evaluate_transfer_to_ra8p1.py`：执行跨数据集迁移评估（源数据集 -> RA8P1），用于验证训练-测试域迁移效果。
- `backend/scripts/compare_eval_results.py`：对比新旧评估 JSON 输出并生成 Markdown 差异报告（指标增减与告警类型变化）。
- `backend/scripts/evaluate_trainset_fit.py`、`backend/scripts/evaluate_local_synthetic_jsonl.py`：用于训练集拟合质量与本地 JSONL 样本评估。

标准评估示例：

```bash
cd backend
venv/bin/python scripts/evaluate_external_can_datasets.py \
  --input ../data/can_eval.csv \
  --format csv \
  --train-ratio 0.6
```

输入文件需至少包含字段：`timestamp, protocol, source, destination, msg_id, payload_hex`，并提供攻击标签列（`attack` / `label` / `is_attack` 之一）。

---

## 真实车机部署

在离线评测形成方法有效性证据之后，系统进一步面向真实车机网关环境部署。本系统支持从模拟环境无缝切换到真实车载网络环境。通过数据源抽象层，可在不修改检测逻辑的前提下接入真实 CAN 总线、车载以太网或离线抓包文件。

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

**[4]** Wu, W., et al. (2020). *A Survey of Intrusion Detection for In-Vehicle Networks*. IEEE Transactions on Intelligent Transportation Systems, 21(3), 919-933.

**[5]** Aliwa, E., et al. (2021). *Cyberattacks and Countermeasures for In-Vehicle Networks*. ACM Computing Surveys, 54(1), 1-37.

### 异常检测算法

**[6]** Cho, K. T., & Shin, K. G. (2016). *Fingerprinting Electronic Control Units for Vehicle Intrusion Detection*. 25th USENIX Security Symposium (USENIX Security 16), 911-927.

**[7]** Müter, M., & Asaj, N. (2011). *Entropy-based Anomaly Detection for In-vehicle Networks*. IEEE Intelligent Vehicles Symposium (IV), 1110-1115.

**[8]** Marchetti, M., Stabili, D., Guido, A., & Colajanni, M. (2016). *Evaluation of Anomaly Detection for In-vehicle Networks through Information-Theoretic Algorithms*. IEEE 2nd International Forum on Research and Technologies for Society and Industry (RTSI), 429-434.

**[9]** Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. IEEE International Conference on Data Mining (ICDM), 413-422.

**[10]** Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python*. Journal of Machine Learning Research, 12, 2825-2830.

**[11]** Wang, K., & Stolfo, S. J. (2004). *Anomalous Payload-based Network Intrusion Detection*. International Workshop on Recent Advances in Intrusion Detection (RAID), 203-222.

### LLM 与网络安全

**[12]** Zhang, J., Bu, H., Wen, H., Liu, Y., Fei, H., Xi, R., Li, L., Yang, Y., Zhu, H., et al. (2025). *When LLMs Meet Cybersecurity: A Systematic Literature Review*. Cybersecurity, 8, 55.

**[13]** Liu, Y., et al. (2024). *Large Language Models for Cyber Security: A Systematic Literature Review*. arXiv preprint arXiv:2405.04760.

**[14]** Schick, T., Dwivedi-Yu, J., Dessi, R., Raileanu, R., Lomeli, M., Hambro, E., Zettlemoyer, L., Cancedda, N., & Scialom, T. (2023). *Toolformer: Language Models Can Teach Themselves to Use Tools*. Advances in Neural Information Processing Systems (NeurIPS 2023).

### LLM 工具调用与 Agent

**[15]** OpenAI. (2023). *Function Calling and Other API Updates*. OpenAI Blog.

**[16]** Yao, S., et al. (2023). *ReAct: Synergizing Reasoning and Acting in Language Models*. International Conference on Learning Representations (ICLR).

### 车载协议标准

**[17]** ISO 11898-1:2015. *Road vehicles — Controller area network (CAN)*. International Organization for Standardization.

**[18]** AUTOSAR. (2022). *SOME/IP Protocol Specification*. AUTOSAR Classic Platform, R22-11.

**[19]** SAE International. (2020). *J2735 — V2X Communications Message Set Dictionary*. SAE Standard.

### 前沿 A 会 / A 刊算法工作

**[20]** Islam, R., Refat, R. U. D., Yerram, S. M., & Malik, H. (2022). *Graph-Based Intrusion Detection System for Controller Area Networks*. IEEE Transactions on Intelligent Transportation Systems, 23(3), 1727-1736.

**[21]** Shahriar, M. H., Xiao, Y., Moriano, P., Lou, W., & Hou, Y. T. (2023). *CANShield: Deep-Learning-Based Intrusion Detection Framework for Controller Area Networks at the Signal Level*. IEEE Internet of Things Journal, 10(24), 22111-22127.

**[22]** Jeong, S., Lee, S., Lee, H., & Kim, H. K. (2024). *X-CANIDS: Signal-Aware Explainable Intrusion Detection System for Controller Area Network-Based In-Vehicle Network*. IEEE Transactions on Vehicular Technology, 73(3), 3230-3246.

**[23]** Gao, F., Liu, J., Li, C., Gao, Z., & Zhao, R. (2025). *Signal-Relationship-Aware Explainable Intrusion Detection in Controller Area Networks Using Graph Transformers*. Knowledge-Based Systems, 328, 114237.

**[24]** Desai, A., Dai, R., Chen, Y., Ho, K., Kee, A., Bulatovic, S., Shafiuzzaman, M., Bai, K. Y., Jeong, I. U., Siu, D., Yavuz, T., & Bultan, T. (2025). *Stateful Behavior Inference and Runtime Enforcement for Vehicle Network Security*. 3rd USENIX Symposium on Vehicle Security and Privacy (VehicleSec '25), 1-17.

**[25]** Koscher, K., Czeskis, A., Roesner, F., Patel, S. N., Kohno, T., Checkoway, S., McCoy, D., Kantor, B., Anderson, D., Shacham, H., & Savage, S. (2010). *Experimental Security Analysis of a Modern Automobile*. IEEE Symposium on Security and Privacy (SP), 447-462.

**[26]** Serag, K., Bhatia, R., Faqih, A., Ozmen, M. O., Kumar, V., Celik, Z. B., & Xu, D. (2023). *ZBCAN: A Zero-Byte CAN Defense System*. 32nd USENIX Security Symposium (USENIX Security 23), 6893-6910.

**[27]** Shin, J., Kim, H., Lee, S., Choi, W., Lee, D. H., & Jo, H. J. (2023). *RIDAS: Real-time Identification of Attack Sources on Controller Area Networks*. 32nd USENIX Security Symposium (USENIX Security 23), 6911-6928.

**[28]** Jo, H. J., & Choi, W. (2022). *A Survey of Attacks on Controller Area Networks and Corresponding Countermeasures*. IEEE Transactions on Intelligent Transportation Systems, 23(7), 6123-6141.

**[29]** Zhou, X., Qin, G., Liang, Y., Song, J., Liu, W., et al. (2025). *CGTS: Graph Transformer-Based Anomaly Detection in Controller Area Networks*. Cybersecurity, 8, 62.

**[30]** Choi, W., Joo, K., Jo, H. J., Park, M. C., & Lee, D. H. (2018). *VoltageIDS: Low-Level Communication Characteristics for Automotive Intrusion Detection System*. IEEE Transactions on Information Forensics and Security, 13(8), 2114-2129.

---

<div align="center">

**GatewayGuard** — 基于 LLM 的智能网关安全分析系统

</div>
