"""LLM Prompt模板集中管理"""

SYSTEM_PROMPT = """你是车载网络安全分析专家，精通CAN总线、车载以太网、V2X协议及常见攻击手法。请用中文简洁回答，直接输出JSON，不要用markdown代码块包裹。"""

ANOMALY_ANALYSIS_PROMPT = """分析以下网关异常事件：

- 协议: {protocol} | 类型: {anomaly_type} | 严重程度: {severity}
- 置信度: {confidence} | 源: {source_node} | 目标: {target_node}
- 检测方法: {detection_method}
- 描述: {description}

直接输出JSON（不要```包裹）：
{{"attack_type":"攻击类型","attack_method":"手法(50字内)","root_cause":"根因(50字内)","affected_scope":["受影响范围"],"attack_intent":"意图(30字内)","risk_level":"high/medium/low","recommendations":["建议1","建议2"],"summary":"一句话总结"}}"""

REPORT_GENERATION_PROMPT = """基于以下异常事件生成预警报告：

{events_json}

直接输出JSON（不要```包裹）：
{{"title":"报告标题","summary":"摘要(100字内)","timeline":["关键事件"],"attack_chain":"攻击链分析(100字内)","impact_assessment":"影响评估(80字内)","risk_level":"critical/high/medium/low","recommendations":["建议1","建议2","建议3"],"conclusion":"结论(50字内)"}}"""
