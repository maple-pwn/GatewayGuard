"""LLM Function Calling 工具定义

定义LLM在交互式分析中可调用的后端工具
"""

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
                        "description": "协议类型",
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
    {
        "type": "function",
        "function": {
            "name": "get_anomaly_events",
            "description": "获取异常事件列表",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": [
                            "critical", "high",
                            "medium", "low", "all",
                        ],
                        "description": "严重程度过滤",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回数量限制",
                    },
                },
            },
        },
    },
]
