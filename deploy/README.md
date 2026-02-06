# GatewayGuard 真实车机部署指南

## 1. 系统要求

| 项目 | 要求 |
|------|------|
| OS | Linux 5.4+ (推荐 Ubuntu 20.04 / Debian 11) |
| Python | 3.10+ |
| Node.js | 18+ (仅前端构建需要) |
| CAN 硬件 | SocketCAN 兼容适配器 (如 PEAK PCAN-USB, Kvaser) |
| 网络 | 以太网接口 (用于车载以太网抓包) |

## 2. CAN 总线配置

### 2.1 虚拟 CAN (开发测试)

```bash
sudo bash deploy/setup_vcan.sh        # 默认创建 vcan0
sudo bash deploy/setup_vcan.sh vcan1  # 创建额外接口
```

### 2.2 真实 CAN 硬件

```bash
# 加载驱动 (以 PEAK USB 为例)
sudo modprobe peak_usb

# 配置 CAN 接口
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# 验证
candump can0
```

### 2.3 修改配置

编辑 `backend/config.yaml`:

```yaml
sources:
  mode: can          # 切换为真实 CAN
  can:
    interface: can0  # 真实硬件接口
    channel: can0
    bustype: socketcan
    bitrate: 500000
  collector:
    enabled: true    # 启动时自动采集
    interval_ms: 10
    buffer_size: 10000
    auto_detect: true
    detect_batch_size: 200
```

## 3. 以太网抓包配置

```yaml
sources:
  mode: ethernet
  ethernet:
    interface: eth0
    filter: "udp port 30490"  # SOME/IP 默认端口
```

需要 root 权限或设置 capabilities:

```bash
sudo setcap cap_net_raw+ep $(which python3)
```

## 4. 部署步骤

### 4.1 后端

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 启动 (开发)
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 启动 (生产)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

> 注意: 实时采集模式下建议 `--workers 1`，避免多进程竞争 CAN 接口。

### 4.2 前端

```bash
cd frontend
npm install
npm run build
# 将 dist/ 目录部署到 Nginx 或直接用 FastAPI 静态文件服务
```

## 5. 数据源模式说明

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `simulator` | 内置模拟器生成数据 | 开发、演示 |
| `can` | 从 SocketCAN 接口实时读取 | 真实 CAN 总线 |
| `ethernet` | Scapy 抓包 | 车载以太网 |
| `pcap` | 导入离线文件 | 回放分析 |
| `multi` | CAN + 以太网同时采集 | 完整车机部署 |

## 6. 离线文件导入

支持格式: `.pcap`, `.pcapng`, `.blf`, `.asc`

通过前端 Dashboard "导入文件" 按钮，或 API:

```bash
curl -X POST "http://localhost:8000/api/traffic/import?file_path=/data/capture.blf"
```

## 7. 注意事项

- CAN 采集需要 root 权限或 `cap_net_raw` capability
- 以太网抓包同样需要相应权限
- 生产环境建议配置 systemd 服务实现自动重启
- 数据库默认使用 SQLite，大规模部署建议切换 PostgreSQL
