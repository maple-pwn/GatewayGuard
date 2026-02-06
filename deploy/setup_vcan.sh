#!/usr/bin/env bash
# setup_vcan.sh - 配置 Linux vCAN 虚拟接口用于开发测试
# 用法: sudo bash setup_vcan.sh [接口名称] (默认 vcan0)

set -euo pipefail

IFACE="${1:-vcan0}"

echo "[*] Loading vcan kernel module..."
modprobe vcan

echo "[*] Creating virtual CAN interface: $IFACE"
ip link add dev "$IFACE" type vcan 2>/dev/null || echo "    (interface already exists)"

echo "[*] Bringing up $IFACE..."
ip link set up "$IFACE"

echo "[+] vCAN interface $IFACE is ready."
echo "    Verify: ip -details link show $IFACE"
ip -details link show "$IFACE"
