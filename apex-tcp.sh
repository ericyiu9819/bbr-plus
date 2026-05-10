#!/bin/bash
# tcp-auto-tune-verified.sh - 验证优化版
set -euo pipefail  # 严格模式，防隐蔽错误

echo "=== 1. 检测系统参数（公理可观测）==="
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)
NIC=$(ip route | awk '/default/ {print $5}' | head -1)
NIC_SPEED=$(ethtool "$NIC" 2>/dev/null | grep Speed | awk '{print $2}' | sed 's/M//' || echo 1000)
RTT_MS=$(ping -c 3 8.8.8.8 | tail -1 | awk -F/ '{print $5}' | cut -d. -f1 || echo 50)

echo "RAM:${RAM_GB}GB CPU:${CPU_CORES}核 NIC:${NIC_SPEED}Mbps RTT:${RTT_MS}ms"

echo "=== 2. 计算最优值（BDP+RAM比例映射）==="
MAX_BUF=$((RAM_GB * 1024**3 / 5))  # 调至20%更保守（原25%略激进）
BDP=$((NIC_SPEED * RTT_MS * 1024 / 8))
RECV_MAX=$((MAX_BUF > BDP*4 ? MAX_BUF : BDP*4))
# 硬上限保护（防超大内存VPS耗尽）
if [ "$RECV_MAX" -gt $((1024**3 * 2)) ]; then RECV_MAX=$((1024**3 * 2)); fi

cat > /tmp/99-auto-tcp.conf << EOF
net.core.rmem_max = $RECV_MAX
net.core.wmem_max = $RECV_MAX
net.ipv4.tcp_rmem = 4096 87380 $RECV_MAX
net.ipv4.tcp_wmem = 4096 65536 $RECV_MAX
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.core.somaxconn = $((CPU_CORES * 8192))
net.ipv4.tcp_max_syn_backlog = $((CPU_CORES * 8192))
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_mem = $((RAM_GB*1024*1024/2)) $((RAM_GB*1024*1024)) $((RAM_GB*1024*1024*2))  # 新增总内存控制
EOF

echo "=== 3. 备份+应用+验证 ==="
cp /etc/sysctl.d/99-tcp*.conf /tmp/backup/ 2>/dev/null || mkdir -p /tmp/backup
cp /tmp/99-auto-tcp.conf /etc/sysctl.d/
sysctl -p /etc/sysctl.d/99-auto-tcp.conf > /dev/null

echo "优化后关键值："
sysctl net.core.rmem_max net.ipv4.tcp_congestion_control net.core.somaxconn
echo "建议立即跑： iperf3 -c 某服务器 测试前后吞吐"
