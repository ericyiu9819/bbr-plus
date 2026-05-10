#!/bin/bash
# tcp-auto-tune-aggressive-safe.sh - 断流风险最小化版
set -euo pipefail

echo "=== 1. 检测 ==="
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
# ...（检测部分同前，省略以简洁）

echo "=== 2. 计算（保守激进）==="
MAX_BUF=$((RAM_GB * 1024**3 / 5))   # 20%更安全
BDP=$((NIC_SPEED * RTT_MS * 1024 / 8))
RECV_MAX=$((MAX_BUF > BDP*4 ? MAX_BUF : BDP*4))  # 降至4倍
if [ "$RECV_MAX" -gt $((1024**3 * 2)) ]; then RECV_MAX=$((1024**3 * 2)); fi  # 2GB cap

cat > /tmp/99-safe-aggressive.conf << EOF
net.core.rmem_max = $RECV_MAX
net.core.wmem_max = $RECV_MAX
net.ipv4.tcp_rmem = 4096 87380 $RECV_MAX
net.ipv4.tcp_wmem = 4096 65536 $RECV_MAX
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.core.somaxconn = $((CPU_CORES * 8192))
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1          # 改回1，更稳
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 65536
net.ipv4.tcp_mem = $((RAM_GB*256*1024)) $((RAM_GB*512*1024)) $((RAM_GB*1024*1024))
net.ipv4.tcp_moderate_rcvbuf = 1
EOF

# 备份+应用（同前）
echo "✅ 安全激进版应用！监控建议："
echo "watch -n 1 'ss -m | head -10; free -h; netstat -s | grep -E \"retrans|drop\"'"
