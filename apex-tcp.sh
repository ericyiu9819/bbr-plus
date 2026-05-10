#!/bin/bash
# Grok 自适应 TCP BBR 优化脚本 v1 - 自动适配 VPS 内存/内核
set -e

echo "=== Grok 自适应 BBR 优化启动 ==="

# 1. 备份 & 清理旧配置
BACKUP="/etc/sysctl.d/99-grok-bbr-opt.conf.bak.$(date +%s)"
sudo cp /etc/sysctl.d/99-grok-bbr-opt.conf "$BACKUP" 2>/dev/null || true
sudo rm -f /etc/sysctl.d/99-grok-bbr-opt.conf

# 2. 探测系统信息
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
KERNEL_VER=$(uname -r | cut -d. -f1-2 | tr -d '.')
INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno)' | head -n1)

echo "探测：RAM=${TOTAL_RAM_MB}MB | 内核=${KERNEL_VER} | 接口=${INTERFACE:-unknown}"

# 3. 自适应缓冲计算（安全比例）
if [ "$TOTAL_RAM_MB" -lt 1024 ]; then
  MAX_BUF=33554432      # 32MB 低配保守
elif [ "$TOTAL_RAM_MB" -lt 4096 ]; then
  MAX_BUF=67108864      # 64MB
else
  MAX_BUF=$((TOTAL_RAM_MB * 1024 * 1024 / 4))  # 高配 ≤25% RAM
fi
MAX_BUF=$(( MAX_BUF > 134217728 ? 134217728 : MAX_BUF ))  # 上限 128MB

# 4. 生成自适应配置
cat <<EOF | sudo tee /etc/sysctl.d/99-grok-adaptive-bbr.conf
# === Grok 自适应 BBR 配置 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 自适应缓冲（根据 RAM 动态）
net.core.rmem_max = $MAX_BUF
net.core.wmem_max = $MAX_BUF
net.ipv4.tcp_rmem = 4096 87380 $MAX_BUF
net.ipv4.tcp_wmem = 4096 65536 $MAX_BUF

# 队列 & 连接（高并发安全）
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# 探测/收敛核心优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
EOF

# 5. 立即生效 + 模块加载
sudo sysctl -p /etc/sysctl.d/99-grok-adaptive-bbr.conf
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo modprobe tcp_bbr 2>/dev/null || echo "警告：tcp_bbr 模块加载失败（可能需重启或魔改内核）"

# 6. 验证 & RTNETLINK 排查
echo "=== 验证结果 ==="
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.rmem_max
lsmod | grep bbr || echo "BBR 未加载（建议重启或安装魔改）"
ss -mtnp | head -n 10
echo "若出现 RTNETLINK 错误，请检查：ip addr / ip route / netplan apply"

echo "=== 优化完成！自适应缓冲 = $MAX_BUF 字节 ==="
echo "建议：iperf3 -c <目标> -t 30 -P 4  测试收敛速度"
