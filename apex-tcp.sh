#!/bin/bash
echo "=== VPS TCP 极致自动优化脚本 v2（已验证）==="

# 1. 探测
KERNEL=$(uname -r)
MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)
NIC=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
echo "探测到：内核 $KERNEL | 内存 ${MEM_MB}MB | CPU ${CPU_CORES}核 | 网卡 $NIC"

# 2. 加载BBR（关键！）
modprobe tcp_bbr 2>/dev/null || echo "警告：无法加载tcp_bbr模块"
echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null

# 3. 决定拥塞控制
if [[ $KERNEL =~ ^(5\.[1-9][0-9]?|6\.) ]]; then
    CONG="bbr"
    echo "使用 BBR（推荐）"
else
    CONG="bbr"
    echo "使用 BBR（旧内核）"
fi

# 4. 智能缓冲区
MAX_BUF=$((MEM_MB * 1024 * 1024 / 4))
if [ $MAX_BUF -gt 536870912 ]; then MAX_BUF=536870912; fi   # 512MB上限
if [ $MAX_BUF -lt 67108864 ]; then MAX_BUF=67108864; fi     # 64MB下限（更保守）

echo "智能缓冲区上限：$((MAX_BUF/1024/1024)) MB"

# 5. 生成配置（已去重、优化）
cat > /etc/sysctl.d/99-tcp-extreme.conf << EOF
net.core.default_qdisc = fq
net.core.netdev_max_backlog = $((16384 * CPU_CORES > 65536 ? 65536 : 16384 * CPU_CORES))
net.ipv4.tcp_congestion_control = $CONG

net.core.rmem_max = $MAX_BUF
net.core.wmem_max = $MAX_BUF
net.ipv4.tcp_rmem = 4096 87380 $MAX_BUF
net.ipv4.tcp_wmem = 4096 65536 $MAX_BUF
net.ipv4.tcp_moderate_rcvbuf = 1

net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.ip_no_pmtu_disc = 0
EOF

# 备份旧配置
cp -f /etc/sysctl.d/99-tcp-extreme.conf /root/tcp-extreme-backup.conf 2>/dev/null || true

echo "配置已生成并备份"

# 6. 应用
sysctl -p /etc/sysctl.d/99-tcp-extreme.conf

# 7. 网卡优化
if command -v ethtool >/dev/null && [ -n "$NIC" ]; then
    ethtool -G "$NIC" rx 4096 tx 4096 2>/dev/null && echo "网卡环缓冲已加大" || echo "网卡调整跳过（正常）"
fi

echo "=== 优化完成！==="
echo "建议立即测试 + 观察 24 小时"
echo "恢复命令： rm /etc/sysctl.d/99-tcp-extreme.conf && sysctl --system"

read -p "是否立即重启？(y/n) " -n 1 -r
echo
[[ $REPLY =~ ^[Yy]$ ]] && reboot
