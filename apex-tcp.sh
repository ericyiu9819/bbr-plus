#!/bin/bash
# =============================================
# 一键 TCP 优化脚本 - 1Gbps CAKE 版
# =============================================

echo "=== 开始为 1Gbps 带宽安装 CAKE 优化 ==="

# 备份
cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null
echo "✅ 已备份原配置"

# 写入优化参数（CAKE 版）
cat >> /etc/sysctl.conf << 'EOF'

# ==================== 1Gbps BBR v3 + CAKE 收敛加速 ====================
# 核心：加快带宽探测与收敛
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_fastopen = 3

# 缓冲区（1Gbps 最佳）
net.core.rmem_max = 167772160
net.core.wmem_max = 167772160
net.ipv4.tcp_rmem = 4096 87380 167772160
net.ipv4.tcp_wmem = 4096 65536 167772160

# === CAKE 核心设置 ===
net.core.default_qdisc = cake

# CAKE 辅助参数
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 65535

# 其他优化
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_tw_reuse = 1
EOF

# 立即生效
sysctl -p >/dev/null 2>&1
echo "✅ sysctl 参数已加载"

# 额外推荐：手动设置 CAKE 带宽限制（效果更好）
echo ""
echo "正在尝试设置 CAKE 带宽参数..."
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -n "$INTERFACE" ]; then
    tc qdisc replace dev $INTERFACE root cake bandwidth 1Gbit flows 2048 dual-srchost nat wash
    echo "✅ 已为接口 $INTERFACE 设置 CAKE (1Gbit)"
else
    echo "⚠️  未检测到默认接口，请手动执行下面命令："
    echo "   tc qdisc replace dev eth0 root cake bandwidth 1Gbit flows 2048 dual-srchost nat wash"
fi

# 验证显示
echo ""
echo "=== 当前关键参数验证 ==="
echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "qdisc: $(sysctl -n net.core.default_qdisc)"
echo "tcp_rmem_max: $(sysctl -n net.core.rmem_max)"
echo "tcp_slow_start_after_idle: $(sysctl -n net.ipv4.tcp_slow_start_after_idle)"
echo "tcp_fastopen: $(sysctl -n net.ipv4.tcp_fastopen)"

echo ""
echo "🎉 CAKE 优化完成！"
echo "建议操作："
echo "1. 重启 VPS：reboot"
echo "2. 重启后用 speedtest-cli 或 iperf3 测试收敛速度"
echo "3. 如有问题恢复备份：mv /etc/sysctl.conf.bak.* /etc/sysctl.conf && sysctl -p"
