#!/bin/bash
# =============================================
# 一键 TCP 优化脚本 - 1Gbps 专用版
# 适用于 XanMod + BBR v3，显著加快收敛速度
# =============================================

echo "=== 开始为 1Gbps 带宽优化 TCP 参数 ==="

# 备份
cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null
echo "✅ 已备份原配置"

# 写入优化参数（1Gbps 适配）
cat >> /etc/sysctl.conf << 'EOF'

# ==================== 1Gbps BBR v3 收敛加速 ====================
# 核心：加快带宽探测与收敛
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_fastopen = 3

# 缓冲区（1Gbps 最佳适配）
net.core.rmem_max = 167772160
net.core.wmem_max = 167772160
net.ipv4.tcp_rmem = 4096 87380 167772160
net.ipv4.tcp_wmem = 4096 65536 167772160

# 队列管理（配合 BBR）
net.core.default_qdisc = fq_codel
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 65535

# 辅助优化
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_tw_reuse = 1
EOF

# 立即生效
sysctl -p >/dev/null 2>&1
echo "✅ 参数已加载"

# 验证显示
echo ""
echo "=== 当前关键参数验证 ==="
echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "qdisc: $(sysctl -n net.core.default_qdisc)"
echo "tcp_rmem_max: $(sysctl -n net.core.rmem_max)"
echo "tcp_slow_start_after_idle: $(sysctl -n net.ipv4.tcp_slow_start_after_idle)"
echo "tcp_fastopen: $(sysctl -n net.ipv4.tcp_fastopen)"

echo ""
echo "🎉 1Gbps 优化完成！"
echo "建议操作："
echo "1. 重启 VPS 以获得最佳效果：reboot"
echo "2. 测试收敛速度：speedtest-cli 或 iperf3"
echo "3. 如需恢复：mv /etc/sysctl.conf.bak.* /etc/sysctl.conf && sysctl -p"
