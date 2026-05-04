#!/bin/bash
# =============================================
# 一键脚本：最简洁内核 + 1Gbps CAKE 加速 + 清理旧内核
# 适用于 Ubuntu/Debian VPS
# =============================================

echo "=== 开始执行：简洁内核 + 加速优化 + 清理 ==="

# 1. 备份当前配置
cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null
echo "✅ 已备份 sysctl 配置"

# 2. 安装最简洁的官方 LTS 内核
echo "正在安装最简洁的官方 LTS 主线内核..."
apt update -qq
apt install -y linux-image-generic-hwe-$(lsb_release -sr) linux-headers-generic-hwe-$(lsb_release -sr)

# 3. 清理多余旧内核（保留最新2个）
echo "正在清理多余旧内核..."
apt autoremove --purge -y
dpkg -l | grep linux-image | awk '/^ii/ {print $2}' | grep -v $(uname -r) | head -n -2 | xargs -r apt purge -y
update-grub

# 4. 写入完整加速参数（1Gbps CAKE 版）
cat >> /etc/sysctl.conf << 'EOF'

# ==================== 最简洁内核下的 1Gbps 加速配置 ====================
# BBR v3 收敛加速
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_fastopen = 3

# 1Gbps 缓冲区优化
net.core.rmem_max = 167772160
net.core.wmem_max = 167772160
net.ipv4.tcp_rmem = 4096 87380 167772160
net.ipv4.tcp_wmem = 4096 65536 167772160

# 队列与连接优化
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 65535

# 其他稳定优化
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_tw_reuse = 1
EOF

# 5. 立即生效
sysctl -p >/dev/null 2>&1

# 6. 设置 CAKE 实时参数
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -n "$INTERFACE" ]; then
    tc qdisc replace dev $INTERFACE root cake bandwidth 1Gbit flows 2048 dual-srchost nat wash 2>/dev/null
    echo "✅ 已为 $INTERFACE 设置 CAKE"
fi

# 验证
echo ""
echo "=== 配置完成验证 ==="
echo "内核版本: $(uname -r)"
echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "qdisc: $(sysctl -n net.core.default_qdisc)"
echo "rmem_max: $(sysctl -n net.core.rmem_max)"

echo ""
echo "🎉 全部完成！"
echo "建议立即重启：reboot"
echo "重启后用 speedtest-cli 测试效果"
echo "如需恢复：mv /etc/sysctl.conf.bak.* /etc/sysctl.conf && sysctl -p"
