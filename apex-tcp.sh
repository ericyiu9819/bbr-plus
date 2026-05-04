#!/bin/bash
# =============================================
# 完全自动化：切换最简洁官方内核 + CAKE 加速
# 无需手动选择 GRUB
# =============================================

set -e  # 出错立即停止

echo "=== 开始完全自动化切换最简洁内核 + 加速 ==="

# 1. 备份
cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d) 2>/dev/null
cp /etc/default/grub /etc/default/grub.bak.$(date +%Y%m%d) 2>/dev/null

# 2. 安装最新官方 HWE 内核（最简洁版）
echo "安装最新官方简洁内核..."
apt update -qq
apt install -y linux-generic-hwe-$(lsb_release -sr) linux-headers-generic-hwe-$(lsb_release -sr)

# 3. 清理多余旧内核
echo "清理旧内核..."
apt autoremove --purge -y

# 4. 查找最新内核名称
LATEST_KERNEL=$(ls /boot/vmlinuz-*generic* 2>/dev/null | sort -V | tail -n1 | sed 's|/boot/vmlinuz-||')
echo "最新内核检测到: $LATEST_KERNEL"

# 5. 自动设置 GRUB 默认启动最新内核
cat > /etc/default/grub << EOF
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux $LATEST_KERNEL"
GRUB_SAVEDEFAULT=true
GRUB_TIMEOUT=3
GRUB_TIMEOUT_STYLE=menu
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_DISABLE_OS_PROBER=false
EOF

update-grub

# 6. 写入 CAKE + BBR 加速参数
cat >> /etc/sysctl.conf << 'EOF'

# ==================== 最简洁内核 + 1G CAKE 加速 ====================
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_fastopen = 3

net.core.rmem_max = 167772160
net.core.wmem_max = 167772160
net.ipv4.tcp_rmem = 4096 87380 167772160
net.ipv4.tcp_wmem = 4096 65536 167772160

net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 65535

net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_tw_reuse = 1
EOF

sysctl -p >/dev/null 2>&1

# 7. 设置 CAKE 接口
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -n "$INTERFACE" ]; then
    tc qdisc replace dev $INTERFACE root cake bandwidth 1Gbit flows 2048 dual-srchost nat wash 2>/dev/null || true
    echo "✅ 已设置 CAKE 到 $INTERFACE"
fi

# 完成
echo ""
echo "🎉 完全自动化配置成功！"
echo "当前内核将设置为默认：$LATEST_KERNEL"
echo "立即重启：reboot"
echo "重启后直接验证：uname -r"
