#!/bin/bash
# =============================================
# 强制切换最简洁官方内核 + 1Gbps CAKE 加速
# 自动检测版本并强制 GRUB 默认新内核
# =============================================

echo "=== 开始强制切换到最简洁官方内核 + 加速 ==="

# 1. 备份
cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d) 2>/dev/null
echo "✅ 已备份配置"

# 2. 检测 Ubuntu 版本并安装对应 HWE 内核（最简洁官方版）
VERSION=$(lsb_release -sr)
echo "检测到系统版本: Ubuntu $VERSION"

if [ "${VERSION%%.*}" -ge 22 ]; then
    HWE_PKG="linux-generic-hwe-$VERSION"
else
    HWE_PKG="linux-generic-hwe-$(lsb_release -sr)"
fi

echo "正在安装最简洁官方 HWE 内核: $HWE_PKG ..."
apt update -qq
apt install -y $HWE_PKG

# 3. 清理旧内核（保留最新2个）
echo "清理多余旧内核..."
apt autoremove --purge -y
dpkg -l | grep linux-image | awk '{print $2}' | grep -v $(uname -r) | head -n -2 | xargs -r apt purge -y 2>/dev/null
update-grub

# 4. 强制设置 GRUB 默认启动新内核
echo "正在强制设置 GRUB 默认新内核..."
sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub
sed -i 's/#GRUB_SAVEDEFAULT=true/GRUB_SAVEDEFAULT=true/' /etc/default/grub
update-grub

# 5. 写入 CAKE + BBR 加速参数
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

# 6. 设置 CAKE 接口
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -n "$INTERFACE" ]; then
    tc qdisc replace dev $INTERFACE root cake bandwidth 1Gbit flows 2048 dual-srchost nat wash 2>/dev/null || true
    echo "✅ 已为 $INTERFACE 设置 CAKE"
fi

# 验证
echo ""
echo "=== 当前状态 ==="
echo "当前内核: $(uname -r)"
echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "qdisc: $(sysctl -n net.core.default_qdisc)"

echo ""
echo "🎉 配置完成！"
echo "【重要】请立即执行：reboot"
echo "重启后用 uname -r 检查是否已是新内核（版本号更高）"
echo "如果还是旧内核，按 ESC 或 Shift 进入 GRUB 菜单手动选最新内核"
