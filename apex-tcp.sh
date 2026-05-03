#!/bin/bash
set -e

echo "=============================================="
echo "   CachyOS Server 内核 + 极致激进网络优化"
echo "=============================================="

# 检查是否已安装
if dpkg -l | grep -q linux-cachyos-server; then
    echo "[✓] 检测到已安装 CachyOS Server 内核，跳过安装步骤。"
else
    echo "[1/3] 添加 CachyOS 仓库..."
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://mirror.cachyos.org/cachyos.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/cachyos.gpg
    echo "deb [signed-by=/etc/apt/keyrings/cachyos.gpg] https://mirror.cachyos.org/repo/x86_64/ cachyos main" | sudo tee /etc/apt/sources.list.d/cachyos.list > /dev/null

    echo "[2/3] 安装 CachyOS Server 内核..."
    sudo apt update
    sudo apt install -y linux-cachyos-server linux-headers-cachyos-server
fi

echo "[3/3] 应用极致激进网络优化参数..."

sudo tee /etc/sysctl.d/99-cachyos-aggressive.conf > /dev/null << 'EOF'
# ========== 极致激进网络优化（高延迟线路专用） ==========
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 32768
net.ipv4.tcp_moderate_rcvbuf = 1

# 极致缓冲区（激进版）
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.core.netdev_max_backlog = 10000
EOF

echo "应用 sysctl 配置..."
sudo sysctl -p /etc/sysctl.d/99-cachyos-aggressive.conf

echo ""
echo "正在删除多余旧内核..."
sudo apt autoremove --purge -y

echo ""
echo "=============================================="
echo "           安装完成！"
echo "=============================================="
echo ""
echo "请执行以下命令重启 VPS："
echo "  sudo reboot"
echo ""
echo "重启后验证命令："
echo "  uname -r"
echo "  sysctl net.ipv4.tcp_congestion_control"
echo "  sysctl net.core.rmem_max"
