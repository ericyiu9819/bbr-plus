#!/bin/bash
set -e
echo "=== XanMod 高网络内核 一键安装（trojan-go 优化） ==="

# 1. 添加 XanMod 官方源
wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /etc/apt/keyrings/xanmod-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/xanmod.list

# 2. 安装内核（x64v3 最适合现代 VPS）
sudo apt update
sudo apt install -y linux-xanmod-x64v3 linux-headers-xanmod-x64v3

# 3. 网络优化配置（BBRv3 + 高并发）
cat > /etc/sysctl.d/99-xanmod-net.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_slow_start_after_idle=0
net.core.somaxconn=8192
net.core.netdev_max_backlog=16384
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF

sudo sysctl -p /etc/sysctl.d/99-xanmod-net.conf

echo "=== 安装完成！请执行 reboot 重启 ==="
echo "重启后验证命令："
echo "uname -r | grep xanmod"
echo "sysctl net.ipv4.tcp_congestion_control"
