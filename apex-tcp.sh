#!/bin/bash
set -e
echo "=== pf-kernel 高网络安装（BBRv3） ==="

# 依赖
apt update && apt install -y git build-essential bc bison flex libssl-dev libelf-dev || \
yum install -y git make gcc bc bison flex elfutils-libelf-devel openssl-devel || \
apk add git build-base bc bison flex linux-headers openssl-dev elfutils-dev

# 下载最新 pf（当前 pf-7.0 系列）
cd /usr/src
git clone --depth 1 https://codeberg.org/pf-kernel/linux.git -b pf-7.0
cd linux

# 极简配置（只留当前硬件 + 网络）
make localmodconfig
scripts/config -e CONFIG_TCP_CONG_BBR
scripts/config --set-str CONFIG_DEFAULT_TCP_CONG bbr
# 额外网络优化
scripts/config -e CONFIG_FQ_CODEL
scripts/config -e CONFIG_NET_SCH_FQ

make -j$(nproc) bzImage modules
sudo make modules_install install

echo "内核安装完成，重启后启用 BBR"
cat > /etc/sysctl.d/99-pf-bbr.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_slow_start_after_idle=0
net.core.somaxconn=8192
EOF
sysctl -p /etc/sysctl.d/99-pf-bbr.conf
reboot
