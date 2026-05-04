#!/bin/bash
set -e
echo "=== pf-kernel 自适应高网络编译（trojan-go 优化版） ==="

# 1. 安装依赖
if command -v apt >/dev/null; then
    sudo apt update && sudo apt install -y git build-essential bc bison flex libssl-dev libelf-dev dwarves pahole
elif command -v yum >/dev/null; then
    sudo yum groupinstall -y "Development Tools" && sudo yum install -y git bc bison flex openssl-devel elfutils-libelf-devel dwarves
elif command -v apk >/dev/null; then
    sudo apk add git build-base bc bison flex linux-headers openssl-dev elfutils-dev pahole
fi

# 2. 下载最新 pf-kernel（pf-7.0 系列）
cd /usr/src
sudo rm -rf linux-pf
git clone --depth 1 https://codeberg.org/pf-kernel/linux.git -b pf-7.0 linux-pf
cd linux-pf

# 3. 自适应配置（核心）
echo "正在生成自适应配置..."
make localmodconfig   # 只保留当前系统已加载模块

# 关键高网络 + 极简优化（自动注入）
scripts/config -e CONFIG_TCP_CONG_BBR
scripts/config --set-str CONFIG_DEFAULT_TCP_CONG bbr
scripts/config -e CONFIG_NET_SCH_FQ
scripts/config -e CONFIG_NET_SCH_FQ_CODEL
scripts/config -e CONFIG_HIGH_RES_TIMERS
scripts/config -d CONFIG_DEBUG_INFO
scripts/config -d CONFIG_DEBUG_KERNEL
scripts/config --set-val CONFIG_HZ 300
scripts/config --set-val CONFIG_PREEMPT_LAZY 1
scripts/config --set-val CONFIG_PREEMPT none
scripts/config --set-val CONFIG_X86_64_ISA_LEVEL 3   # 大部分现代CPU用3
scripts/config -d CONFIG_PREEMPT_RT
scripts/config -d CONFIG_RSEQ_SLICE_EXTENSION
scripts/config -d CONFIG_RSEQ_STATS
scripts/config -d CONFIG_RSEQ_DEBUG_DEFAULT_ENABLE
scripts/config -d CONFIG_KALLSYMS_SELFTEST
scripts/config -d CONFIG_CACHESTAT_SYSCALL
scripts/config -d CONFIG_MICROCODE_DBG
scripts/config -d CONFIG_X86_USER_SHADOW_STACK
scripts/config -d CONFIG_BASE_SMALL
scripts/config -d CONFIG_IO_URING_MOCK_FILE
scripts/config -d CONFIG_CRASH_HOTPLUG
# 砍掉大部分 legacy 和 debug
scripts/config -d CONFIG_*_V1
scripts/config -d CONFIG_*DEBUG*
scripts/config -d CONFIG_*TEST*

echo "配置完成，开始编译（这会花 10-40 分钟，取决于你的CPU）..."

# 4. 编译安装
make -j$(nproc) bzImage modules
sudo make modules_install install

# 5. 自动配置 BBR
sudo mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-highnet.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_slow_start_after_idle=0
net.core.somaxconn=8192
net.core.netdev_max_backlog=16384
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF
sudo sysctl -p /etc/sysctl.d/99-highnet.conf

echo "=== 安装完成！请重启 ==="
echo "重启后验证命令："
echo "uname -r | grep pf"
echo "sysctl net.ipv4.tcp_congestion_control"
echo "iperf3 -c 测试IP -t 30 -P 4"
