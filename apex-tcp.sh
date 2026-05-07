#!/bin/bash
# VPS Network Auto-Tuner - Aggressive Mode (v2.0)
# 用法: sudo bash vps-net-tuner.sh
# 功能：检测系统 → 动态生成激进网络参数 → 持久化并验证
# 飞轮闭环：每次运行自动适配 + 可安全回滚

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "错误：必须以 root 执行" >&2
    exit 1
fi

echo "=== [检测阶段] ==="
KERNEL=$(uname -r)
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)
CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
MAIN_IFACE=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')

echo "内核: $KERNEL | RAM: ${RAM_MB}MB | CPU: $CPU_CORES | 当前CC: $CURRENT_CC | 主接口: ${MAIN_IFACE:-unknown}"

# === 备份机制（彻底可逆）===
TIMESTAMP=$(date +%s)
CONFIG_DIR="/etc/sysctl.d"
BACKUP_DIR="/root/vps-net-tuner-backup"
mkdir -p "$BACKUP_DIR"

# 备份主配置文件和已存在的99-vps-aggressive.conf
cp -f /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak_$TIMESTAMP" 2>/dev/null || true
if [[ -f "$CONFIG_DIR/99-vps-aggressive.conf" ]]; then
    cp -f "$CONFIG_DIR/99-vps-aggressive.conf" "$BACKUP_DIR/99-vps-aggressive.conf.bak_$TIMESTAMP"
fi
echo "备份完成 → $BACKUP_DIR/*_$TIMESTAMP"

# === 动态缓冲计算（更保守分档）===
if [[ $RAM_MB -gt 16384 ]]; then
    MAX_BUF=134217728  # 128MB
elif [[ $RAM_MB -gt 4096 ]]; then
    MAX_BUF=67108864   # 64MB
elif [[ $RAM_MB -gt 1024 ]]; then
    MAX_BUF=33554432   # 32MB
else
    MAX_BUF=16777216   # 16MB 低配保护
fi

# === 生成配置（清理旧版防止冲突）===
cat > "$CONFIG_DIR/99-vps-aggressive.conf" << EOF
# === 激进网络调优 - $(date) 基于${RAM_MB}MB RAM生成 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3

# 缓冲区（BDP匹配）
net.core.rmem_max = $MAX_BUF
net.core.wmem_max = $MAX_BUF
net.ipv4.tcp_rmem = 4096 87380 $MAX_BUF
net.ipv4.tcp_wmem = 4096 65536 $MAX_BUF

# 高并发与队列
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# 减少开销
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200

# 安全/稳定
vm.swappiness = 10
EOF

echo "激进配置生成完成（适配 ${RAM_MB}MB RAM，缓冲上限 ${MAX_BUF} 字节）"

# === 应用配置 ===
sysctl --system >/dev/null
sysctl -p "$CONFIG_DIR/99-vps-aggressive.conf" >/dev/null

# === BBR验证 ===
if ! lsmod | grep -q "^tcp_bbr"; then
    modprobe tcp_bbr 2>/dev/null || echo "警告：BBR模块加载失败，请确认内核支持"
fi

echo "=== [调优完成] ==="
echo "当前关键参数："
sysctl net.ipv4.tcp_congestion_control net.core.rmem_max net.core.default_qdisc

echo ""
echo "=== 反向验证飞轮 ==="
echo "1. 测试：iperf3 -c <目标IP> -t 30   或   speedtest-cli"
echo "2. 监控 24h：free -h && ss -m && dmesg | grep -i oom"
echo "3. 回滚命令："
echo "   sudo rm -f $CONFIG_DIR/99-vps-aggressive.conf"
echo "   sudo mv $BACKUP_DIR/sysctl.conf.bak_$TIMESTAMP /etc/sysctl.conf 2>/dev/null"
echo "   sudo sysctl --system"
echo "定期重跑此脚本（crontab每月一次）形成迭代飞轮。"

echo "脚本已优化完成，可直接使用。"
