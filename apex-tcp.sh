#!/bin/bash
# VPS 网络自适应实时优化脚本 v2.1
# 功能：自动识别现有内核参数 + 智能 BBR 判断 + 内存自适应缓冲区 + 详细前后对比
# 已修复 here-document 警告

echo "=== VPS 网络内核参数自适应优化 v2.1 开始 ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "错误：请用 root 或 sudo 执行此脚本！"
    exit 1
fi

# ==================== 步骤1：备份现有配置 ====================
BACKUP_DIR="/root/sysctl_backup_$(date +%F_%H%M)"
mkdir -p "$BACKUP_DIR"
cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/sysctl.d/* "$BACKUP_DIR/" 2>/dev/null || true
echo "已备份原有 sysctl 配置到：$BACKUP_DIR"

# ==================== 步骤2：检测当前内核和网络参数 ====================
KERNEL=$(uname -r)
MEM_TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_GB=$((MEM_TOTAL_KB / 1024 / 1024))

echo "检测信息："
echo "  系统内核：$KERNEL"
echo "  物理内存：${MEM_GB} GB"

CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
AVAILABLE_CC=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "unknown")
echo "  当前拥塞控制：$CURRENT_CC"
echo "  可用拥塞控制：$AVAILABLE_CC"

CURRENT_RMEM_MAX=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
CURRENT_WMEM_MAX=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)
echo "  当前 rmem_max：$CURRENT_RMEM_MAX bytes"
echo "  当前 wmem_max：$CURRENT_WMEM_MAX bytes"

# ==================== 步骤3：BBR 支持检测 ====================
BBR_AVAILABLE=0
if modprobe -q tcp_bbr 2>/dev/null; then
    echo "tcp_bbr 模块加载成功"
    mkdir -p /etc/modules-load.d
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true
    if echo "$AVAILABLE_CC" | grep -q "bbr"; then
        BBR_AVAILABLE=1
        echo "✓ BBR 已可用，将优先启用"
    fi
else
    echo "⚠ 当前内核不支持 BBR 模块，将保留原有拥塞控制算法"
fi

# ==================== 步骤4：自适应缓冲区计算 ====================
if [ "$MEM_GB" -ge 16 ]; then
    MAX_BUF=134217728
    DEF_BUF=524288
elif [ "$MEM_GB" -ge 8 ]; then
    MAX_BUF=67108864
    DEF_BUF=262144
elif [ "$MEM_GB" -ge 4 ]; then
    MAX_BUF=33554432
    DEF_BUF=131072
else
    MAX_BUF=16777216
    DEF_BUF=87380
fi

if [ "$CURRENT_RMEM_MAX" -gt "$MAX_BUF" ]; then
    MAX_BUF=$CURRENT_RMEM_MAX
fi
if [ "$CURRENT_WMEM_MAX" -gt "$MAX_BUF" ]; then
    MAX_BUF=$CURRENT_WMEM_MAX
fi

echo "自适应缓冲区设定：rmem/wmem_max = $MAX_BUF bytes"

# ==================== 步骤5：生成并应用优化配置 ====================
cat > /etc/sysctl.d/99-vps-optimize-v2.conf << 'CONFIG_EOF'
# === 自适应网络优化配置 v2.1 ===

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_max = MAX_BUF_PLACEHOLDER
net.core.wmem_max = MAX_BUF_PLACEHOLDER
net.core.rmem_default = DEF_BUF_PLACEHOLDER
net.core.wmem_default = DEF_BUF_PLACEHOLDER
net.ipv4.tcp_rmem = 4096 DEF_BUF_PLACEHOLDER MAX_BUF_PLACEHOLDER
net.ipv4.tcp_wmem = 4096 DEF_BUF_PLACEHOLDER MAX_BUF_PLACEHOLDER
net.ipv4.tcp_moderate_rcvbuf = 1

net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000

net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300

net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_syncookies = 1

fs.file-max = 2097152
CONFIG_EOF

# 替换占位符
sed -i "s/MAX_BUF_PLACEHOLDER/$MAX_BUF/g" /etc/sysctl.d/99-vps-optimize-v2.conf
sed -i "s/DEF_BUF_PLACEHOLDER/$DEF_BUF/g" /etc/sysctl.d/99-vps-optimize-v2.conf

# 如果 BBR 不可用，恢复原有拥塞控制
if [ "$BBR_AVAILABLE" -eq 0 ]; then
    sed -i "s/net.ipv4.tcp_congestion_control = bbr/net.ipv4.tcp_congestion_control = $CURRENT_CC/" /etc/sysctl.d/99-vps-optimize-v2.conf
fi

# 立即生效
sysctl -p /etc/sysctl.d/99-vps-optimize-v2.conf > /dev/null

# 文件描述符优化（已修复 here-document）
cat >> /etc/security/limits.conf << 'LIMITS_EOF'
* soft nofile 1048576
* hard nofile 1048576
LIMITS_EOF

# ==================== 步骤6：显示结果 ====================
echo ""
echo "=== 优化完成！关键参数前后对比 ==="
echo "拥塞控制     ： $CURRENT_CC  →  $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "rmem_max     ： $CURRENT_RMEM_MAX  →  $(sysctl -n net.core.rmem_max)"
echo "wmem_max     ： $CURRENT_WMEM_MAX  →  $(sysctl -n net.core.wmem_max)"
echo ""

echo "建议："
echo "1. 重启服务器：reboot"
echo "2. 测试效果：mtr、iperf3、speedtest-cli"
echo "3. 回滚：删除 /etc/sysctl.d/99-vps-optimize-v2.conf 并恢复备份文件夹"

lsmod | grep -q bbr && echo "✓ BBR 已加载" || echo "BBR 未加载（正常）"
