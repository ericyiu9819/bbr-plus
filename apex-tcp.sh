#!/bin/bash
# VPS 网络自适应实时优化脚本 v2.0
# 功能：自动识别现有内核参数 + 智能 BBR 判断 + 内存自适应缓冲区 + 详细前后对比
# 适用于 Ubuntu/Debian/CentOS/AlmaLinux/Rocky 等 KVM VPS

echo "=== VPS 网络内核参数自适应优化 v2.0 开始 ==="

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

# 当前拥塞控制算法
CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
AVAILABLE_CC=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "unknown")
echo "  当前拥塞控制：$CURRENT_CC"
echo "  可用拥塞控制：$AVAILABLE_CC"

# 当前缓冲区大小（用于自适应参考）
CURRENT_RMEM_MAX=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
CURRENT_WMEM_MAX=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)
echo "  当前 rmem_max：$CURRENT_RMEM_MAX bytes"
echo "  当前 wmem_max：$CURRENT_WMEM_MAX bytes"

# ==================== 步骤3：尝试加载并判断 BBR 支持 ====================
BBR_AVAILABLE=0
if modprobe -q tcp_bbr 2>/dev/null; then
    echo "tcp_bbr 模块加载成功"
    mkdir -p /etc/modules-load.d
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true
    if echo "$AVAILABLE_CC" | grep -q "bbr" || sysctl -n net.ipv4.tcp_available_congestion_control | grep -q "bbr"; then
        BBR_AVAILABLE=1
        echo "✓ BBR 已可用，将优先启用"
    fi
else
    echo "⚠ 当前内核不支持 BBR 模块（或未编译），将保留原有拥塞控制算法"
fi

# ==================== 步骤4：自适应缓冲区计算 ====================
if [ "$MEM_GB" -ge 16 ]; then
    MAX_BUF=134217728     # 128MB
    DEF_BUF=524288        # 512KB
elif [ "$MEM_GB" -ge 8 ]; then
    MAX_BUF=67108864      # 64MB
    DEF_BUF=262144        # 256KB
elif [ "$MEM_GB" -ge 4 ]; then
    MAX_BUF=33554432      # 32MB
    DEF_BUF=131072        # 128KB
else
    MAX_BUF=16777216      # 16MB（低配安全值）
    DEF_BUF=87380
fi

# 如果当前缓冲区已经更大，则保留当前值（避免降低性能）
if [ "$CURRENT_RMEM_MAX" -gt "$MAX_BUF" ]; then
    MAX_BUF=$CURRENT_RMEM_MAX
fi
if [ "$CURRENT_WMEM_MAX" -gt "$MAX_BUF" ]; then
    MAX_BUF=$CURRENT_WMEM_MAX
fi

echo "自适应缓冲区设定：rmem/wmem_max = $MAX_BUF bytes"

# ==================== 步骤5：生成并应用优化配置 ====================
cat > /etc/sysctl.d/99-vps-optimize-v2.conf << 'EOF'
# === 自适应网络优化配置 v2.0（基于当前内核自动识别）===

# 1. 拥塞控制（智能选择）
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 2. 自适应 TCP 缓冲区
net.core.rmem_max = MAX_BUF_PLACEHOLDER
net.core.wmem_max = MAX_BUF_PLACEHOLDER
net.core.rmem_default = DEF_BUF_PLACEHOLDER
net.core.wmem_default = DEF_BUF_PLACEHOLDER
net.ipv4.tcp_rmem = 4096 DEF_BUF_PLACEHOLDER MAX_BUF_PLACEHOLDER
net.ipv4.tcp_wmem = 4096 DEF_BUF_PLACEHOLDER MAX_BUF_PLACEHOLDER
net.ipv4.tcp_moderate_rcvbuf = 1

# 3. 连接队列与高并发优化
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000

# 4. TIME_WAIT 与短连接优化
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300

# 5. 其他性能增强
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_syncookies = 1

# 6. 系统文件描述符提升
fs.file-max = 2097152
EOF

# 替换占位符为实际自适应数值（因为 Here Document 用 'EOF' 防止提前展开）
sed -i "s/MAX_BUF_PLACEHOLDER/$MAX_BUF/g" /etc/sysctl.d/99-vps-optimize-v2.conf
sed -i "s/DEF_BUF_PLACEHOLDER/$DEF_BUF/g" /etc/sysctl.d/99-vps-optimize-v2.conf

# 如果 BBR 不可用，则恢复为当前拥塞控制算法
if [ "$BBR_AVAILABLE" -eq 0 ]; then
    sed -i "s/net.ipv4.tcp_congestion_control = bbr/net.ipv4.tcp_congestion_control = $CURRENT_CC/" /etc/sysctl.d/99-vps-optimize-v2.conf
fi

# 立即实时应用
sysctl -p /etc/sysctl.d/99-vps-optimize-v2.conf > /dev/null

# 系统文件描述符额外优化
cat >> /etc/security/limits.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
EOF 2>/dev/null || true

# ==================== 步骤6：显示优化前后对比 ====================
echo ""
echo "=== 优化完成！关键参数前后对比 ==="
echo "拥塞控制     ： $CURRENT_CC  →  $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "rmem_max     ： $CURRENT_RMEM_MAX  →  $(sysctl -n net.core.rmem_max)"
echo "wmem_max     ： $CURRENT_WMEM_MAX  →  $(sysctl -n net.core.wmem_max)"
echo "默认队列     ： fq（已设置）"
echo ""

echo "建议操作："
echo "1. 重启服务器使所有参数完全生效：reboot"
echo "2. 测试效果：mtr 测试路由稳定性、iperf3 或 speedtest-cli 测试速度"
echo "3. 回滚：删除 /etc/sysctl.d/99-vps-optimize-v2.conf 并恢复 $BACKUP_DIR 中的文件，然后执行 sysctl -p"
echo ""
echo "脚本运行完毕！如果需要进一步调整，请把运行后的输出贴给我。"

# 最终验证
lsmod | grep -q bbr && echo "✓ BBR 已加载" || echo "BBR 未加载（正常，如果内核不支持）"
