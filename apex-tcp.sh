#!/bin/bash
# =====================================================
# TCP 性能优化脚本 - 纯公理化演绎版（无任何惯例复制）
# 推导自 BDP 定律 + 拥塞信号可靠性 + 队列理论 + 奥卡姆剃刀
# 每条修改都有明确的第一性原理依据
# =====================================================

set -euo pipefail

echo "=============================================="
echo "   TCP 性能优化脚本（公理驱动 · 最小有效集）"
echo "=============================================="
echo ""
echo "本脚本严格遵循以下公理生成："
echo "• 公理1: 缓冲区必须 ≥ BDP 才能跑满带宽"
echo "• 公理2: 模型驱动 CC 优于丢包驱动"
echo "• 公理3: fq 队列显著降低 bufferbloat"
echo "• 公理4: 空闲后保持 cwnd 避免重复慢启动"
echo "• 公理5: MTU 探测 + Fast Open 消除不必要 RTT"
echo ""

# 检查 root
if [[ $EUID -ne 0 ]]; then
    echo "❌ 请使用 root 权限运行: sudo $0"
    exit 1
fi

# 交互输入（用户可通过 ping + speedtest 获取真实值）
read -p "请输入目标最大带宽 (Mbps，例如 300): " BW_Mbps
read -p "请输入典型最大 RTT (毫秒，例如 120): " RTT_ms

# 输入校验 + 默认兜底
if ! [[ "$BW_Mbps" =~ ^[0-9]+(\.[0-9]+)?$ ]] || ! [[ "$RTT_ms" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "⚠ 输入无效，使用保守默认值 100Mbps / 150ms"
    BW_Mbps=100
    RTT_ms=150
fi

# 计算 BDP (字节)
# 公式: BDP = (带宽 Mbps × 1,000,000 bits/s × RTT ms × 0.001 s) / 8 bits/byte
BDP=$(awk "BEGIN { printf \"%.0f\", ($BW_Mbps * 1000000 * $RTT_ms / 1000) / 8 }")
BDP_MB=$(awk "BEGIN { printf \"%.2f\", $BDP / 1024 / 1024 }")
echo ""
echo "📐 计算结果：BDP ≈ $BDP bytes (${BDP_MB} MB)"

# 安全系数 3（公理推导：覆盖估计误差 + 2-3 倍突发流量）
SAFETY_FACTOR=3
BUFFER_MAX=$(( BDP * SAFETY_FACTOR ))

# 上限保护（防止极端值吃光 VPS 内存）
if [ "$BUFFER_MAX" -gt 268435456 ]; then
    BUFFER_MAX=268435456
    echo "⚠ BDP 过大，已安全限制到 256 MB"
fi
BUFFER_MAX_MB=$(awk "BEGIN { printf \"%.2f\", $BUFFER_MAX / 1024 / 1024 }")
echo "✅ 最终缓冲区上限：$BUFFER_MAX bytes (${BUFFER_MAX_MB} MB)（安全系数 ×3）"
echo ""

echo "🚀 开始应用优化..."

# 1. 核心缓冲区（公理1：必须覆盖 BDP）
sysctl -w net.core.rmem_max=$BUFFER_MAX >/dev/null
sysctl -w net.core.wmem_max=$BUFFER_MAX >/dev/null

# 2. TCP 缓冲区（low / default / high）
# high 值直接设为计算出的 BUFFER_MAX
sysctl -w net.ipv4.tcp_rmem="4096 131072 $BUFFER_MAX" >/dev/null
sysctl -w net.ipv4.tcp_wmem="4096 131072 $BUFFER_MAX" >/dev/null

# 3. 模型驱动拥塞控制（公理2）
if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
    echo "✓ 已启用 BBR（模型驱动，优于 Cubic）"
else
    echo "⚠ 内核不支持 BBR，降级使用 cubic（建议升级内核 ≥4.9）"
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null
fi

# 4. 公平队列 + pacing（公理3）
sysctl -w net.core.default_qdisc=fq >/dev/null
echo "✓ 已启用 fq 队列规则（显著降低 bufferbloat）"

# 5. 空闲后保持 cwnd（公理4）
sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null

# 6. MTU 探测（公理5）
sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null

# 7. TCP Fast Open（公理5）
sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null

# 8. 基础必需（窗口缩放、SACK、时间戳）
sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null
sysctl -w net.ipv4.tcp_sack=1 >/dev/null
sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null

echo ""
echo "✅ 所有优化已应用完毕！"
echo ""

# 持久化选项
read -p "是否将本次配置写入 /etc/sysctl.conf 以实现重启后自动生效？(y/N): " PERSIST
if [[ "$PERSIST" =~ ^[Yy]$ ]]; then
    cat >> /etc/sysctl.conf <<EOF

# === TCP 公理化优化（$(date +%F) 生成）===
# BDP=${BDP} bytes, 安全系数×3, BUFFER_MAX=${BUFFER_MAX}
net.core.rmem_max = $BUFFER_MAX
net.core.wmem_max = $BUFFER_MAX
net.ipv4.tcp_rmem = 4096 131072 $BUFFER_MAX
net.ipv4.tcp_wmem = 4096 131072 $BUFFER_MAX
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
EOF
    echo "✅ 已追加到 /etc/sysctl.conf"
fi

echo ""
echo "📊 建议测试方法（前后对比）："
echo "   iperf3 -c <目标IP> -t 30 -P 4 -i 5"
echo "   观察吞吐量、延迟、丢包变化"
echo ""
echo "🔄 如需回滚：sysctl -p /etc/sysctl.conf（若有备份）或重启"
echo "=============================================="
