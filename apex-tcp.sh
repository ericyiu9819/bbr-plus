#!/bin/bash
# =====================================================
# TCP 性能优化脚本 - 公理化演绎版（自动分析增强版）
# 推导自：动态网络公理 + 最小工具公理 + 测量保真公理
# 奥卡姆剃刀：只用 ping + curl，零额外依赖
# =====================================================

set -euo pipefail

echo "=============================================="
echo "   TCP 性能优化脚本（公理驱动 · 自动分析版）"
echo "=============================================="
echo ""
echo "本脚本基于以下公理生成："
echo "• 公理1: 网络参数必须实时测量（而非手动输入）"
echo "• 公理2: 只用系统内置工具（ping + curl）"
echo "• 公理3: 测量必须真实（最大RTT + 真实下载测试）"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "❌ 请使用 root 权限运行: sudo $0"
    exit 1
fi

# ==================== 自动分析核心（新增） ====================
echo ""
read -rp "是否启用【自动分析】网络参数？（强烈推荐）[Y/n]: " auto_mode
auto_mode=${auto_mode:-Y}

if [[ "$auto_mode" =~ ^[Yy] ]]; then
    echo ""
    echo "🔍 正在自动分析 RTT（最大往返延迟）..."

    ping_target="223.5.5.5"   # 国内最优，国际用户可改为 8.8.8.8
    max_rtt_str=$(ping -c 5 -W 2 "$ping_target" 2>/dev/null | \
                  grep -o 'time=[0-9.]*' | sed 's/time=//' | sort -n | tail -1)

    if [[ -n "$max_rtt_str" ]]; then
        RTT_ms=$(echo "$max_rtt_str" | awk '{printf "%.0f", $1}')
        echo "✅ 检测到最大 RTT: ${RTT_ms} ms（基于 $ping_target）"
    else
        RTT_ms=150
        echo "⚠️ 无法获取 RTT，使用安全默认值 150 ms"
    fi

    echo ""
    echo "🔍 正在自动分析带宽（真实下载测试，约 3-8 秒）..."

    test_url="http://cachefly.cachefly.net/1mb.test"
    speed_bps=$(curl -o /dev/null -s --max-time 20 -w "%{speed_download}\n" "$test_url" 2>/dev/null || echo "0")

    if [[ "$speed_bps" =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( $(echo "$speed_bps > 10000" | awk '{print ($1>10000)}') )); then
        BW_Mbps=$(echo "$speed_bps * 8 / 1000000" | awk '{printf "%.0f", $1}')
        echo "✅ 检测到下载带宽: ${BW_Mbps} Mbps"
    else
        BW_Mbps=100
        echo "⚠️ 带宽测试失败或过低，使用安全默认值 100 Mbps"
    fi

else
    echo ""
    read -p "请输入目标最大带宽 (Mbps，例如 300): " BW_Mbps
    read -p "请输入典型最大 RTT (毫秒，例如 120): " RTT_ms
fi

# ==================== BDP 计算（保持不变） ====================
echo ""
echo "📐 计算带宽-延迟积 (BDP)..."
BDP=$(awk "BEGIN { printf \"%.0f\", ($BW_Mbps * 1000000 * $RTT_ms / 1000) / 8 }")
BDP_MB=$(awk "BEGIN { printf \"%.2f\", $BDP / 1024 / 1024 }")
echo "✅ BDP ≈ $BDP bytes (${BDP_MB} MB)"

SAFETY=3
BUFFER_MAX=$(( BDP * SAFETY ))
if [ "$BUFFER_MAX" -gt 268435456 ]; then
    BUFFER_MAX=268435456
fi
BUFFER_MAX_MB=$(awk "BEGIN { printf \"%.2f\", $BUFFER_MAX / 1024 / 1024 }")
echo "✅ 最终缓冲区上限: $BUFFER_MAX bytes (${BUFFER_MAX_MB} MB)（安全系数 ×3）"
echo ""

# ==================== 后续优化逻辑（完全不变） ====================
echo "🚀 开始应用优化..."

sysctl -w net.core.rmem_max=$BUFFER_MAX >/dev/null
sysctl -w net.core.wmem_max=$BUFFER_MAX >/dev/null
sysctl -w net.ipv4.tcp_rmem="4096 131072 $BUFFER_MAX" >/dev/null
sysctl -w net.ipv4.tcp_wmem="4096 131072 $BUFFER_MAX" >/dev/null

if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
    echo "✓ 已启用 BBR"
else
    echo "⚠ 内核不支持 BBR，使用 cubic"
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null
fi

sysctl -w net.core.default_qdisc=fq >/dev/null
sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null
sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null
sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null
sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null
sysctl -w net.ipv4.tcp_sack=1 >/dev/null
sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null

echo ""
echo "✅ 所有优化已应用完毕！"

read -rp "是否将配置持久化到 /etc/sysctl.conf？[y/N]: " PERSIST
if [[ "$PERSIST" =~ ^[Yy]$ ]]; then
    cat >> /etc/sysctl.conf <<EOF

# === TCP 公理化优化（自动分析版 - $(date +%F)）===
# 自动检测: BW=${BW_Mbps}Mbps, RTT=${RTT_ms}ms, BDP=${BDP}
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
    echo "✅ 已持久化"
fi

echo ""
echo "📊 建议测试：iperf3 -c <目标IP> -t 30 -P 4"
echo "=============================================="
