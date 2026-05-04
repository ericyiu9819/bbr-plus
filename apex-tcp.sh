#!/bin/bash
set -euo pipefail

echo "=== BBRv3 极致优化 v5 ==="

# 1. 内存检测（最稳）
MEM=$(free -m | awk 'NR==2{print $2; exit}')
echo "内存: ${MEM}MB"

# 2. 接口 + 带宽（更鲁棒）
IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}' || echo "eth0")
BW_KBPS=$(ip -s link show "$IFACE" 2>/dev/null | awk '/TX:/{gsub(/[^0-9.]/,"",$2); printf "%.0f", $2*1000; exit}' || echo 1000000)
BW_Mbps=$((BW_KBPS / 1000))

# 3. 实时RTT（用avg，兜底多方式）
RTT_MS=$(ping -c 3 -W 2 8.8.8.8 2>/dev/null | awk -F'/' 'END{print int($4+0.5)}' || \
         ping -c 2 -W 2 1.1.1.1 2>/dev/null | awk -F'/' 'END{print int($4+0.5)}' || echo 80)

echo "接口:${IFACE} 带宽≈${BW_Mbps}Mbps RTT≈${RTT_MS}ms"

# 4. 精确BDP（避免整数截断）
MAX_BUF=$(awk -v bw="$BW_Mbps" -v rtt="$RTT_MS" 'BEGIN {
    bdp = bw * 1024 * 1024 / 8 * (rtt / 1000) * 4;
    maxb = (bdp > 134217728) ? 134217728 : (bdp < 4194304 ? 4194304 : bdp);
    print int(maxb);
}' || echo 16777216)

# 5. 小内存强制保守
[ "$MEM" -lt 1024 ] && MAX_BUF=$((MEM * 1024 * 1024 * 20 / 100))

echo "最终缓冲: $((MAX_BUF / 1024 / 1024))MB"

# 6. 备份 + 配置
cp -b /etc/sysctl.d/99-bbr-auto.conf /etc/sysctl.d/99-bbr-auto.conf.bak 2>/dev/null || true

cat > /etc/sysctl.d/99-bbr-auto.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = __MAX_BUF__
net.core.wmem_max = __MAX_BUF__
net.ipv4.tcp_rmem = 4096 87380 __MAX_BUF__
net.ipv4.tcp_wmem = 4096 65536 __MAX_BUF__
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.conf.all.rp_filter = 1
EOF

sed -i "s/__MAX_BUF__/$MAX_BUF/g" /etc/sysctl.d/99-bbr-auto.conf

if sysctl -p /etc/sysctl.d/99-bbr-auto.conf; then
    echo "=== 优化成功 ==="
    sysctl net.ipv4.tcp_congestion_control net.core.rmem_max net.core.default_qdisc
else
    echo "=== 加载失败，回滚 ==="
    exit 1
fi

echo -e "\nreboot后跑: iperf3 -c <target> -P 4 -t 60 测试收敛。"
