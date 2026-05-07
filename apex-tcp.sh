#!/bin/bash
# VPS TCP 自适应优化 v4.0 - 控制论闭环（中国→国外VPS优化）
# 要求: root, 内核>=4.9, 依赖: iperf3 mtr jq bc (自动安装)

set -euo pipefail
LOG="/var/log/tcp-adapt-opt.log"
TEST_HOST="8.8.8.8"   # 改成你的常用目标IP

# 中国优选iperf服务器（优先HK/SG）
IPERF_SERVERS=("speedtest.hkg12.hk.leaseweb.net" "84.17.57.129" "speedtest.sin1.sg.leaseweb.net" "89.187.162.1" "iperf3.moji.fr")

CURRENT_IPERF=""
INTERVAL=600
ALPHA=0.65          # 平滑系数（0.6-0.8激进）
GAIN=3.0            # 当前增益
GAIN_MAX=6.0
STABLE_COUNT=0
STABLE_WIN=4
SMOOTHED_BDP=0
PREV_RTT=200

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "${1}" | sed 's/^0*//' | grep -E '^[0-9]+$' | head -c 10 || echo 0; }

safe_rtt() {
    local raw=$(ping -c 3 -W 2 "$1" 2>/dev/null | tail -n1 | awk -F/ '{print $5}' | tr -dc '0-9')
    safe_int "${raw:-9999}"
}

safe_bw() {
    local json=$(iperf3 -c "$1" -t 5 -J 2>/dev/null || echo '{}')
    local bps=$(echo "$json" | jq -r '.end.sum_sent.bits_per_second // 0')
    safe_int "$((bps / 1000000))"
}

select_best_server() {
    local best=9999 srv_best=""
    for s in "${IPERF_SERVERS[@]}"; do
        local r=$(safe_rtt "$s")
        [ "$r" -lt "$best" ] && best=$r && srv_best=$s
    done
    CURRENT_IPERF=$srv_best
    log "选中服务器: $CURRENT_IPERF (RTT≈${best}ms)"
}

# 自安装依赖
if ! command -v iperf3 >/dev/null; then
    log "安装依赖..."
    if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y iperf3 mtr jq bc;
    elif command -v yum >/dev/null; then yum install -y iperf3 mtr jq bc; fi
fi

if [[ $EUID -ne 0 ]]; then log "必须root"; exit 1; fi
select_best_server

while true; do
    # 1. 测量
    CPU=$(awk '{print $1}' /proc/loadavg)
    MEM_FREE=$(free -m | awk 'NR==2{print int(($4+$7)/$2*100)}' || echo 50)
    RTT=$(safe_rtt "$TEST_HOST")
    LOSS=$(mtr -r -c 6 "$TEST_HOST" 2>/dev/null | tail -1 | awk '{print int($NF)}' || echo 2)
    BW=$(safe_bw "$CURRENT_IPERF")
    [ "$BW" -eq 0 ] && BW=80

    # 2. 计算BDP + 平滑
    BDP=$((10#${BW} * 125 * 10#${RTT} / 1000))
    [ "$SMOOTHED_BDP" -eq 0 ] && SMOOTHED_BDP=$BDP
    SMOOTHED_BDP=$(echo "scale=0; $ALPHA*$BDP + (1-$ALPHA)*$SMOOTHED_BDP" | bc)

    # 3. 稳定性判断 + 激进/阻尼
    CHANGE=0
    [ "$PREV_RTT" -gt 0 ] && CHANGE=$(echo "scale=0; (10#${PREV_RTT}-10#${RTT})*100/10#${PREV_RTT}" | bc)
    if (( LOSS < 2 && CHANGE < 15 && MEM_FREE > 30 && CPU < 1.5 )); then
        STABLE_COUNT=$((STABLE_COUNT+1))
        GAIN=$(echo "scale=2; $GAIN + 0.25" | bc)
        [ $(echo "$GAIN > $GAIN_MAX" | bc) -eq 1 ] && GAIN=$GAIN_MAX
        ALPHA=0.75
    else
        STABLE_COUNT=0
        GAIN=$(echo "scale=2; $GAIN - 0.35" | bc)
        [ $(echo "$GAIN < 3.0" | bc) -eq 1 ] && GAIN=3.0
        ALPHA=0.55
    fi

    MAX_BUF=$(echo "scale=0; $SMOOTHED_BDP * $GAIN" | bc)
    [ "$MAX_BUF" -gt 16777216 ] && MAX_BUF=16777216

    # 4. 收敛锁定
    [ $STABLE_COUNT -ge $STABLE_WIN ] && INTERVAL=3600 && ALPHA=0.4 && log "已收敛 → 稳定模式"

    # 5. 应用参数
    cat > /etc/sysctl.d/99-adapt-tcp.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-adapt-tcp.conf >/dev/null 2>&1
    modprobe tcp_bbr 2>/dev/null || true

    log "状态: RTT=${RTT}ms Loss=${LOSS}% BW=${BW}Mbps Gain=${GAIN} Buf=${MAX_BUF} Interval=${INTERVAL}s"

    # 6. 飞轮验证
    sleep 8
    NEW_RTT=$(safe_rtt "$TEST_HOST")
    [ $((NEW_RTT * 100)) -lt $((RTT * 92)) ] && log "✓ 飞轮正向：延迟改善"

    PREV_RTT=$RTT
    sleep $INTERVAL
done
