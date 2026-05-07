#!/bin/bash
# SVCC v9.0 - State-Vector Consensus Controller（纯内部交叉协同，从零演绎）
set -euo pipefail

SCRIPT_PATH="/root/svcc-tcp.sh"
LOG="/var/log/svcc-tcp.log"

# 自动部署
if [ "$0" != "$SCRIPT_PATH" ]; then
    echo "[$(date)] SVCC v9.0 自动部署..."
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat "$0" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    pkill -f "svcc-tcp.sh" 2>/dev/null || true
    nohup "$SCRIPT_PATH" > /dev/null 2>&1 &
    echo "✅ SVCC v9.0 已后台启动 → tail -f $LOG"
    exit 0
fi

INTERVAL=90
GAIN=4
MAX_BUF=8388608

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0; }

if [[ $EUID -ne 0 ]]; then log "必须root"; exit 1; fi
log "=== SVCC v9.0 从底层启动 ==="

while true; do
    # 1. 采集最新活跃连接的状态向量（最真实内部数据）
    read -r RTT CWND INFLIGHT SSTHRESH <<< $(ss -tin | awk 'NR>1 {print $3,$5,$7,$9}' | sort -k3 -nr | head -n1)
    RTT=$(safe_int "${RTT:-180}")
    CWND=$(safe_int "${CWND:-16}")
    INFLIGHT=$(safe_int "${INFLIGHT:-0}")
    SSTHRESH=$(safe_int "${SSTHRESH:-65535}")

    MEM_FREE=$(free -m | awk 'NR==2 {print int(($4+$7)/$2*100)}' || echo 50)

    FILL_RATE=$(( INFLIGHT * 100 / (CWND * 1448 + 1) ))
    RTT_HIGH=$(( RTT > 350 ? 1 : 0 ))
    MEM_PRESSURE=$(( MEM_FREE < 28 ? 1 : 0 ))

    log "状态向量: RTT=${RTT} CWND=${CWND} Fill=${FILL_RATE}% MemFree=${MEM_FREE}%"

    # 2. 交叉协同投票（多参数一致性）
    VOTE_UNDERFILL=0
    VOTE_BLOAT=0
    VOTE_MEM=0

    [ $FILL_RATE -lt 58 ] && VOTE_UNDERFILL=1
    [ $RTT_HIGH -eq 1 ] && [ $FILL_RATE -gt 70 ] && VOTE_BLOAT=1
    [ $MEM_PRESSURE -eq 1 ] && VOTE_MEM=1

    # 3. 共识决策（从底层平衡激进与安全）
    if [ $VOTE_MEM -eq 1 ]; then
        GAIN=2
        log "内存压力主导 → 强制保守"
    elif [ $VOTE_BLOAT -eq 1 ]; then
        GAIN=$((GAIN - 1))
        [ $GAIN -lt 2 ] && GAIN=2
        log "bufferbloat共识 → 降低增益"
    elif [ $VOTE_UNDERFILL -eq 1 ]; then
        GAIN=$((GAIN + 1))
        [ $GAIN -gt 9 ] && GAIN=9
        log "管道欠填充共识 → 激进提升"
    else
        GAIN=$((GAIN > 4 ? GAIN - 1 : GAIN))  # 自然收敛
    fi

    MAX_BUF=$(( CWND * 1448 * GAIN + 3145728 ))
    [ $MAX_BUF -gt 16777216 ] && MAX_BUF=16777216
    [ $MAX_BUF -lt 4194304 ] && MAX_BUF=4194304

    # 4. 应用
    cat > /etc/sysctl.d/99-svcc.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-svcc.conf >/dev/null 2>&1

    log "SVCC调整完成: Gain=${GAIN} MaxBuf=${MAX_BUF}"

    sleep $INTERVAL
done
