#!/bin/bash
# ICSC v8.1 - 純內部交叉協同控制器（演繹驗證後優化版）
set -euo pipefail

SCRIPT_PATH="/root/icsc-tcp.sh"
LOG="/var/log/icsc-tcp.log"

if [ "$0" != "$SCRIPT_PATH" ]; then
    echo "[$(date)] ICSC v8.1 自動部署..."
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat "$0" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    pkill -f "icsc-tcp.sh" 2>/dev/null || true
    nohup "$SCRIPT_PATH" > /dev/null 2>&1 &
    echo "✅ ICSC v8.1 已啟動，tail -f $LOG"
    exit 0
fi

INTERVAL=120
GAIN=4
MAX_BUF=8388608

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0; }

if [[ $EUID -ne 0 ]]; then log "必須root"; exit 1; fi
log "=== ICSC v8.1 啟動 ==="

while true; do
    # 改進1：取最活躍連接（bytes sent最多）
    read -r RTT CWND INFLIGHT <<< $(ss -tin | awk 'NR>1 {print $3,$5,$7}' | sort -k3 -nr | head -n1)
    RTT=$(safe_int "${RTT:-180}")
    CWND=$(safe_int "${CWND:-20}")
    INFLIGHT=$(safe_int "${INFLIGHT:-0}")

    MEM_FREE=$(free -m | awk 'NR==2 {print int(($4+$7)/$2*100)}' || echo 50)

    FILL_RATE=$(( INFLIGHT * 100 / (CWND * 1448 + 1) ))
    RTT_HIGH=$(( RTT > 350 ? 1 : 0 ))
    MEM_PRESSURE=$(( MEM_FREE < 30 ? 1 : 0 ))

    log "狀態向量: RTT=${RTT} CWND=${CWND} Fill=${FILL_RATE}% Mem=${MEM_FREE}%"

    # 交叉協同決策
    if [ $MEM_PRESSURE -eq 1 ]; then
        GAIN=2
        log "内存壓力一票否決 → 保守"
    elif [ $RTT_HIGH -eq 1 ] && [ $FILL_RATE -gt 75 ]; then
        GAIN=$((GAIN - 1))
        [ $GAIN -lt 2 ] && GAIN=2
        log "bufferbloat共識 → 降增益"
    elif [ $FILL_RATE -lt 55 ]; then
        GAIN=$((GAIN + 1))
        [ $GAIN -gt 9 ] && GAIN=9
        log "管道欠填充共識 → 激進"
    else
        GAIN=$((GAIN > 4 ? GAIN - 1 : GAIN))   # 緩慢收斂
    fi

    MAX_BUF=$(( CWND * 1448 * GAIN + 4194304 ))
    [ $MAX_BUF -gt 16777216 ] && MAX_BUF=16777216
    [ $MAX_BUF -lt 4194304 ] && MAX_BUF=4194304

    cat > /etc/sysctl.d/99-icsc.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-icsc.conf >/dev/null 2>&1

    log "ICSC調整: Gain=${GAIN} MaxBuf=${MAX_BUF}"

    sleep $INTERVAL
done
