#!/usr/bin/env bash
set -euo pipefail

NAME="vps-tcp-xray"
CONF="/etc/sysctl.d/99-${NAME}.conf"
STATE_DIR="/var/lib/${NAME}"
STATE="${STATE_DIR}/state"
LOG="/var/log/${NAME}.log"
MONITOR="/usr/local/bin/${NAME}-monitor"
SERVICE="/etc/systemd/system/${NAME}.service"
TIMER="/etc/systemd/system/${NAME}.timer"

TARGET="${TARGET:-1.1.1.1}"
INTERVAL="${INTERVAL:-5min}"
MODE="${MODE:-aggressive}"   # safe | aggressive

MiB=$((1024 * 1024))
MIN_BUF=$((32 * MiB))
MID_BUF=$((128 * MiB))
HIGH_BUF=$((256 * MiB))
MAX_BUF=$((512 * MiB))

log() {
    echo "[$(date '+%F %T')] $*" | tee -a "$LOG"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_root() {
    [[ "${EUID}" -eq 0 ]] || die "run as root"
}

detect_iface() {
    ip route get "$TARGET" 2>/dev/null | awk '
        /dev/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "dev") {
                    print $(i + 1)
                    exit
                }
            }
        }
    '
}

detect_cc() {
    modprobe tcp_bbr 2>/dev/null || true

    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        echo "bbr"
    else
        echo "cubic"
    fi
}

detect_qdisc() {
    local cc="$1"

    if [[ "$cc" == "bbr" ]]; then
        echo "fq"
    else
        echo "fq_codel"
    fi
}

detect_mem_buf() {
    local mem_mb
    mem_mb="$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)"

    if (( mem_mb <= 1024 )); then
        echo "$MIN_BUF"
    elif (( mem_mb <= 4096 )); then
        echo "$MID_BUF"
    elif (( mem_mb <= 16384 )); then
        echo "$HIGH_BUF"
    else
        echo "$MAX_BUF"
    fi
}

write_sysctl() {
    local cc="$1"
    local qdisc="$2"
    local buf="$3"

    cat > "$CONF" <<EOF
# Managed by ${NAME}

net.core.default_qdisc = ${qdisc}
net.ipv4.tcp_congestion_control = ${cc}

net.core.rmem_max = ${buf}
net.core.wmem_max = ${buf}
net.ipv4.tcp_rmem = 4096 87380 ${buf}
net.ipv4.tcp_wmem = 4096 65536 ${buf}

net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 3

net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 32768

net.ipv4.ip_local_port_range = 10240 65535

net.ipv4.tcp_ecn = 1
net.ipv4.tcp_no_metrics_save = 0
EOF

    if [[ "$MODE" == "aggressive" ]]; then
        cat >> "$CONF" <<EOF

# Mildly aggressive, but still bounded.
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_reordering = 15
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fin_timeout = 15
EOF
    fi

    sysctl --system >/dev/null 2>&1 || log "warning: some sysctl values may not be supported by this kernel"
}

tune_limits() {
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d /etc/security/limits.d

    cat > "/etc/systemd/system.conf.d/99-${NAME}-limits.conf" <<EOF
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF

    cat > "/etc/systemd/user.conf.d/99-${NAME}-limits.conf" <<EOF
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF

    cat > "/etc/security/limits.d/99-${NAME}.conf" <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
}

tune_nic() {
    local iface="$1"

    [[ -n "$iface" ]] || return 0
    command -v ethtool >/dev/null 2>&1 || return 0

    ethtool -K "$iface" tso on gso on gro on 2>/dev/null || true
    ethtool -G "$iface" rx 4096 tx 4096 2>/dev/null || true
}

install_monitor() {
    cat > "$MONITOR" <<'MONITOR_EOF'
#!/usr/bin/env bash
set -euo pipefail

NAME="vps-tcp-xray"
STATE_DIR="/var/lib/${NAME}"
STATE="${STATE_DIR}/state"
LOG="/var/log/${NAME}.log"

TARGET="${TARGET:-1.1.1.1}"

MiB=$((1024 * 1024))
MIN_BUF=$((32 * MiB))
MAX_BUF=$((512 * MiB))

log() {
    echo "[$(date '+%F %T')] $*" >> "$LOG"
}

clamp_buf() {
    local v="$1"

    (( v < MIN_BUF )) && v="$MIN_BUF"
    (( v > MAX_BUF )) && v="$MAX_BUF"

    echo "$v"
}

safe_int() {
    local v="${1:-0}"

    if [[ "$v" =~ ^[0-9]+$ ]]; then
        echo "$v"
    else
        echo 0
    fi
}

get_rtt_loss() {
    local out rtt loss

    out="$(ping -c 10 -W 2 "$TARGET" 2>/dev/null || true)"

    loss="$(echo "$out" | awk -F',' '/packet loss/ {
        gsub(/% packet loss/, "", $3)
        gsub(/ /, "", $3)
        print int($3)
    }')"

    rtt="$(echo "$out" | awk -F'/' '/rtt|round-trip/ {
        print int($5)
    }')"

    rtt="$(safe_int "$rtt")"
    loss="$(safe_int "$loss")"

    if [[ "$rtt" -eq 0 && "$loss" -eq 0 && -z "$out" ]]; then
        rtt=999
        loss=100
    fi

    echo "$rtt $loss"
}

get_nstat_value() {
    local key="$1"
    local value

    value="$(nstat -az "$key" 2>/dev/null | awk -v k="$key" '$1 == k {print int($2)}')"
    safe_int "$value"
}

get_sysctl_value() {
    local key="$1"
    local fallback="$2"
    local value

    value="$(sysctl -n "$key" 2>/dev/null || true)"
    safe_int "${value:-$fallback}"
}

apply_buf_only() {
    local buf="$1"

    sysctl -w \
        net.core.rmem_max="$buf" \
        net.core.wmem_max="$buf" \
        net.ipv4.tcp_rmem="4096 87380 $buf" \
        net.ipv4.tcp_wmem="4096 65536 $buf" \
        >/dev/null 2>&1 || log "warning: buffer sysctl apply failed"
}

mkdir -p "$STATE_DIR"

if [[ -f "$STATE" ]]; then
    # shellcheck disable=SC1090
    . "$STATE"
fi

CURRENT_BUF="${CURRENT_BUF:-$(get_sysctl_value net.core.rmem_max $((128 * 1024 * 1024)))}"
BAD_STREAK="${BAD_STREAK:-0}"
GOOD_STREAK="${GOOD_STREAK:-0}"
HIGH_BDP_STREAK="${HIGH_BDP_STREAK:-0}"
LAST_RETRANS="${LAST_RETRANS:-0}"
LAST_LOSS_PROBES="${LAST_LOSS_PROBES:-0}"

CURRENT_BUF="$(safe_int "$CURRENT_BUF")"
BAD_STREAK="$(safe_int "$BAD_STREAK")"
GOOD_STREAK="$(safe_int "$GOOD_STREAK")"
HIGH_BDP_STREAK="$(safe_int "$HIGH_BDP_STREAK")"
LAST_RETRANS="$(safe_int "$LAST_RETRANS")"
LAST_LOSS_PROBES="$(safe_int "$LAST_LOSS_PROBES")"

read -r RTT LOSS < <(get_rtt_loss)

NOW_RETRANS="$(get_nstat_value TcpRetransSegs)"
NOW_LOSS_PROBES="$(get_nstat_value TcpExtTCPLossProbes)"

DELTA_RETRANS=$(( NOW_RETRANS - LAST_RETRANS ))
DELTA_LOSS_PROBES=$(( NOW_LOSS_PROBES - LAST_LOSS_PROBES ))

(( DELTA_RETRANS < 0 )) && DELTA_RETRANS=0
(( DELTA_LOSS_PROBES < 0 )) && DELTA_LOSS_PROBES=0

ACTION="hold"
NEW_BUF="$CURRENT_BUF"

if (( LOSS >= 3 || DELTA_RETRANS >= 300 || DELTA_LOSS_PROBES >= 50 )); then
    BAD_STREAK=$((BAD_STREAK + 1))
    GOOD_STREAK=0
    HIGH_BDP_STREAK=0

    if (( BAD_STREAK >= 2 )); then
        NEW_BUF=$(( CURRENT_BUF * 90 / 100 ))
        NEW_BUF="$(clamp_buf "$NEW_BUF")"
        ACTION="reduce_buffer_congestion_suspected"
        BAD_STREAK=0
    fi

elif (( RTT >= 120 && LOSS <= 1 && DELTA_RETRANS < 80 )); then
    HIGH_BDP_STREAK=$((HIGH_BDP_STREAK + 1))
    BAD_STREAK=0
    GOOD_STREAK=0

    if (( HIGH_BDP_STREAK >= 2 )); then
        NEW_BUF=$(( CURRENT_BUF * 112 / 100 ))
        NEW_BUF="$(clamp_buf "$NEW_BUF")"
        ACTION="increase_buffer_high_bdp_suspected"
        HIGH_BDP_STREAK=0
    fi

elif (( RTT <= 50 && LOSS == 0 && DELTA_RETRANS < 30 )); then
    GOOD_STREAK=$((GOOD_STREAK + 1))
    BAD_STREAK=0
    HIGH_BDP_STREAK=0

    if (( GOOD_STREAK >= 6 )); then
        NEW_BUF=$(( CURRENT_BUF * 96 / 100 ))
        NEW_BUF="$(clamp_buf "$NEW_BUF")"
        ACTION="reduce_buffer_low_bdp"
        GOOD_STREAK=0
    fi

else
    BAD_STREAK=0
    GOOD_STREAK=0
    HIGH_BDP_STREAK=0
fi

if [[ "$NEW_BUF" != "$CURRENT_BUF" ]]; then
    apply_buf_only "$NEW_BUF"
    CURRENT_BUF="$NEW_BUF"
fi

cat > "$STATE" <<STATE_EOF
CURRENT_BUF=${CURRENT_BUF}
BAD_STREAK=${BAD_STREAK}
GOOD_STREAK=${GOOD_STREAK}
HIGH_BDP_STREAK=${HIGH_BDP_STREAK}
LAST_RETRANS=${NOW_RETRANS}
LAST_LOSS_PROBES=${NOW_LOSS_PROBES}
STATE_EOF

CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"

log "target=${TARGET} rtt=${RTT}ms loss=${LOSS}% retrans_delta=${DELTA_RETRANS} loss_probe_delta=${DELTA_LOSS_PROBES} buf=${CURRENT_BUF} cc=${CC} qdisc=${QDISC} action=${ACTION}"
MONITOR_EOF

    chmod +x "$MONITOR"
}

install_systemd() {
    cat > "$SERVICE" <<EOF
[Unit]
Description=VPS TCP Xray Adaptive Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=TARGET=${TARGET}
ExecStart=${MONITOR}
EOF

    cat > "$TIMER" <<EOF
[Unit]
Description=Run VPS TCP Xray Adaptive Monitor

[Timer]
OnBootSec=1min
OnUnitActiveSec=${INTERVAL}
RandomizedDelaySec=30
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${NAME}.timer"
}

backup() {
    mkdir -p "$STATE_DIR/backup"

    cp -a /etc/sysctl.conf "$STATE_DIR/backup/sysctl.conf.$(date +%F-%H%M%S)" 2>/dev/null || true
    cp -a /etc/sysctl.d "$STATE_DIR/backup/sysctl.d.$(date +%F-%H%M%S)" 2>/dev/null || true
    sysctl -a > "$STATE_DIR/backup/sysctl.before.$(date +%F-%H%M%S)" 2>/dev/null || true
}

check_deps() {
    command -v ip >/dev/null 2>&1 || die "missing command: ip"
    command -v ping >/dev/null 2>&1 || die "missing command: ping"
    command -v sysctl >/dev/null 2>&1 || die "missing command: sysctl"
    command -v nstat >/dev/null 2>&1 || die "missing command: nstat"
    command -v systemctl >/dev/null 2>&1 || die "missing command: systemctl"
}

install_all() {
    need_root
    check_deps

    mkdir -p "$STATE_DIR"
    backup

    local cc qdisc buf iface

    cc="$(detect_cc)"
    qdisc="$(detect_qdisc "$cc")"
    buf="$(detect_mem_buf)"
    iface="$(detect_iface || true)"

    write_sysctl "$cc" "$qdisc" "$buf"
    tune_limits
    tune_nic "$iface"

    cat > "$STATE" <<EOF
CURRENT_BUF=${buf}
BAD_STREAK=0
GOOD_STREAK=0
HIGH_BDP_STREAK=0
LAST_RETRANS=0
LAST_LOSS_PROBES=0
EOF

    install_monitor
    install_systemd

    log "installed mode=${MODE} target=${TARGET} interval=${INTERVAL} iface=${iface:-unknown} cc=${cc} qdisc=${qdisc} buf=${buf}"

    echo "Installed ${NAME}."
    echo "Mode: ${MODE}"
    echo "Target: ${TARGET}"
    echo "Interface: ${iface:-unknown}"
    echo "Log: ${LOG}"
}

status_all() {
    echo "=== sysctl ==="
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true
    sysctl net.core.default_qdisc 2>/dev/null || true
    sysctl net.core.rmem_max 2>/dev/null || true
    sysctl net.core.wmem_max 2>/dev/null || true
    sysctl net.ipv4.tcp_rmem 2>/dev/null || true
    sysctl net.ipv4.tcp_wmem 2>/dev/null || true
    sysctl net.ipv4.tcp_fastopen 2>/dev/null || true
    sysctl net.ipv4.tcp_ecn 2>/dev/null || true
    sysctl net.core.somaxconn 2>/dev/null || true
    sysctl net.ipv4.tcp_max_syn_backlog 2>/dev/null || true
    sysctl net.ipv4.ip_local_port_range 2>/dev/null || true

    echo
    echo "=== state ==="
    cat "$STATE" 2>/dev/null || true

    echo
    echo "=== timer ==="
    systemctl status "${NAME}.timer" --no-pager 2>/dev/null || true

    echo
    echo "=== recent log ==="
    tail -n 30 "$LOG" 2>/dev/null || true
}

rollback_all() {
    need_root

    systemctl disable --now "${NAME}.timer" 2>/dev/null || true

    rm -f "$CONF" "$MONITOR" "$SERVICE" "$TIMER"
    rm -f "/etc/systemd/system.conf.d/99-${NAME}-limits.conf"
    rm -f "/etc/systemd/user.conf.d/99-${NAME}-limits.conf"
    rm -f "/etc/security/limits.d/99-${NAME}.conf"

    systemctl daemon-reload
    sysctl --system >/dev/null 2>&1 || true

    echo "Removed ${NAME} configuration."
    echo "Backups are stored in: ${STATE_DIR}/backup"
}

run_once() {
    need_root

    [[ -x "$MONITOR" ]] || die "monitor is not installed. Run: sudo bash $0 install"

    "$MONITOR"
    tail -n 5 "$LOG" 2>/dev/null || true
}

case "${1:-}" in
    install)
        install_all
        ;;
    status)
        status_all
        ;;
    rollback)
        rollback_all
        ;;
    run-once)
        run_once
        ;;
    *)
        cat <<EOF
Usage:
  sudo bash $0 install
  sudo bash $0 status
  sudo bash $0 run-once
  sudo bash $0 rollback

Optional:
  MODE=safe sudo bash $0 install
  MODE=aggressive sudo bash $0 install
  TARGET=8.8.8.8 sudo bash $0 install
  INTERVAL=3min TARGET=1.1.1.1 sudo bash $0 install
EOF
        exit 1
        ;;
esac
