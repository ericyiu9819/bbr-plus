#!/usr/bin/env bash
# ============================================================
#  ATTAS v4.1 – Adaptive TCP Traffic Acceleration System
#  修复: FIX-GHOST(幽灵进程), FIX-HEALTH(health.json), FIX-RTT(测量目标)
#  支持: Ubuntu/Debian/CentOS/RHEL/Fedora/Arch/Alpine/OpenSUSE
#        Amazon Linux/Armbian/Raspbian/Void/Gentoo/Docker/LXC
#  要求: bash 4.0+, Linux kernel 3.10+, root权限
# ============================================================
set -uo pipefail
IFS=$'\n\t'

# ── 常量 ────────────────────────────────────────────────────
readonly VERSION="4.1"
readonly GITHUB_USER="your-username"
readonly GITHUB_REPO="attas"
readonly GITHUB_BRANCH="main"
readonly REMOTE_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/attas.sh"
readonly LOG_FILE="/var/log/attas.log"
readonly CONFIG_DIR="/etc/attas"
readonly CONFIG_FILE="${CONFIG_DIR}/attas.conf"
readonly BASELINE_FILE="${CONFIG_DIR}/baseline.dat"
readonly LEARNED_FILE="${CONFIG_DIR}/learned.dat"
readonly SYSCTL_CONF="/etc/sysctl.d/99-attas.conf"
readonly MODULES_CONF="/etc/modules-load.d/attas.conf"
readonly SERVICE_FILE="/etc/systemd/system/attas.service"
readonly WATCHDOG_FILE="/etc/systemd/system/attas-watchdog.service"
readonly BIN_PATH="/usr/local/bin/attas"
readonly HEALTH_FILE="/tmp/attas_health.json"
readonly LOCK_FILE="/tmp/attas_monitor.lock"        # FIX-GHOST
readonly LOSS_CACHE="/tmp/attas_loss.cache"
readonly LOSS_PID_FILE="/tmp/attas_loss.pid"
readonly MONITOR_INTERVAL=30
readonly RTT_HIGH=150
readonly RTT_LOW=30
readonly LOSS_HIGH=2
readonly LOSS_LOW=1

# ── 颜色 ────────────────────────────────────────────────────
setup_colors() {
  if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
  else
    RED=''; YELLOW=''; GREEN=''; BLUE=''; CYAN=''; BOLD=''; NC=''
  fi
}
setup_colors

# ── 工具函数 ─────────────────────────────────────────────────
log() {
  local msg="$1" level="${2:-INFO}"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  local color="$NC"
  case "$level" in
    OK)    color="$GREEN"  ;;
    WARN)  color="$YELLOW" ;;
    ERROR) color="$RED"    ;;
    INFO)  color="$CYAN"   ;;
  esac
  local line="[${ts}][${level}] ${msg}"
  echo -e "${color}${line}${NC}"
  echo "$line" >> "$LOG_FILE" 2>/dev/null || true
}

die() { log "$1" "ERROR"; exit 1; }

has_cmd() { command -v "$1" &>/dev/null; }

safe_sysctl() {
  local key="$1" val="$2"
  if sysctl -w "${key}=${val}" &>/dev/null; then
    log "sysctl ${key}=${val}" "OK"
    return 0
  else
    log "sysctl ${key} 设置失败（容器限制？）" "WARN"
    return 1
  fi
}

num_gt() {
  local a="$1" b="$2"
  [[ "$a" =~ ^[0-9]+([.][0-9]+)?$ ]] && \
  [[ "$b" =~ ^[0-9]+([.][0-9]+)?$ ]] && \
  (( $(echo "$a > $b" | bc -l 2>/dev/null || echo 0) ))
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$(dirname "$LOG_FILE")" || true
  touch "$LOG_FILE" 2>/dev/null || true
}

# ── 自我落盘检测（FIX-PIPE）────────────────────────────────
ensure_self_on_disk() {
  if [[ ! -f "$0" ]] || [[ "$(basename "$0")" == "bash" ]]; then
    log "检测到管道模式，正在下载脚本..." "WARN"
    local tmp download_ok=false
    tmp=$(mktemp /tmp/attas_XXXXXX.sh)
    if has_cmd curl; then
      curl -sSL "$REMOTE_URL" -o "$tmp" 2>/dev/null && download_ok=true
    fi
    if [[ "$download_ok" == false ]] && has_cmd wget; then
      wget -qO "$tmp" "$REMOTE_URL" 2>/dev/null && download_ok=true
    fi
    if [[ "$download_ok" == true ]]; then
      chmod +x "$tmp"
      exec bash "$tmp" "$@"
    else
      die "下载失败，请手动执行: curl -sSL $REMOTE_URL -o attas.sh && bash attas.sh"
    fi
  fi
}

# ── 权限检查 ──────────────────────────────────────────────
check_root() {
  [[ $EUID -eq 0 ]] || die "请以 root 权限运行: sudo bash $0"
}

# ── 容器检测 ──────────────────────────────────────────────
detect_container() {
  CONTAINER_ENV=false
  if [[ -f /.dockerenv ]] || \
     grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null || \
     [[ "$(systemd-detect-virt 2>/dev/null)" =~ ^(docker|lxc|container) ]]; then
    CONTAINER_ENV=true
    log "检测到容器环境，部分 sysctl 将跳过" "WARN"
  fi
}

# ── OS 检测 ───────────────────────────────────────────────
detect_os() {
  OS_ID="unknown"; OS_FAMILY="unknown"; PKG_MGR="unknown"
  INSTALL_CMD=""; UPDATE_CMD=""

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_FAMILY="${ID_LIKE:-$OS_ID}"
  fi

  if has_cmd apt-get; then
    PKG_MGR="apt"; INSTALL_CMD="apt-get install -y -q"
    UPDATE_CMD="apt-get update -q"
  elif has_cmd dnf; then
    PKG_MGR="dnf"; INSTALL_CMD="dnf install -y -q"
    UPDATE_CMD="dnf check-update -q || true"
  elif has_cmd yum; then
    PKG_MGR="yum"; INSTALL_CMD="yum install -y -q"
    UPDATE_CMD="yum makecache -q"
  elif has_cmd pacman; then
    PKG_MGR="pacman"; INSTALL_CMD="pacman -S --noconfirm --needed"
    UPDATE_CMD="pacman -Sy"
  elif has_cmd apk; then
    PKG_MGR="apk"; INSTALL_CMD="apk add --no-cache"
    UPDATE_CMD="apk update"
  elif has_cmd zypper; then
    PKG_MGR="zypper"; INSTALL_CMD="zypper install -y"
    UPDATE_CMD="zypper refresh"
  elif has_cmd emerge; then
    PKG_MGR="emerge"; INSTALL_CMD="emerge"
    UPDATE_CMD="emerge --sync"
  elif has_cmd xbps-install; then
    PKG_MGR="xbps"; INSTALL_CMD="xbps-install -y"
    UPDATE_CMD="xbps-install -S"
  else
    log "未检测到已知包管理器，依赖安装将跳过" "WARN"
  fi

  log "OS: ${OS_ID} | 包管理器: ${PKG_MGR}" "INFO"
}

# ── Init 系统检测 ─────────────────────────────────────────
detect_init() {
  INIT_SYS="unknown"
  if has_cmd systemctl && systemctl list-units &>/dev/null; then
    INIT_SYS="systemd"
  elif [[ -f /sbin/openrc ]]; then
    INIT_SYS="openrc"
  elif [[ -d /etc/runit ]]; then
    INIT_SYS="runit"
  elif [[ -f /sbin/init ]]; then
    INIT_SYS="sysvinit"
  fi
  log "Init 系统: ${INIT_SYS}" "INFO"
}

# ── 内核与算法检测 ────────────────────────────────────────
detect_kernel() {
  KERNEL_VER=$(uname -r | cut -d'-' -f1)
  KERNEL_MAJOR=$(echo "$KERNEL_VER" | cut -d'.' -f1)
  KERNEL_MINOR=$(echo "$KERNEL_VER" | cut -d'.' -f2)
  log "内核版本: ${KERNEL_VER}" "INFO"

  AVAILABLE_ALGOS=""
  if [[ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]]; then
    AVAILABLE_ALGOS=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)
  fi
  log "可用拥塞控制算法: ${AVAILABLE_ALGOS}" "INFO"
}

# ── 镜像管理 ──────────────────────────────────────────────
test_url() {
  local url="$1" timeout="${2:-5}"
  if has_cmd curl; then
    curl -sS --connect-timeout "$timeout" --max-time "$timeout" \
         -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -qE '^[23]'
  elif has_cmd wget; then
    wget -q --timeout="$timeout" -O /dev/null "$url" 2>/dev/null
  else
    return 1
  fi
}

test_connectivity() {
  log "测试网络连通性..." "INFO"
  local targets=("8.8.8.8" "1.1.1.1" "223.5.5.5")
  for t in "${targets[@]}"; do
    if ping -c 1 -W 3 "$t" &>/dev/null; then
      log "网络连通 (via $t)" "OK"
      return 0
    fi
  done
  log "无法连接外部网络，监控将使用降级默认值" "WARN"
  return 1
}

switch_to_aliyun_mirror() {
  case "$PKG_MGR" in
    apt)
      local src="/etc/apt/sources.list"
      if grep -q "aliyun" "$src" 2>/dev/null; then return 0; fi
      cp "$src" "${src}.attas.bak" 2>/dev/null || true
      sed -i 's|http://.*\.ubuntu\.com|http://mirrors.aliyun.com|g;
              s|http://deb\.debian\.org|http://mirrors.aliyun.com|g' "$src" 2>/dev/null || true
      log "已切换 apt 镜像到阿里云" "OK"
      ;;
    yum|dnf)
      if [[ -f /etc/yum.repos.d/CentOS-Base.repo ]]; then
        sed -i 's|mirror\.centos\.org|mirrors.aliyun.com|g' \
            /etc/yum.repos.d/CentOS-Base.repo 2>/dev/null || true
        log "已切换 yum/dnf 镜像到阿里云" "OK"
      fi
      ;;
  esac
}

check_repo_and_mirror() {
  local test_urls=("https://packages.debian.org" "https://centos.org" "https://archlinux.org")
  local reachable=false
  for url in "${test_urls[@]}"; do
    test_url "$url" 5 && reachable=true && break
  done
  if [[ "$reachable" == false ]]; then
    log "默认仓库不可达，尝试切换阿里云镜像..." "WARN"
    switch_to_aliyun_mirror
    $UPDATE_CMD 2>/dev/null || true
  fi
}

# ── 依赖安装 ──────────────────────────────────────────────
install_pkg() {
  local pkg="$1"
  [[ -z "$INSTALL_CMD" ]] && return 1
  log "安装 ${pkg}..." "INFO"
  $UPDATE_CMD &>/dev/null || true
  # shellcheck disable=SC2086
  $INSTALL_CMD "$pkg" &>/dev/null && log "安装 ${pkg} 成功" "OK" && return 0
  log "安装 ${pkg} 失败" "WARN"
  return 1
}

declare -A DEP_MAP_APT=(
  [ping]="iputils-ping" [curl]="curl" [wget]="wget" [bc]="bc"
  [awk]="gawk" [ss]="iproute2" [ip]="iproute2" [sysctl]="procps"
  [modprobe]="kmod" [ethtool]="ethtool" [tc]="iproute2"
  [netstat]="net-tools" [iostat]="sysstat"
)
declare -A DEP_MAP_YUM=(
  [ping]="iputils" [curl]="curl" [wget]="wget" [bc]="bc"
  [awk]="gawk" [ss]="iproute" [ip]="iproute" [sysctl]="procps-ng"
  [modprobe]="kmod" [ethtool]="ethtool" [tc]="iproute"
  [netstat]="net-tools" [iostat]="sysstat"
)
declare -A DEP_MAP_APK=(
  [ping]="iputils" [curl]="curl" [wget]="wget" [bc]="bc"
  [awk]="gawk" [ss]="iproute2" [ip]="iproute2" [sysctl]="procps"
  [modprobe]="kmod" [ethtool]="ethtool" [tc]="iproute2"
)

check_and_install_cmd() {
  local cmd="$1"
  has_cmd "$cmd" && return 0

  local pkg=""
  case "$PKG_MGR" in
    apt)    pkg="${DEP_MAP_APT[$cmd]:-}" ;;
    yum|dnf) pkg="${DEP_MAP_YUM[$cmd]:-}" ;;
    apk)    pkg="${DEP_MAP_APK[$cmd]:-}" ;;
    pacman) pkg="$cmd" ;;
    *)      pkg="" ;;
  esac

  if [[ -n "$pkg" ]]; then
    install_pkg "$pkg" || log "${cmd} 安装失败，将跳过相关功能" "WARN"
  else
    log "${cmd} 未找到且无法自动安装" "WARN"
  fi
}

run_dependency_check() {
  local deps=(ping curl wget bc awk ss ip sysctl modprobe ethtool tc)
  log "检查依赖项..." "INFO"
  for dep in "${deps[@]}"; do
    check_and_install_cmd "$dep"
  done
  log "依赖检查完成" "OK"
}

# ── 内核模块加载 ──────────────────────────────────────────
load_kernel_modules() {
  local modules=(tcp_bbr tcp_hybla tcp_vegas tcp_cubic sch_fq sch_fq_codel)
  for mod in "${modules[@]}"; do
    modprobe "$mod" 2>/dev/null && log "模块 ${mod} 已加载" "OK" || true
  done
  # 持久化
  if [[ -d /etc/modules-load.d ]]; then
    printf '%s\n' "${modules[@]}" > "$MODULES_CONF" 2>/dev/null || true
  fi
}

# ════════════════════════════════════════════════════════════
#  核心测量函数（FIX-RTT）
# ════════════════════════════════════════════════════════════

# FIX-RTT: 使用多个真实外部目标，取最小有效值，排除本地回环
measure_rtt() {
  local targets=("8.8.8.8" "1.1.1.1" "223.5.5.5" "208.67.222.222" "114.114.114.114")
  local best=9999 count=0

  for target in "${targets[@]}"; do
    local result
    result=$(ping -c 3 -W 2 "$target" 2>/dev/null \
             | grep -E 'rtt|round-trip' \
             | grep -oE '[0-9]+\.[0-9]+/[0-9]+\.[0-9]+' \
             | cut -d'/' -f1 \
             | cut -d'.' -f1)

    # 过滤非法值：必须 >0 且 <2000
    if [[ "$result" =~ ^[0-9]+$ ]] && \
       [[ "$result" -gt 0 ]] && \
       [[ "$result" -lt 2000 ]]; then
      count=$((count + 1))
      [[ "$result" -lt "$best" ]] && best="$result"
    fi
  done

  if [[ $count -eq 0 ]]; then
    log "所有 ping 目标均失败，使用默认 RTT=80ms" "WARN"
    echo 80
  else
    echo "$best"
  fi
}

# FIX-GHOST: 异步丢包测量，5 pings，写缓存文件
start_loss_monitor() {
  # 终止旧的后台测量
  if [[ -f "$LOSS_PID_FILE" ]]; then
    local old_pid; old_pid=$(cat "$LOSS_PID_FILE" 2>/dev/null)
    kill "$old_pid" 2>/dev/null || true
  fi

  (
    while true; do
      local target="8.8.8.8"
      local output; output=$(ping -c 5 -W 2 "$target" 2>/dev/null)
      local loss
      loss=$(echo "$output" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
      echo "${loss:-0}" > "$LOSS_CACHE"
      sleep $((MONITOR_INTERVAL * 2))
    done
  ) &
  echo $! > "$LOSS_PID_FILE"
  log "异步丢包监测已启动 (PID=$(cat $LOSS_PID_FILE))" "INFO"
}

get_loss() {
  local val
  val=$(cat "$LOSS_CACHE" 2>/dev/null)
  if [[ "$val" =~ ^[0-9]+$ ]]; then
    echo "$val"
  else
    echo 0
  fi
}

get_bandwidth_mbps() {
  local iface
  iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
  [[ -z "$iface" ]] && echo 100 && return

  local rx1 rx2
  rx1=$(cat "/sys/class/net/${iface}/statistics/rx_bytes" 2>/dev/null || echo 0)
  sleep 1
  rx2=$(cat "/sys/class/net/${iface}/statistics/rx_bytes" 2>/dev/null || echo 0)
  echo $(( (rx2 - rx1) * 8 / 1000000 ))
}

# ── BDP 动态计算 ───────────────────────────────────────────
calc_bdp_buffer() {
  local rtt_ms="$1" bw_mbps="$2"
  # BDP(bytes) = bandwidth(B/s) × RTT(s) × 1.5(安全系数)
  local bw_bytes=$(( bw_mbps * 1000000 / 8 ))
  local rtt_s_x1000=$(( rtt_ms ))
  local bdp=$(( bw_bytes * rtt_s_x1000 * 3 / 2000 ))

  # 限制在 4MB ~ 256MB
  local min_buf=$(( 4 * 1024 * 1024 ))
  local max_buf=$(( 256 * 1024 * 1024 ))
  [[ $bdp -lt $min_buf ]] && bdp=$min_buf
  [[ $bdp -gt $max_buf ]] && bdp=$max_buf

  echo "$bdp"
}

# ── 评分引擎（BUG-01已修复，elif互斥）─────────────────────
calc_score() {
  local rtt="$1" loss="$2"
  local score=100

  # RTT 评分（elif 互斥，避免多条件叠加）
  if   [[ $rtt -gt 300 ]]; then score=$((score - 50))
  elif [[ $rtt -gt 200 ]]; then score=$((score - 40))
  elif [[ $rtt -gt 150 ]]; then score=$((score - 30))
  elif [[ $rtt -gt 100 ]]; then score=$((score - 20))
  elif [[ $rtt -gt 50  ]]; then score=$((score - 10))
  fi

  # 丢包评分（elif 互斥）
  if   [[ $loss -gt 10 ]]; then score=$((score - 40))
  elif [[ $loss -gt 5  ]]; then score=$((score - 30))
  elif [[ $loss -gt 2  ]]; then score=$((score - 20))
  elif [[ $loss -gt 1  ]]; then score=$((score - 10))
  fi

  # 保底 0
  [[ $score -lt 0 ]] && score=0
  echo "$score"
}

# ── 算法选择 ──────────────────────────────────────────────
select_algo() {
  local score="$1" rtt="$2"

  # 优先选择内核已支持的算法
  local preferred_order=("bbr" "hybla" "cubic" "vegas" "reno")

  # 根据网络状态选择最优算法
  local wanted
  if   [[ $score -ge 80 ]];                        then wanted="bbr"
  elif [[ $score -ge 50 && $rtt -gt $RTT_HIGH ]];  then wanted="hybla"
  elif [[ $score -ge 40 ]];                        then wanted="cubic"
  else                                                   wanted="vegas"
  fi

  # 验证算法可用性
  if echo "$AVAILABLE_ALGOS" | grep -qw "$wanted"; then
    echo "$wanted"
    return
  fi

  # 降级到第一个可用算法
  for algo in "${preferred_order[@]}"; do
    if echo "$AVAILABLE_ALGOS" | grep -qw "$algo"; then
      echo "$algo"
      return
    fi
  done
  echo "cubic"
}

# ── TCP 参数应用（BUG-03已修复，接口检测）─────────────────
apply_sysctl() {
  local algo="$1" score="$2" rtt="$3" bw_mbps="$4"
  local buf; buf=$(calc_bdp_buffer "$rtt" "$bw_mbps")

  log "应用 sysctl: algo=${algo} buf=${buf}B score=${score}" "INFO"

  safe_sysctl "net.ipv4.tcp_congestion_control" "$algo"
  safe_sysctl "net.core.rmem_max"               "$buf"
  safe_sysctl "net.core.wmem_max"               "$buf"
  safe_sysctl "net.ipv4.tcp_rmem"               "4096 87380 ${buf}"
  safe_sysctl "net.ipv4.tcp_wmem"               "4096 65536 ${buf}"
  safe_sysctl "net.ipv4.tcp_fastopen"           "3"
  safe_sysctl "net.ipv4.tcp_max_syn_backlog"    "8192"
  safe_sysctl "net.core.somaxconn"              "8192"
  safe_sysctl "net.ipv4.tcp_slow_start_after_idle" "0"
  safe_sysctl "net.ipv4.tcp_mtu_probing"        "1"

  # BBR 专属：设置 fq 队列调度（BUG-03: 先验证接口存在）
  if [[ "$algo" == "bbr" ]]; then
    safe_sysctl "net.core.default_qdisc" "fq" || \
    safe_sysctl "net.core.default_qdisc" "fq_codel"

    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)

    # FIX-BUG03: 接口名非空 + 接口实际存在
    if [[ -n "$iface" ]] && ip link show "$iface" &>/dev/null; then
      tc qdisc replace dev "$iface" root fq 2>/dev/null && \
        log "tc fq 已应用到接口 ${iface}" "OK" || \
        log "tc fq 应用失败（可能为容器限制）" "WARN"
    else
      log "未找到有效默认接口，跳过 tc qdisc" "WARN"
    fi
  fi
}

# ── 配置持久化 ────────────────────────────────────────────
save_config() {
  local algo="$1" buf="$2"
  cat > "$SYSCTL_CONF" <<EOF
# ATTAS v${VERSION} 自动生成 – $(date)
net.ipv4.tcp_congestion_control = ${algo}
net.core.rmem_max               = ${buf}
net.core.wmem_max               = ${buf}
net.ipv4.tcp_fastopen           = 3
net.ipv4.tcp_max_syn_backlog    = 8192
net.core.somaxconn              = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing        = 1
EOF
  sysctl -p "$SYSCTL_CONF" &>/dev/null || true
  log "持久化配置写入 ${SYSCTL_CONF}" "OK"
}

# ════════════════════════════════════════════════════════════
#  FIX-HEALTH: 写入 health.json（Bash 引擎版）
# ════════════════════════════════════════════════════════════
write_health_json() {
  local algo="$1" score="$2" rtt="$3" loss="$4" bw="$5"
  cat > "$HEALTH_FILE" <<EOF
{
  "status":    "running",
  "engine":    "bash",
  "version":   "${VERSION}",
  "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')",
  "algorithm": "${algo}",
  "score":     ${score},
  "rtt_ms":    ${rtt},
  "loss_pct":  ${loss},
  "bw_mbps":   ${bw},
  "pid":       $$
}
EOF
}

# ── 基线捕获 ──────────────────────────────────────────────
write_baseline() {
  local rtt; rtt=$(measure_rtt)
  local loss; loss=$(get_loss)
  local algo; algo=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  local buf; buf=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
  cat > "$BASELINE_FILE" <<EOF
BASELINE_DATE=$(date '+%Y-%m-%d %H:%M:%S')
BASELINE_RTT=${rtt}
BASELINE_LOSS=${loss}
BASELINE_ALGO=${algo}
BASELINE_BUF=${buf}
EOF
  log "基线数据已记录" "OK"
}

# ── 性能报告 ──────────────────────────────────────────────
show_report() {
  echo -e "\n${BOLD}${CYAN}══ ATTAS v${VERSION} 性能对比报告 ══${NC}"
  if [[ -f "$BASELINE_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$BASELINE_FILE"
    echo -e "${YELLOW}【优化前基线】${NC}"
    echo "  时间: ${BASELINE_DATE:-未知}"
    echo "  算法: ${BASELINE_ALGO:-未知} | 缓冲区: ${BASELINE_BUF:-0} bytes"
    echo "  RTT:  ${BASELINE_RTT:-?} ms  | 丢包: ${BASELINE_LOSS:-?}%"
  fi
  echo -e "\n${GREEN}【当前状态】${NC}"
  local cur_algo; cur_algo=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  local cur_buf;  cur_buf=$(sysctl -n net.core.rmem_max 2>/dev/null)
  local cur_rtt;  cur_rtt=$(measure_rtt)
  local cur_loss; cur_loss=$(get_loss)
  echo "  算法: ${cur_algo} | 缓冲区: ${cur_buf} bytes"
  echo "  RTT:  ${cur_rtt} ms  | 丢包: ${cur_loss}%"
  echo ""
}

# ════════════════════════════════════════════════════════════
#  监控主循环（FIX-GHOST: 单例锁）
# ════════════════════════════════════════════════════════════
monitor_mode() {

  # ── FIX-GHOST: 单例锁，防止幽灵子进程 ─────────────────
  if [[ -f "$LOCK_FILE" ]]; then
    local old_pid; old_pid=$(cat "$LOCK_FILE" 2>/dev/null)
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      log "监控进程已运行 (PID=${old_pid})，退出重复实例" "WARN"
      exit 0
    else
      log "清除过期锁文件 (PID=${old_pid})" "INFO"
      rm -f "$LOCK_FILE"
    fi
  fi
  echo $$ > "$LOCK_FILE"
  trap 'rm -f "$LOCK_FILE"; log "监控进程退出" "INFO"' EXIT INT TERM
  # ────────────────────────────────────────────────────────

  log "ATTAS v${VERSION} 监控模式启动 (PID=$$)" "OK"

  # 启动异步丢包监测
  start_loss_monitor

  local last_algo=""
  local cycle=0

  while true; do
    cycle=$((cycle + 1))

    # 每5个周期更新一次带宽（避免频繁 sleep 1）
    local bw=100
    if (( cycle % 5 == 1 )); then
      bw=$(get_bandwidth_mbps)
    fi

    local rtt; rtt=$(measure_rtt)
    local loss; loss=$(get_loss)
    local score; score=$(calc_score "$rtt" "$loss")
    local algo; algo=$(select_algo "$score" "$rtt")

    log "[bash] RTT:${rtt}ms Loss:${loss}% Score:${score} Algo:${algo}" "INFO"

    # 只在算法变化时更新 sysctl（减少无效写入）
    if [[ "$algo" != "$last_algo" ]]; then
      apply_sysctl "$algo" "$score" "$rtt" "$bw"
      local buf; buf=$(calc_bdp_buffer "$rtt" "$bw")
      save_config "$algo" "$buf"
      last_algo="$algo"
    else
      log "[bash] Stable: ${algo}" "OK"
    fi

    # FIX-HEALTH: 每次循环都写入健康文件
    write_health_json "$algo" "$score" "$rtt" "$loss" "$bw"

    sleep "$MONITOR_INTERVAL"
  done
}

# ── 状态显示 ──────────────────────────────────────────────
show_status() {
  echo -e "\n${BOLD}${CYAN}══ ATTAS v${VERSION} 状态 ══${NC}"

  # 健康文件
  if [[ -f "$HEALTH_FILE" ]]; then
    echo -e "${GREEN}健康状态:${NC}"
    cat "$HEALTH_FILE"
  else
    echo -e "${YELLOW}健康文件不存在（服务可能尚未完成首次循环）${NC}"
  fi

  echo -e "\n${GREEN}当前 sysctl:${NC}"
  sysctl net.ipv4.tcp_congestion_control \
         net.core.rmem_max \
         net.core.wmem_max \
         net.ipv4.tcp_fastopen 2>/dev/null

  echo -e "\n${GREEN}可用算法:${NC}"
  cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null

  if [[ "$INIT_SYS" == "systemd" ]]; then
    echo -e "\n${GREEN}服务状态:${NC}"
    systemctl status attas.service --no-pager -l 2>/dev/null | head -20
    echo -e "\n${GREEN}最近日志 (10行):${NC}"
    journalctl -u attas.service -n 10 --no-pager 2>/dev/null
  fi
  echo ""
}

# ── 服务安装 ──────────────────────────────────────────────
install_service() {
  # 复制脚本到 bin
  cp -f "$0" "$BIN_PATH"
  chmod +x "$BIN_PATH"
  log "脚本已安装至 ${BIN_PATH}" "OK"

  case "$INIT_SYS" in
    systemd)
      cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ATTAS v${VERSION} Adaptive TCP Acceleration
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now attas.service
      log "systemd 服务已安装并启动" "OK"
      ;;
    openrc)
      cat > /etc/init.d/attas <<EOF
#!/sbin/openrc-run
description="ATTAS v${VERSION} Adaptive TCP Acceleration"
command="${BIN_PATH}"
command_args="--monitor"
command_background=true
pidfile="/run/attas.pid"
depend() { need net; }
EOF
      chmod +x /etc/init.d/attas
      rc-update add attas default
      rc-service attas start
      log "OpenRC 服务已安装并启动" "OK"
      ;;
    runit)
      mkdir -p /etc/sv/attas
      cat > /etc/sv/attas/run <<EOF
#!/bin/sh
exec ${BIN_PATH} --monitor
EOF
      chmod +x /etc/sv/attas/run
      ln -sf /etc/sv/attas /var/service/attas 2>/dev/null || true
      log "runit 服务已安装并启动" "OK"
      ;;
    *)
      # 降级：写入 /etc/rc.local
      if ! grep -q "attas --monitor" /etc/rc.local 2>/dev/null; then
        echo "${BIN_PATH} --monitor &" >> /etc/rc.local
        log "已写入 /etc/rc.local" "OK"
      fi
      ${BIN_PATH} --monitor &
      log "ATTAS 后台启动 (PID=$!)" "OK"
      ;;
  esac
}

# ── 看门狗 ────────────────────────────────────────────────
install_watchdog() {
  [[ "$INIT_SYS" != "systemd" ]] && return
  cat > "$WATCHDOG_FILE" <<EOF
[Unit]
Description=ATTAS Watchdog
After=attas.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do \
  systemctl is-active attas.service || systemctl restart attas.service; \
  sleep 60; done'
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now attas-watchdog.service
  log "看门狗服务已安装" "OK"
}

# ── 卸载 ──────────────────────────────────────────────────
uninstall() {
  log "开始卸载 ATTAS..." "INFO"
  systemctl stop  attas.service attas-watchdog.service 2>/dev/null || true
  systemctl disable attas.service attas-watchdog.service 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$WATCHDOG_FILE" "$BIN_PATH"
  rm -f "$SYSCTL_CONF" "$MODULES_CONF"
  rm -f "$LOCK_FILE" "$LOSS_CACHE" "$LOSS_PID_FILE" "$HEALTH_FILE"
  rm -rf "$CONFIG_DIR"
  systemctl daemon-reload 2>/dev/null || true
  sysctl -p 2>/dev/null || true
  log "ATTAS 已完全卸载" "OK"
}

# ════════════════════════════════════════════════════════════
#  主入口
# ════════════════════════════════════════════════════════════
main() {
  ensure_dirs
  ensure_self_on_disk "$@"
  detect_container
  detect_os
  detect_init
  detect_kernel

  case "${1:-install}" in
    --monitor)
      check_root
      monitor_mode
      ;;
    --status)
      detect_init
      show_status
      ;;
    --report)
      show_report
      ;;
    --check-deps)
      check_root
      test_connectivity
      check_repo_and_mirror
      run_dependency_check
      ;;
    --uninstall)
      check_root
      uninstall
      ;;
    install|"")
      check_root
      log "══ ATTAS v${VERSION} 安装开始 ══" "INFO"
      test_connectivity
      check_repo_and_mirror
      run_dependency_check
      load_kernel_modules
      write_baseline
      apply_sysctl "bbr" 100 50 100
      local buf; buf=$(calc_bdp_buffer 50 100)
      save_config "bbr" "$buf"
      install_service
      install_watchdog
      log "══ ATTAS v${VERSION} 安装完成 ══" "OK"
      log "运行 'attas --status' 查看状态" "INFO"
      ;;
    *)
      echo "用法: $0 {install|--monitor|--status|--report|--check-deps|--uninstall}"
      exit 1
      ;;
  esac
}

main "$@"
