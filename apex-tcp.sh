#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-1.1.1.1}"
PING_COUNT="${2:-30}"

need_root() {
  [ "$EUID" -eq 0 ] || { echo "请用 root 运行"; exit 1; }
}

is_positive_int() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

detect_iface() {
  ip route get "$TARGET" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'
}

detect_metrics() {
  local result loss rtt
  result=$(ping -c "$PING_COUNT" -q "$TARGET" 2>/dev/null || true)

  loss=$(printf '%s\n' "$result" | awk -F',' '/packet loss/ {for(i=1;i<=NF;i++) if($i ~ /packet loss/) {gsub(/^[ \t]+|[ \t]+$/, "", $i); sub(/% packet loss.*/, "", $i); print $i; exit}}')
  rtt=$(printf '%s\n' "$result" | awk -F'/' '/rtt|round-trip/ {print $5; exit}')

  echo "${loss:-100} ${rtt:-999}"
}

has_sysctl() {
  sysctl -n "$1" >/dev/null 2>&1
}

set_sysctl_if_exists() {
  local key="$1"
  local value="$2"
  if has_sysctl "$key"; then
    sysctl -w "$key=$value" >/dev/null
    echo "已设置: $key=$value"
  else
    echo "跳过: $key 不存在"
  fi
}

has_cc() {
  sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "$1"
}

select_cc() {
  modprobe tcp_bbr 2>/dev/null || true
  if has_cc bbr3; then
    echo "bbr3"
  elif has_cc bbr; then
    echo "bbr"
  else
    echo ""
  fi
}

apply_base() {
  local cc
  cc=$(select_cc)

  set_sysctl_if_exists net.core.default_qdisc fq

  if [ -n "$cc" ]; then
    set_sysctl_if_exists net.ipv4.tcp_congestion_control "$cc"
  else
    echo "警告: 当前内核无 bbr/bbr3，保持默认拥塞控制"
  fi

  set_sysctl_if_exists net.ipv4.tcp_fastopen 3
  set_sysctl_if_exists net.ipv4.tcp_mtu_probing 1
  set_sysctl_if_exists net.ipv4.tcp_slow_start_after_idle 0
  set_sysctl_if_exists net.ipv4.tcp_no_metrics_save 1
  set_sysctl_if_exists net.core.somaxconn 65535
  set_sysctl_if_exists net.ipv4.tcp_max_syn_backlog 65535
  set_sysctl_if_exists net.ipv4.ip_local_port_range "1024 65535"
  set_sysctl_if_exists net.ipv4.tcp_rmem "4096 87380 67108864"
  set_sysctl_if_exists net.ipv4.tcp_wmem "4096 65536 67108864"
  set_sysctl_if_exists net.core.rmem_max 67108864
  set_sysctl_if_exists net.core.wmem_max 67108864
}

apply_preemptive_safe() {
  local iface
  iface=$(detect_iface || true)

  echo "启用安全抢占模块"

  set_sysctl_if_exists net.ipv4.tcp_notsent_lowat 16384
  set_sysctl_if_exists net.ipv4.tcp_autocorking 0
  set_sysctl_if_exists net.ipv4.tcp_low_latency 1

  if command -v tc >/dev/null 2>&1 && [ -n "${iface:-}" ]; then
    tc qdisc replace dev "$iface" root fq 2>/dev/null || echo "警告: tc 设置 fq 失败"
    echo "出口网卡: $iface"
  else
    echo "跳过 tc qdisc: 未安装 tc 或未检测到出口网卡"
  fi
}

apply_dynamic() {
  local loss rtt loss_int rtt_int
  read -r loss rtt < <(detect_metrics)

  loss_int=${loss%.*}
  rtt_int=${rtt%.*}

  echo "检测目标: $TARGET"
  echo "丢包率: ${loss}%"
  echo "平均RTT: ${rtt} ms"
  echo

  apply_base
  apply_preemptive_safe

  echo
  if [ "$loss_int" -lt 1 ]; then
    echo "模式: 低丢包链路 -> TCP + BBR/BBRv3"
    set_sysctl_if_exists net.ipv4.tcp_retries2 8
  elif [ "$loss_int" -lt 3 ]; then
    echo "模式: 轻微丢包 -> QUIC/Hysteria2 更优"
    set_sysctl_if_exists net.ipv4.tcp_retries2 7
  elif [ "$loss_int" -lt 10 ]; then
    echo "模式: 中高丢包 -> 需要 UDP/FEC 抗丢包"
    set_sysctl_if_exists net.ipv4.tcp_retries2 6
  else
    echo "模式: 严重丢包 -> 参数优化价值极低"
    set_sysctl_if_exists net.ipv4.tcp_retries2 5
  fi

  if [ "$rtt_int" -gt 150 ]; then
    echo "高 RTT: 提高窗口容忍度"
    set_sysctl_if_exists net.ipv4.tcp_adv_win_scale 1
  fi
}

persist() {
  local conf="/etc/sysctl.d/99-dynamic-tcp-accel.conf"
  local cc
  cc=$(select_cc)

  cat >"$conf" <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_autocorking=0
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.rmem_max=67108864
net.core.wmem_max=67108864
EOF

  if [ -n "$cc" ]; then
    echo "net.ipv4.tcp_congestion_control=$cc" >>"$conf"
  fi

  sysctl --system >/dev/null 2>&1 || echo "警告: sysctl --system 部分参数加载失败"
}

main() {
  need_root

  if ! is_positive_int "$PING_COUNT"; then
    echo "PING_COUNT 必须是正整数"
    exit 1
  fi

  if ! command -v ping >/dev/null 2>&1; then
    echo "缺少 ping 命令"
    exit 1
  fi

  apply_dynamic
  persist

  echo
  echo "完成"
  echo "当前拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  echo "当前队列算法: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
}

main "$@"
