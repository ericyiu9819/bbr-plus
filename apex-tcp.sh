#!/usr/bin/env bash
set -euo pipefail

SYSCTL_CONF="/etc/sysctl.d/99-vps-aggressive-tcp.conf"
LIMITS_CONF="/etc/security/limits.d/99-vps-aggressive.conf"

if [[ "${1:-}" == "--rollback" ]]; then
  echo "[Rollback] 删除配置..."
  rm -f "$SYSCTL_CONF" "$LIMITS_CONF"
  sysctl --system >/dev/null
  echo "回滚完成。建议重启 VPS。"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "错误：请使用 root 运行。"
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "错误：缺少命令 $1"
    exit 1
  }
}

need_cmd sysctl
need_cmd ip
need_cmd awk

if command -v tc >/dev/null 2>&1; then
  HAS_TC=1
else
  HAS_TC=0
  echo "提示：未找到 tc，跳过 qdisc 应用。可安装 iproute2。"
fi

echo "[1/6] 检查并加载 BBR..."
modprobe tcp_bbr 2>/dev/null || true

if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
  echo "错误：当前内核不支持 BBR。"
  echo "建议使用 Debian 12 / Ubuntu 22.04+ / Linux 5.10+ 内核。"
  exit 1
fi

echo "[2/6] 写入 TCP 参数..."

cat > "$SYSCTL_CONF" <<'EOF'
# VPS aggressive TCP profile
# 目标：更主动探测带宽、更稳定 pacing、更大窗口、更快恢复

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 高 BDP 链路缓冲
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 268435456
net.ipv4.tcp_wmem = 4096 1048576 268435456

# 突发连接承载
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# TCP Fast Open：应用支持时才明显生效
net.ipv4.tcp_fastopen = 3

# TIME_WAIT 复用
net.ipv4.tcp_tw_reuse = 1

# MTU 探测，降低路径 MTU 黑洞影响
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024

# 降低发送端未发送队列堆积
net.ipv4.tcp_notsent_lowat = 16384

# 保持现代 TCP 基础能力
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1

# 恢复策略：偏激进但不过度误断
net.ipv4.tcp_retries2 = 10
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 5

# 代理/转发类服务更充足的本地端口
net.ipv4.ip_local_port_range = 10240 65535

# 系统级文件句柄上限
fs.file-max = 2097152
EOF

echo "[3/6] 应用 sysctl..."
sysctl --system >/dev/null

echo "[4/6] 写入 nofile limits..."

cat > "$LIMITS_CONF" <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

echo "[5/6] 应用 fq qdisc 到主机网卡..."

if [[ "$HAS_TC" -eq 1 ]]; then
  mapfile -t DEVS < <(
    ip -o link show \
      | awk -F': ' '{print $2}' \
      | sed 's/@.*//' \
      | grep -Ev '^(lo|docker|veth|br-|tun|tap|wg|zt|tailscale|virbr|vmnet|ifb)'
  )

  if [[ "${#DEVS[@]}" -eq 0 ]]; then
    echo "未找到可应用的主机网卡，跳过。"
  else
    for dev in "${DEVS[@]}"; do
      if tc qdisc replace dev "$dev" root fq 2>/dev/null; then
        echo "已应用 fq: $dev"
      else
        echo "跳过或失败: $dev"
      fi
    done
  fi
fi

echo "[6/6] 当前状态："
echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "默认 qdisc: $(sysctl -n net.core.default_qdisc)"
echo "可用算法: $(sysctl -n net.ipv4.tcp_available_congestion_control)"
echo

if [[ "$HAS_TC" -eq 1 ]]; then
  tc qdisc show | grep -E 'fq|fq_codel|cake' || true
fi

echo
echo "完成。建议重启 VPS 后测速。"
echo "回滚命令：sudo bash $0 --rollback"
