# 1. 创建配置（推荐路径）
cat <<EOF | sudo tee /etc/sysctl.d/99-grok-bbr-opt.conf
# 基础（必须）
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 缓冲（适中，128MB 平衡）
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# 队列 & 连接
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# 探测/收敛优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
EOF

# 2. 立即生效 + 永久
sudo sysctl -p /etc/sysctl.d/99-grok-bbr-opt.conf
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# 3. 验证
sysctl net.ipv4.tcp_congestion_control   # 应显示 bbr
lsmod | grep bbr
ss -m | head -n 10
# 测试收敛：iperf3 -c <目标> -t 30 -P 4   # 观察带宽爬升速度
