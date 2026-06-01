#!/bin/bash

# --- 权限检查 ---
if [ "$EUID" -ne 0 ]; then
    echo "错误: 必须以 root 权限运行此脚本！" >&2
    exit 1
fi

# --- 路径常量 ---
SCRIPT_PATH="/usr/local/bin/tcp.sh"
SHORTCUT_PATH="/usr/local/bin/t"
SYSCTL_FILE="/etc/sysctl.d/99-tcp-tune.conf"
LIMITS_FILE="/etc/security/limits.d/99-tcp-tune.conf"
BBR_FILE="/etc/sysctl.d/10-bbr.conf"

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- 工具函数 ---
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()     { echo -e "${RED}[ERR]${NC}  $*" >&2; }
line()    { echo -e "${YELLOW}──────────────────────────────────────────────${NC}"; }
pause()   { read -rp "按回车键继续..."; }

# ==================================================
# --- 1. 自安装与快捷方式 ---
# 首次通过管道执行时，将脚本写入本地再运行
# ==================================================
if [[ "$0" != "$SCRIPT_PATH" && "$_" != "$SCRIPT_PATH" ]]; then
    info "正在安装脚本到本地..."
    mkdir -p /usr/local/bin

    REMOTE_URL="https://raw.githubusercontent.com/Memory2014/simpletest/main/tcp.sh"
    if curl -fsSL "$REMOTE_URL" -o "$SCRIPT_PATH" 2>/dev/null; then
        chmod +x "$SCRIPT_PATH"
        ok "脚本已安装至 $SCRIPT_PATH"
    else
        err "下载失败，请检查网络或手动安装。"
        exit 1
    fi

    ln -sf "$SCRIPT_PATH" "$SHORTCUT_PATH"
    ok "快捷命令 't' 已创建，任意位置输入 t 即可打开面板。"

    exec bash "$SCRIPT_PATH"
    exit 0
fi

# ==================================================
# --- 2. 功能模块 ---
# ==================================================

# ---- 2.1 开启 BBR + FQ ----
enable_bbr() {
    local cur
    cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$cur" == "bbr" ]]; then
        warn "BBR 已在运行中，无需重复操作。"
        pause; return
    fi

    # 检查内核是否支持 BBR
    if ! modprobe tcp_bbr 2>/dev/null && ! grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        err "当前内核不支持 BBR，请升级内核（推荐 4.9+）。"
        pause; return
    fi

    info "启用 BBR + FQ..."
    cat > "$BBR_FILE" <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system &>/dev/null

    local result
    result=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$result" == "bbr" ]]; then
        ok "BBR 启用成功！当前拥塞算法: ${BOLD}bbr${NC}，队列调度: ${BOLD}fq${NC}"
    else
        err "BBR 启用失败，当前算法仍为: $result"
    fi
    pause
}

# ---- 2.2 内核参数深度调优 ----
tune_sysctl() {
    local mem_kb cpu_count buf_bytes
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    cpu_count=$(nproc)
    # 缓冲区 = 总内存的 5%，最小 4MB，最大 256MB
    buf_bytes=$(( mem_kb * 1024 / 20 ))
    (( buf_bytes < 4194304   )) && buf_bytes=4194304
    (( buf_bytes > 268435456 )) && buf_bytes=268435456

    info "系统信息: CPU ${cpu_count} 核 | 内存 $(( mem_kb / 1024 )) MB | 分配缓冲 $(( buf_bytes / 1024 / 1024 )) MB"
    info "正在写入内核调优参数..."

    cat > "$SYSCTL_FILE" <<EOF
# TCP/UDP 网络深度调优 - 由 tcp.sh 自动生成
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 系统: $(uname -r) | CPU: ${cpu_count} 核 | 内存: $(( mem_kb / 1024 )) MB

# === 拥塞控制（BBR 已由独立文件管理，此处不重复）===

# === 连接队列 ===
net.core.somaxconn           = 65535
net.core.netdev_max_backlog  = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_orphans     = 32768

# === 收发缓冲区（动态基于内存 5%）===
net.core.rmem_max    = ${buf_bytes}
net.core.wmem_max    = ${buf_bytes}
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.tcp_rmem    = 4096 87380 ${buf_bytes}
net.ipv4.tcp_wmem    = 4096 65536 ${buf_bytes}

# === UDP 缓冲（QUIC/Hysteria2/TUIC 场景）===
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# === 连接复用与超时 ===
net.ipv4.tcp_tw_reuse          = 1
net.ipv4.tcp_fin_timeout       = 15
net.ipv4.tcp_retries2          = 8
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen          = 3

# === 跨境/代理优化 ===
# 降低首包延迟 TTFB（减少发送队列积压）
net.ipv4.tcp_notsent_lowat = 16384
# MTU 探测，防止 ICMP 黑洞导致连接超时
net.ipv4.tcp_mtu_probing   = 1
# ECN 显式拥塞通知，轻微拥塞打标记而非直接丢包
net.ipv4.tcp_ecn           = 1
EOF

    if sysctl --system &>/dev/null; then
        ok "内核参数写入并生效，配置文件: $SYSCTL_FILE"
    else
        err "sysctl 应用失败，请检查内核版本兼容性。"
        pause; return
    fi

    # 文件句柄限制
    mkdir -p /etc/security/limits.d/
    cat > "$LIMITS_FILE" <<EOF
# 由 tcp.sh 自动生成
* soft nofile 1048576
* hard nofile 1048576
* soft nproc  65535
* hard nproc  65535
EOF
    # 当前会话立即生效
    ulimit -n 1048576 2>/dev/null || true
    ok "文件句柄限制已提升至 1048576（重新登录后对所有进程生效）"

    # MSS Clamp（iptables）
    if command -v iptables &>/dev/null; then
        # 先删除旧规则避免重复
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu
        ok "iptables MSS Clamp 规则已添加（防止跨境连接超时）"
        warn "MSS 规则重启后失效，如需持久化请安装 iptables-persistent"
    fi

    echo
    line
    printf "  %-20s : ${GREEN}%s${NC}\n" "拥塞算法" "$(sysctl -n net.ipv4.tcp_congestion_control)"
    printf "  %-20s : ${GREEN}%s${NC}\n" "队列调度" "$(sysctl -n net.core.default_qdisc)"
    printf "  %-20s : ${GREEN}%s MB${NC}\n" "最大收发缓冲" "$(( buf_bytes / 1024 / 1024 ))"
    printf "  %-20s : ${GREEN}%s${NC}\n" "文件句柄上限" "$(ulimit -n)"
    printf "  %-20s : ${GREEN}%s${NC}\n" "ECN" "$(sysctl -n net.ipv4.tcp_ecn)"
    printf "  %-20s : ${GREEN}%s${NC}\n" "MTU 探测" "$(sysctl -n net.ipv4.tcp_mtu_probing)"
    line
    pause
}

# ---- 2.3 网卡多队列均衡（RPS/RFS）----
tune_nic() {
    if ! command -v ethtool &>/dev/null; then
        info "安装 ethtool..."
        apt-get install -y ethtool 2>/dev/null || yum install -y ethtool 2>/dev/null || {
            err "ethtool 安装失败，请手动安装后重试。"
            pause; return
        }
    fi

    local cpu_count rps_mask
    cpu_count=$(nproc)
    rps_mask=$(printf '%x' $(( (1 << cpu_count) - 1 )))

    # 排除虚拟/回环接口
    local interfaces
    interfaces=$(ls /sys/class/net | grep -vE '^(lo|docker|veth|br-|virbr|tun|tap|wg|sit0|any)' || true)

    if [[ -z "$interfaces" ]]; then
        warn "未发现可优化的物理/虚拟网卡接口。"
        pause; return
    fi

    local count=0
    for eth in $interfaces; do
        # 尝试扩大 Ring Buffer
        local max_rx
        max_rx=$(ethtool -g "$eth" 2>/dev/null | awk '/Pre-set maximums/{f=1} f && /RX:/{print $2; exit}')
        if [[ -n "$max_rx" && "$max_rx" =~ ^[0-9]+$ ]]; then
            ethtool -G "$eth" rx "$max_rx" tx "$max_rx" &>/dev/null && \
                ok "[$eth] Ring Buffer 已扩展至 $max_rx"
        fi

        # 设置 RPS（软件多队列）
        local rps_set=0
        for f in /sys/class/net/$eth/queues/rx-*/rps_cpus; do
            [[ -f "$f" ]] && echo "$rps_mask" > "$f" && rps_set=1
        done
        for f in /sys/class/net/$eth/queues/rx-*/rps_flow_cnt; do
            [[ -f "$f" ]] && echo "4096" > "$f"
        done
        [[ "$rps_set" -eq 1 ]] && ok "[$eth] RPS 已分散至 $cpu_count 个核心（掩码: 0x$rps_mask）"
        (( count++ ))
    done

    # RFS 全局流控
    sysctl -w net.core.rps_sock_flow_entries=32768 &>/dev/null
    ok "全局 RFS 流控条目: 32768"

    echo
    line
    info "已处理 $count 个网卡接口，软中断已均摊至全部 $cpu_count 个核心。"
    warn "注意: 此配置重启后失效，如需持久化请将命令加入 /etc/rc.local 或 systemd 服务。"
    line
    pause
}

# ---- 2.4 IPv4 优先解析 ----
set_ipv4_priority() {
    local gai_conf="/etc/gai.conf"

    if grep -q "^precedence ::ffff:0:0/96  100" "$gai_conf" 2>/dev/null; then
        warn "IPv4 优先已经开启，无需重复操作。"
        pause; return
    fi

    # 确保 gai.conf 存在
    if [[ ! -f "$gai_conf" ]]; then
        cat > "$gai_conf" <<'EOF'
label  ::1/128       0
label  ::/0          1
label  2002::/16     2
label  ::/96         3
label  ::ffff:0:0/96 4
precedence  ::1/128       50
precedence  ::/0          40
precedence  2002::/16     30
precedence  ::/96         20
precedence  ::ffff:0:0/96 10
EOF
    fi

    cp "$gai_conf" "${gai_conf}.bak"
    # 将已注释的那行解注释，或追加
    if grep -q "^#precedence ::ffff:0:0/96  100" "$gai_conf"; then
        sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' "$gai_conf"
    else
        echo "precedence ::ffff:0:0/96  100" >> "$gai_conf"
    fi

    ok "IPv4 优先解析已开启（备份: ${gai_conf}.bak）"
    info "验证: $(curl -s --max-time 3 -4 ifconfig.me 2>/dev/null || echo '无法获取外网 IP')"
    pause
}

# ---- 2.5 查看当前状态 ----
show_status() {
    clear
    line
    echo -e "  ${BOLD}系统网络参数快照${NC}   $(date '+%Y-%m-%d %H:%M:%S')"
    line

    # 内核基础信息
    printf "  %-28s : ${GREEN}%s${NC}\n" "内核版本" "$(uname -r)"
    printf "  %-28s : ${GREEN}%s 核${NC}\n" "CPU 核心数" "$(nproc)"
    printf "  %-28s : ${GREEN}%s MB${NC}\n" "物理内存" "$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 ))"
    echo

    # TCP 核心参数
    printf "  %-28s : ${GREEN}%s${NC}\n" "拥塞控制算法" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "队列调度器" "$(sysctl -n net.core.default_qdisc 2>/dev/null)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "可用拥塞算法" "$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)"
    echo

    # 缓冲区
    local rmem
    rmem=$(sysctl -n net.core.rmem_max 2>/dev/null)
    printf "  %-28s : ${GREEN}%s MB${NC}\n" "最大接收缓冲 rmem_max" "$(( rmem / 1024 / 1024 ))"
    printf "  %-28s : ${GREEN}%s MB${NC}\n" "最大发送缓冲 wmem_max" "$(( $(sysctl -n net.core.wmem_max 2>/dev/null) / 1024 / 1024 ))"
    echo

    # 连接参数
    printf "  %-28s : ${GREEN}%s${NC}\n" "somaxconn" "$(sysctl -n net.core.somaxconn 2>/dev/null)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "tcp_fastopen" "$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "tcp_ecn" "$(sysctl -n net.ipv4.tcp_ecn 2>/dev/null)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "tcp_mtu_probing" "$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "tcp_tw_reuse" "$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null)"
    echo

    # 文件句柄
    printf "  %-28s : ${GREEN}%s${NC}\n" "文件句柄上限 (ulimit)" "$(ulimit -n)"
    printf "  %-28s : ${GREEN}%s${NC}\n" "系统级 file-max" "$(sysctl -n fs.file-max 2>/dev/null)"
    echo

    # 网卡信息
    local interfaces
    interfaces=$(ls /sys/class/net | grep -vE '^(lo|docker|veth|br-|virbr|tun|tap|wg|sit0|any)' || true)
    for eth in $interfaces; do
        local speed link
        speed=$(cat /sys/class/net/$eth/speed 2>/dev/null || echo "未知")
        link=$(cat /sys/class/net/$eth/operstate 2>/dev/null || echo "未知")
        local rps_mask_cur
        rps_mask_cur=$(cat /sys/class/net/$eth/queues/rx-0/rps_cpus 2>/dev/null | tr -d '\n' || echo "0")
        printf "  %-28s : ${GREEN}%s${NC} | 速率: %s Mbps | RPS掩码: %s\n" \
            "网卡 $eth" "$link" "$speed" "$rps_mask_cur"
    done
    echo

    # IPv4 优先
    if grep -q "^precedence ::ffff:0:0/96  100" /etc/gai.conf 2>/dev/null; then
        printf "  %-28s : ${GREEN}已开启${NC}\n" "IPv4 优先解析"
    else
        printf "  %-28s : ${RED}未开启${NC}\n" "IPv4 优先解析"
    fi

    # iptables MSS 规则
    if command -v iptables &>/dev/null && iptables -t mangle -L POSTROUTING -n 2>/dev/null | grep -q "TCPMSS"; then
        printf "  %-28s : ${GREEN}已存在${NC}\n" "iptables MSS Clamp"
    else
        printf "  %-28s : ${RED}未设置${NC}\n" "iptables MSS Clamp"
    fi

    line
    pause
}

# ---- 2.6 回退所有设置 ----
rollback() {
    echo
    read -rp "$(echo -e "${RED}警告: 将清除所有调优配置并恢复默认值，确定？[y/N]: ${NC}")" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消。"; sleep 1; return; }

    info "清理配置文件..."
    rm -f "$SYSCTL_FILE" "$LIMITS_FILE" "$BBR_FILE"

    info "恢复内存中的内核参数..."
    sysctl -w net.ipv4.tcp_congestion_control=cubic   &>/dev/null
    sysctl -w net.core.default_qdisc=pfifo_fast        &>/dev/null
    sysctl -w net.core.rps_sock_flow_entries=0          &>/dev/null
    sysctl --system                                     &>/dev/null

    info "恢复网卡 RPS..."
    local interfaces
    interfaces=$(ls /sys/class/net | grep -vE '^(lo|docker|veth|br-|virbr|tun|tap|wg|sit0|any)' || true)
    for eth in $interfaces; do
        for f in /sys/class/net/$eth/queues/rx-*/rps_cpus; do [[ -f "$f" ]] && echo "0" > "$f"; done
    done

    info "清理 iptables MSS 规则..."
    if command -v iptables &>/dev/null; then
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    fi

    info "恢复 IPv4/IPv6 解析优先级..."
    if [[ -f /etc/gai.conf.bak ]]; then
        mv /etc/gai.conf.bak /etc/gai.conf
    else
        sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' \
            /etc/gai.conf 2>/dev/null || true
    fi

    ulimit -n 1024 2>/dev/null || true

    ok "回退完成，所有调优配置已清除，网络参数已恢复默认。"
    pause
}

# ---- 2.7 在线更新 ----
update_script() {
    info "正在从 GitHub 拉取最新版本..."
    local tmp="${SCRIPT_PATH}.tmp"
    local url="https://raw.githubusercontent.com/Memory2014/simpletest/main/tcp.sh"

    if curl -fsSL "$url" -o "$tmp"; then
        # 简单校验：确保是 bash 脚本
        if head -1 "$tmp" | grep -q "bash"; then
            mv "$tmp" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            ok "更新成功！重新载入脚本..."
            sleep 1
            exec bash "$SCRIPT_PATH"
        else
            rm -f "$tmp"
            err "下载的文件格式异常，更新中止。"
        fi
    else
        rm -f "$tmp"
        err "下载失败，请检查网络连接。"
    fi
    pause
}

# ---- 2.8 卸载脚本 ----
uninstall() {
    echo
    read -rp "$(echo -e "${RED}确认卸载？将同时回退所有调优设置 [y/N]: ${NC}")" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消。"; sleep 1; return; }

    rollback &>/dev/null

    rm -f "$SHORTCUT_PATH" "$SCRIPT_PATH"
    ok "卸载完成，脚本与快捷命令 't' 已移除。"
    exit 0
}

# ==================================================
# --- 3. 主菜单 ---
# ==================================================

# 状态检测函数
_bbr_status()    { [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] && echo -e "${GREEN}● 已启用${NC}" || echo -e "${RED}○ 未启用${NC}"; }
_sysctl_status() { [[ -f "$SYSCTL_FILE" ]] && echo -e "${GREEN}● 已优化${NC}" || echo -e "${RED}○ 未优化${NC}"; }
_nic_status()    { [[ "$(sysctl -n net.core.rps_sock_flow_entries 2>/dev/null)" == "32768" ]] && echo -e "${GREEN}● 已启用${NC}" || echo -e "${RED}○ 未启用${NC}"; }
_ipv4_status()   { grep -q "^precedence ::ffff:0:0/96  100" /etc/gai.conf 2>/dev/null && echo -e "${GREEN}● 已开启${NC}" || echo -e "${RED}○ 未开启${NC}"; }

while true; do
    clear
    echo -e "${YELLOW}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║       TCP/UDP 网络深度调优面板  优化版       ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════╝${NC}"
    echo -e "  内核: $(uname -r)  |  CPU: $(nproc) 核  |  内存: $(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 )) MB"
    echo -e "  算法: ${GREEN}$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)${NC}  |  句柄: ${GREEN}$(ulimit -n)${NC}  |  时间: $(date '+%H:%M:%S')"
    line
    echo -e "  ${BOLD}优化功能${NC}"
    echo -e "  1) BBR + FQ 拥塞控制       $(_bbr_status)"
    echo -e "  2) 内核参数深度调优         $(_sysctl_status)"
    echo -e "  3) 网卡多队列均衡 (RPS/RFS) $(_nic_status)"
    echo -e "  4) IPv4 优先解析            $(_ipv4_status)"
    line
    echo -e "  ${BOLD}维护功能${NC}"
    echo -e "  5) 查看当前网络状态详情"
    echo -e "  6) 一键回退所有设置"
    echo -e "  7) 在线更新脚本"
    echo -e "  8) 卸载脚本"
    echo -e "  0) 退出"
    line
    read -rp "请选择 [0-8]: " opt
    case "$opt" in
        1) enable_bbr ;;
        2) tune_sysctl ;;
        3) tune_nic ;;
        4) set_ipv4_priority ;;
        5) show_status ;;
        6) rollback ;;
        7) update_script ;;
        8) uninstall ;;
        0) echo "再见！"; exit 0 ;;
        *) err "无效选项，请输入 0-8 的数字。"; sleep 1 ;;
    esac
done
