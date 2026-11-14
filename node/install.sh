#!/usr/bin/env bash
# superNET node installer for Debian / Ubuntu.
#
#   sudo bash install.sh [--port 51820] [--subnet 10.66.0.0/24] [--endpoint HOST] [--mtu 1380]
#   sudo bash install.sh --uninstall
#
# Sets up kernel WireGuard (wg0) with NAT so clients can leave through this
# server. Sized for small machines (1 vCPU / 1 GB): no resident daemon besides
# the kernel interface. Safe to run again: finished steps are skipped and the
# existing keys and peers are kept.
set -euo pipefail

PORT=51820
SUBNET=10.66.0.0/24
ENDPOINT=""
MTU=1380
UNINSTALL=0

CONF_DIR=/etc/wireguard
STATE_DIR=/etc/supernet
WG_CONF=$CONF_DIR/wg0.conf
SYSCTL_FILE=/etc/sysctl.d/90-supernet.conf
MODULES_FILE=/etc/modules-load.d/supernet.conf
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m警告:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT=$2; shift 2 ;;
        --subnet) SUBNET=$2; shift 2 ;;
        --endpoint) ENDPOINT=$2; shift 2 ;;
        --mtu) MTU=$2; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) die "未知参数 $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo bash install.sh）"

uninstall() {
    local backup
    backup=/root/supernet-backup-$(date +%Y%m%d-%H%M%S)
    mkdir -p "$backup"
    log "停止 wg0，备份配置到 $backup"
    systemctl disable --now wg-quick@wg0 2>/dev/null || true
    [ -f "$WG_CONF" ] && mv "$WG_CONF" "$backup/"
    [ -d "$STATE_DIR" ] && mv "$STATE_DIR" "$backup/"
    rm -f "$SYSCTL_FILE" "$MODULES_FILE" /usr/local/bin/supernet-node
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        ufw delete allow "$PORT/udp" >/dev/null 2>&1 || true
    fi
    sysctl --system >/dev/null
    log "已卸载。转发开关恢复为系统默认值（重启后完全生效）。"
}

if [ "$UNINSTALL" = 1 ]; then
    [ -f "$STATE_DIR/node.env" ] && . "$STATE_DIR/node.env"
    uninstall
    exit 0
fi

# ---------------------------------------------------------------- checks
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*) FAMILY=debian ;;
    *rhel*|*centos*|*fedora*) FAMILY=rhel ;;
    *) die "目前只支持 Debian / Ubuntu 和 CentOS / Rocky / Alma（检测到 ${PRETTY_NAME:-未知系统}）" ;;
esac
EL_MAJOR=${VERSION_ID%%.*}
log "系统：${PRETTY_NAME}，内核 $(uname -r)，内存 $(free -m | awk '/Mem:/{print $2}') MB"

VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)
case "$VIRT" in
    openvz|lxc|lxc-libvirt)
        # Containers share the host kernel: no module loading, maybe no TUN.
        if ! ip link add supernet-probe type wireguard 2>/dev/null; then
            die "这是 $VIRT 容器，宿主机内核不提供 WireGuard，暂不支持（需要用户态出口，见设计文档）"
        fi
        ip link del supernet-probe ;;
esac
log "虚拟化：$VIRT"

ipcalc_base() { echo "${SUBNET%/*}"; }
PREFIX=${SUBNET#*/}
[ "$PREFIX" -ge 16 ] && [ "$PREFIX" -le 28 ] || die "子网前缀应在 /16 到 /28 之间"
BASE=$(ipcalc_base)
SERVER_IP="${BASE%.*}.$(( ${BASE##*.} + 1 ))"

WAN=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}' | head -1)
[ -n "$WAN" ] || die "找不到默认出口网卡"
log "出口网卡：$WAN"

# ---------------------------------------------------------------- coexistence
# The node may share the machine with other services (e.g. an s-ui / sing-box
# panel). Refuse to touch anything that is already in use.
if ! ip link show wg0 >/dev/null 2>&1; then
    if ss -Hlun "sport = :$PORT" | grep -q .; then
        die "UDP $PORT 已被占用：$(ss -Hlunp "sport = :$PORT" | awk '{print $NF}' | head -1)，请用 --port 换一个"
    fi
    if ip -4 route show | awk '{print $1}' | grep -qx "$SUBNET"; then
        die "子网 $SUBNET 已在路由表中，请用 --subnet 换一个"
    fi
fi
case "$WAN" in
    tun*|sing*|utun*)
        warn "默认路由走 ${WAN}（像是 sing-box 的 TUN）。节点流量会被它接管，请确认这是你想要的。" ;;
esac
for svc in s-ui sing-box x-ui xray; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        log "检测到正在运行的 ${svc}：只会新增 wg0、一张独立的 nftables 表和内核参数，不会改动它"
    fi
done

# ---------------------------------------------------------------- packages
need=()
command -v wg >/dev/null || need+=(wireguard-tools)
command -v nft >/dev/null || need+=(nftables)
command -v qrencode >/dev/null || need+=(qrencode)
command -v curl >/dev/null || need+=(curl)
has_wg_module() {
    modprobe wireguard 2>/dev/null || ip link add supernet-probe type wireguard 2>/dev/null
}

if [ "$FAMILY" = debian ]; then
    if [ ${#need[@]} -gt 0 ]; then
        log "安装 ${need[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends "${need[@]}" >/dev/null
    fi
else
    # EL 8/9 kernels may lack WireGuard: ELRepo ships it as a kABI-tracking
    # kmod (no compiler, no DKMS). wireguard-tools comes from EPEL.
    case "$EL_MAJOR" in
        8|9) ;;
        *) die "EL $EL_MAJOR 暂不支持（只支持 8 和 9）" ;;
    esac
    if ! has_wg_module && ! rpm -q elrepo-release >/dev/null 2>&1; then
        log "添加 ELRepo 软件源（kmod-wireguard）"
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-v2-elrepo.org 2>/dev/null || true
        dnf install -y -q "https://www.elrepo.org/elrepo-release-$EL_MAJOR.el$EL_MAJOR.elrepo.noarch.rpm" >/dev/null
    fi
    if ! command -v wg >/dev/null; then
        # Only this one package is needed from EPEL. Enabling the whole repo
        # makes dnf load ~300 MB of metadata, which a 1 GB machine cannot do.
        need=("${need[@]/wireguard-tools}")
        epel="https://dl.fedoraproject.org/pub/epel/$EL_MAJOR/Everything/x86_64/Packages/w/"
        rpm_name=$(curl -fsS --max-time 30 "$epel" | grep -oE 'wireguard-tools-[0-9][^"<]*\.x86_64\.rpm' | sort -uV | tail -1)
        [ -n "$rpm_name" ] || die "无法从 EPEL 获取 wireguard-tools"
        need+=("$epel$rpm_name")
    fi
    has_wg_module || need+=(kmod-wireguard)
    # Drop the blanks left by removing wireguard-tools above.
    read -r -a need <<<"${need[*]}"
    if [ ${#need[@]} -gt 0 ]; then
        log "安装 ${need[*]##*/}"
        dnf install -y -q --setopt=install_weak_deps=False --disablerepo='epel*' "${need[@]}" >/dev/null
    fi
fi

if ! has_wg_module; then
    die "WireGuard 内核模块无法加载（Debian/Ubuntu 老内核可装 wireguard-dkms；EL 请确认 kmod-wireguard 与当前内核 $(uname -r) 匹配）"
fi
ip link del supernet-probe 2>/dev/null || true

# ---------------------------------------------------------------- keys and config
umask 077
mkdir -p "$CONF_DIR" "$STATE_DIR/peers"
if [ ! -f "$STATE_DIR/server.key" ]; then
    log "生成服务端密钥"
    wg genkey > "$STATE_DIR/server.key"
fi
wg pubkey < "$STATE_DIR/server.key" > "$STATE_DIR/server.pub"

if [ -z "$ENDPOINT" ] && [ -f "$STATE_DIR/node.env" ]; then
    ENDPOINT=$(. "$STATE_DIR/node.env"; echo "${ENDPOINT:-}")
fi
if [ -z "$ENDPOINT" ]; then
    # Cloud servers often sit behind 1:1 NAT, so ask the outside world first.
    ENDPOINT=$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
    [ -n "$ENDPOINT" ] || ENDPOINT=$(ip -4 addr show "$WAN" | awk '/inet /{sub("/.*","",$2); print $2; exit}')
fi
log "客户端连接地址：$ENDPOINT:$PORT"

cat > "$STATE_DIR/node.env" <<EOF
PORT=$PORT
SUBNET=$SUBNET
SERVER_IP=$SERVER_IP
ENDPOINT=$ENDPOINT
MTU=$MTU
WAN=$WAN
EOF

# The firewall rules live in their own nftables table, created and removed
# with the interface, so an existing firewall (ufw, iptables) is untouched.
cat > "$STATE_DIR/nft-up.nft" <<EOF
table inet supernet {
    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "wg0" oifname "$WAN" tcp flags syn tcp option maxseg size set rt mtu
        oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        ip saddr $SUBNET oifname "$WAN" masquerade
    }
}
EOF

PEERS=""
if [ -f "$WG_CONF" ]; then
    # Keep the peers added by supernet-node.
    PEERS=$(awk '/^# supernet-peer /{p=1} p' "$WG_CONF")
fi
cat > "$WG_CONF" <<EOF
# Managed by superNET (install.sh). Add peers with: supernet-node peer add NAME
[Interface]
Address = $SERVER_IP/$PREFIX
ListenPort = $PORT
MTU = $MTU
PrivateKey = $(cat "$STATE_DIR/server.key")
PostUp = nft -f $STATE_DIR/nft-up.nft
PostDown = nft delete table inet supernet 2>/dev/null || true
EOF
# Hosts with an iptables FORWARD policy of DROP (Docker sets one) would drop
# forwarded traffic no matter what our own table accepts.
if command -v iptables >/dev/null; then
    cat >> "$WG_CONF" <<'EOF'
PostUp = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -I FORWARD -i %i -j ACCEPT
PostUp = iptables -C FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
EOF
fi
[ -n "$PEERS" ] && printf '\n%s\n' "$PEERS" >> "$WG_CONF"
chmod 600 "$WG_CONF"

# ---------------------------------------------------------------- kernel tuning
log "写入内核参数 $SYSCTL_FILE"
echo nf_conntrack > "$MODULES_FILE"
modprobe nf_conntrack 2>/dev/null || true
{
    echo "# superNET node: forwarding plus tuning for a 1 GB machine."
    echo "net.ipv4.ip_forward = 1"
    # Each conntrack entry is ~300 bytes; 65536 entries ≈ 20 MB worst case.
    echo "net.netfilter.nf_conntrack_max = 65536"
    echo "net.netfilter.nf_conntrack_tcp_timeout_established = 7200"
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || modprobe tcp_bbr 2>/dev/null; then
        echo "net.core.default_qdisc = fq"
        echo "net.ipv4.tcp_congestion_control = bbr"
    fi
    echo "net.core.rmem_max = 4194304"
    echo "net.core.wmem_max = 4194304"
} > "$SYSCTL_FILE"
sysctl -q -p "$SYSCTL_FILE" || warn "部分内核参数未生效（容器环境常见）"

# ---------------------------------------------------------------- firewall
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    log "ufw 已启用：放行 UDP $PORT 和 wg0 的转发"
    ufw allow "$PORT/udp" >/dev/null
    ufw route allow in on wg0 out on "$WAN" >/dev/null
fi
if systemctl is-active --quiet firewalld 2>/dev/null; then
    log "firewalld 已启用：放行 UDP ${PORT}，wg0 加入 trusted 区"
    firewall-cmd -q --permanent --add-port="$PORT/udp"
    firewall-cmd -q --permanent --zone=trusted --add-interface=wg0
    firewall-cmd -q --reload
fi

# ---------------------------------------------------------------- service
install -m 755 "$HERE/supernet-node" /usr/local/bin/supernet-node
systemctl enable wg-quick@wg0 >/dev/null 2>&1
if ip link show wg0 >/dev/null 2>&1; then
    systemctl restart wg-quick@wg0
else
    systemctl start wg-quick@wg0
fi
sleep 1
ip link show wg0 >/dev/null || die "wg0 没有启动，查看：journalctl -u wg-quick@wg0"

log "完成。wg0 已启动，开机自动启动。"
echo
echo "下一步：supernet-node peer add 手机       # 生成客户端配置、二维码和 supernet:// 链接"
echo "注意：如果云服务商有安全组/防火墙，请放行 UDP $PORT 入站。"
