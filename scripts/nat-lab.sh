#!/usr/bin/env bash
# NAT-to-NAT hole-punching lab, entirely inside network namespaces on a
# Linux host that runs the coordinator. The host's own routes and firewall
# are not changed: the NAT rules live inside the two "router" namespaces,
# and the host only forwards between two veth links (TEST-NET 192.0.2.0/24).
#
#   nat-lab.sh SUPERNET_BIN INVITE_FILE [random]
#
# Two devices (snA-dev, snB-dev), each behind its own NAT, run
# `supernet mesh-probe` and print the path they found to each other. With
# `random`, NAT B maps every flow to a random port (a symmetric NAT, like
# many mobile networks): hole punching should fail and fall back to a relay.
set -u
BIN=$1
INVITE=$(cat "$2")
MODE=${3:-}
cleanup() {
    for n in snA-dev snA-nat snB-dev snB-nat; do ip netns del $n 2>/dev/null; done
    ip link del snA-h 2>/dev/null; ip link del snB-h 2>/dev/null
}
cleanup

setup() { # side host_ip nat_out_ip lan_prefix masquerade_flags
    local s=$1 hip=$2 oip=$3 lan=$4 flags=$5
    ip netns add sn$s-nat; ip netns add sn$s-dev
    # host <-> router (public side)
    ip link add sn$s-h type veth peer name out
    ip link set out netns sn$s-nat
    ip addr add $hip/30 dev sn$s-h; ip link set sn$s-h up
    # router <-> device (private side)
    ip -n sn$s-nat link add in type veth peer name eth0
    ip -n sn$s-nat link set eth0 netns sn$s-dev
    ip -n sn$s-nat addr add $oip/30 dev out; ip -n sn$s-nat link set out up
    ip -n sn$s-nat addr add $lan.1/24 dev in; ip -n sn$s-nat link set in up
    ip -n sn$s-nat link set lo up
    ip -n sn$s-nat route add default via $hip
    ip netns exec sn$s-nat sysctl -qw net.ipv4.ip_forward=1
    ip netns exec sn$s-nat nft -f - <<EOF
table ip nat {
    chain post {
        type nat hook postrouting priority 100;
        oifname "out" masquerade $flags
    }
}
EOF
    ip -n sn$s-dev addr add $lan.2/24 dev eth0; ip -n sn$s-dev link set eth0 up
    ip -n sn$s-dev link set lo up
    ip -n sn$s-dev route add default via $lan.1
}

setup A 192.0.2.9 192.0.2.10 10.10.1 ""
if [ "$MODE" = random ]; then setup B 192.0.2.13 192.0.2.14 10.10.2 "random"; else setup B 192.0.2.13 192.0.2.14 10.10.2 ""; fi

ip netns exec snA-dev timeout 60 "$BIN" mesh-probe --invite "$INVITE" --name snA-dev --seconds 45 > /tmp/natlab-A.log 2>&1 &
ip netns exec snB-dev timeout 60 "$BIN" mesh-probe --invite "$INVITE" --name snB-dev --seconds 45 > /tmp/natlab-B.log 2>&1 &
if [ -n "${NATLAB_DEBUG:-}" ]; then
    sleep 25
    for s in A B; do echo "-- NAT $s conntrack (udp)"; ip netns exec sn$s-nat cat /proc/net/nf_conntrack 2>/dev/null | grep udp | grep -v "dport=53 " | sed -E 's/ +/ /g' | head -8; done
fi
wait
echo "== A（NAT A 后面）"; head -1 /tmp/natlab-A.log; grep snB-dev /tmp/natlab-A.log | tail -1
echo "== B（NAT B 后面${MODE:+，对称 NAT}）"; head -1 /tmp/natlab-B.log; grep snA-dev /tmp/natlab-B.log | tail -1
cleanup
