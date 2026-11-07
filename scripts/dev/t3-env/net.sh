#!/usr/bin/env bash
# Interim host network for one sandy qemu guest (`SANDY_NETWORK=nic SANDY_TAP=sandytap0`): bridge sbr0, tap
# sandytap0, NAT, DHCP. Sandy should provision this per run (#677); until then the operator runs it once.
# Public egress works. Private, LAN, mesh and multicast ranges and the host itself are blocked.
# The bridge name avoids br-* and the tap avoids vm-*, which a host firewall may trust. It tracks the filter of
# the t3br0 bridge on the reference host. Run as root with dnsmasq, nftables and iproute2 on PATH:
#   sudo env PATH="$(nix build nixpkgs#dnsmasq nixpkgs#nftables nixpkgs#iproute2 --no-link --print-out-paths \
#     | sed 's|$|/bin|' | tr '\n' ':')$PATH" bash net.sh up|down
set -euo pipefail

BR=sbr0
TAP=sandytap0
NET=192.168.84.0/24
GW=192.168.84.1
PIDF=/run/sandy-dnsmasq.pid
PRIVATE="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3"

down() {
  if [ -f "$PIDF" ]; then
    kill "$(cat "$PIDF")" 2>/dev/null || true
    rm -f "$PIDF"
  fi
  iptables -D INPUT -i "$BR" -j sbr-in 2>/dev/null || true
  iptables -D FORWARD -i "$BR" -j sbr-fwd 2>/dev/null || true
  iptables -D FORWARD -o "$BR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$BR" -o "$BR" -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "$NET" -j sbr-nat 2>/dev/null || true
  ip6tables -D INPUT -i "$BR" -j DROP 2>/dev/null || true
  ip6tables -D FORWARD -i "$BR" -j DROP 2>/dev/null || true
  for c in sbr-in sbr-fwd; do iptables -F "$c" 2>/dev/null && iptables -X "$c" 2>/dev/null || true; done
  iptables -t nat -F sbr-nat 2>/dev/null && iptables -t nat -X sbr-nat 2>/dev/null || true
  ip link del "$TAP" 2>/dev/null || true
  ip link del "$BR" 2>/dev/null || true
}

up() {
  down
  ip link add "$BR" type bridge
  ip addr add "$GW/24" dev "$BR"
  ip link set "$BR" up
  ip tuntap add dev "$TAP" mode tap
  ip link set "$TAP" master "$BR"
  ip link set "$TAP" up
  sysctl -qw "net.ipv4.conf.$BR.forwarding=1"

  # INPUT: new connections from the guest to ws01 die, except DHCP to dnsmasq.
  iptables -N sbr-in
  iptables -A sbr-in -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A sbr-in -p udp --dport 67 -j ACCEPT
  iptables -A sbr-in -j DROP
  iptables -I INPUT 1 -i "$BR" -j sbr-in

  # FORWARD: spoofed sources and private destinations drop, public destinations pass.
  iptables -N sbr-fwd
  iptables -A sbr-fwd ! -s "$NET" -j DROP
  for d in $PRIVATE; do iptables -A sbr-fwd -d "$d" -j DROP; done
  iptables -A sbr-fwd -j ACCEPT
  iptables -I FORWARD 1 -i "$BR" -j sbr-fwd
  iptables -I FORWARD 1 -o "$BR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # Frames inside the bridge (host DHCP offer to the guest) pass br_netfilter's FORWARD hook when Docker has it on.
  iptables -I FORWARD 1 -i "$BR" -o "$BR" -j ACCEPT

  # NAT out of whatever uplink holds the default route.
  iptables -t nat -N sbr-nat
  iptables -t nat -A sbr-nat ! -d "$NET" -j MASQUERADE
  iptables -t nat -I POSTROUTING 1 -s "$NET" -j sbr-nat

  # IPv6: the bridge has no address; drop as a backstop.
  ip6tables -I INPUT 1 -i "$BR" -j DROP
  ip6tables -I FORWARD 1 -i "$BR" -j DROP

  # DHCP only (port=0 turns DNS off). The guest gets public resolvers, which the FORWARD rules reach.
  # --dhcp-broadcast: dnsmasq did not set a static ARP entry here, so a unicast reply to an unconfigured guest
  # waited on an ARP the guest could not answer (seen with tcpdump on sandytap0).
  dnsmasq --conf-file=/dev/null --pid-file="$PIDF" --port=0 --dhcp-broadcast \
    --interface="$BR" --bind-interfaces --except-interface=lo \
    --dhcp-range=192.168.84.10,192.168.84.50,12h \
    --dhcp-option=3,"$GW" --dhcp-option=6,1.1.1.1,9.9.9.9

  echo "up: $BR $GW/24, tap $TAP. Run sandy with SANDY_NETWORK=nic SANDY_TAP=$TAP."
}

case "${1:-}" in
up) up ;;
down)
  down
  echo "down: $BR and $TAP removed."
  ;;
*)
  echo "usage: sudo env PATH=\"\$PATH\" bash $0 up|down (see the header for the PATH)" >&2
  exit 2
  ;;
esac
