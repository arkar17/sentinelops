#!/bin/sh
# Probe-worker egress firewall (02_TECHNICAL_ARCHITECTURE.md §7, defense in depth).
# Rejects outbound traffic to private, loopback, link-local/metadata, CGNAT, multicast and
# reserved ranges for IPv4 and IPv6, except the hosts in SENTINELOPS_EGRESS_ALLOW
# ("host:port ..."; default: the database). Fails closed: if rules cannot be applied the worker
# does not start. Then drops root and runs the worker as the unprivileged sentinelops user.
set -eu

ALLOW="${SENTINELOPS_EGRESS_ALLOW-postgres:5432}"

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

for entry in $ALLOW; do
    host="${entry%:*}"
    port="${entry##*:}"
    addresses="$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)"
    if [ -z "$addresses" ]; then
        echo "egress-firewall: cannot resolve allowed host $host" >&2
        exit 1
    fi
    for address in $addresses; do
        iptables -A OUTPUT -d "$address" -p tcp --dport "$port" -j ACCEPT
    done
done

# DNS servers from resolv.conf (Docker's embedded resolver is on loopback and already allowed).
for server in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf); do
    case "$server" in
        *:*) ip6tables -A OUTPUT -d "$server" -p udp --dport 53 -j ACCEPT
             ip6tables -A OUTPUT -d "$server" -p tcp --dport 53 -j ACCEPT ;;
        *) iptables -A OUTPUT -d "$server" -p udp --dport 53 -j ACCEPT
           iptables -A OUTPUT -d "$server" -p tcp --dport 53 -j ACCEPT ;;
    esac
done

for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
           192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 \
           198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
    iptables -A OUTPUT -d "$net" -j REJECT --reject-with icmp-net-prohibited
done
for net in ::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 64:ff9b:1::/48 100::/64 2001::/32 \
           2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8; do
    ip6tables -A OUTPUT -d "$net" -j REJECT
done

echo "egress-firewall: rules applied; starting as sentinelops" >&2
exec setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all -- "$@"
