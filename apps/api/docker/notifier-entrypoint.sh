#!/bin/sh
# Notifier egress firewall (ADR-014, defense in depth). Default deny: outbound traffic is allowed
# only to the hosts in SENTINELOPS_EGRESS_ALLOW ("host:port ...", e.g. the database and the
# platform SMTP relay), to the networks in SENTINELOPS_EGRESS_ALLOW_CIDRS ("cidr:port ...";
# default: Telegram's published Bot API ranges on 443) and to DNS. IPv6 egress is denied.
# Fails closed: if any rule cannot be applied the notifier does not start. Then drops root and
# runs as the unprivileged sentinelops user.
set -eu

ALLOW="${SENTINELOPS_EGRESS_ALLOW-postgres:5432}"
ALLOW_CIDRS="${SENTINELOPS_EGRESS_ALLOW_CIDRS-91.108.4.0/22:443 91.108.8.0/22:443 91.108.12.0/22:443 91.108.16.0/22:443 91.108.56.0/22:443 149.154.160.0/20:443}"

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

for entry in $ALLOW_CIDRS; do
    iptables -A OUTPUT -d "${entry%:*}" -p tcp --dport "${entry##*:}" -j ACCEPT
done

for server in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf); do
    case "$server" in
        *:*) ;;
        *) iptables -A OUTPUT -d "$server" -p udp --dport 53 -j ACCEPT
           iptables -A OUTPUT -d "$server" -p tcp --dport 53 -j ACCEPT ;;
    esac
done

iptables -A OUTPUT -j REJECT --reject-with icmp-net-prohibited
ip6tables -A OUTPUT -j REJECT

echo "egress-firewall: default-deny rules applied; starting as sentinelops" >&2
exec setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all -- "$@"
