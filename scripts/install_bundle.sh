#!/bin/bash
# Run as root on the destination. Cooperates with apply.sh's lock.
set -euo pipefail
[[ $EUID == 0 && $# == 1 ]]
exec 9>/run/firewall-poc.lock
flock 9
install -m 600 "$1" /etc/firewall-poc/bundle.next
mv /etc/firewall-poc/bundle.next /etc/firewall-poc/bundle.json
flock -u 9
systemctl start --no-block firewall-apply.service
