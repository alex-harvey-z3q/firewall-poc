#!/bin/bash
# Run on a disposable Ubuntu 24.04 image builder after copying repo to /opt/firewall-poc.
# Dependencies must be installed before sealing; production VMs never download packages.
set -euo pipefail
[[ $EUID == 0 ]]
cd /opt/firewall-poc
command -v python3
command -v iptables-restore
command -v flock
/opt/puppetlabs/puppet/bin/ruby -e 'require "puppet/resource_api"'
bash scripts/install_modules.sh
/opt/puppetlabs/bin/puppet --version | grep '^8\.'
for module in firewall firewall_multi stdlib; do test -f "vendor/$module/metadata.json"; done
chmod 755 scripts/apply.sh
install -d -m 700 /etc/firewall-poc /var/lib/firewall-poc/hiera
install -m 644 image/firewall-*.service image/firewall-apply.timer /etc/systemd/system/
# Explicit dependency means networking fails if the early firewall cannot load.
for unit in systemd-networkd NetworkManager; do
  mkdir -p "/etc/systemd/system/$unit.service.d"
  printf '[Unit]\nRequires=firewall-quarantine.service\nAfter=firewall-quarantine.service\n' > "/etc/systemd/system/$unit.service.d/firewall.conf"
done
for competing in ufw firewalld nftables netfilter-persistent puppet; do
  systemctl disable --now "$competing.service" 2>/dev/null || true
done
systemctl daemon-reload
systemctl enable firewall-quarantine.service firewall-apply.timer
# Do not start quarantine on the builder's remote SSH session. It applies on next boot.
# Remove instance identity before capturing; Azure deprovisioning is a separate operator step.
rm -f /etc/firewall-poc/bundle.json
