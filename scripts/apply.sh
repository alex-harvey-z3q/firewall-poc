#!/bin/bash
# Local convergence requires no network. On any failure, quarantine stays active.
set -euo pipefail
exec 9>/run/firewall-poc.lock
flock -n 9 || exit 0
cd /opt/firewall-poc
bundle=''
cleanup() {
  local result=$?
  if (( result != 0 )); then
    /usr/sbin/iptables-restore --wait 10 < image/quarantine.rules
  fi
  if [[ -n "$bundle" ]]; then rm -f "$bundle"; fi
  return "$result"
}
trap cleanup EXIT
trap 'exit 1' TERM INT
/usr/sbin/iptables-restore --wait 10 < image/quarantine.rules
bundle=$(mktemp /run/firewall-poc-bundle.XXXXXX)
cp /etc/firewall-poc/bundle.json "$bundle"
python3 scripts/compile_policy.py --bundle "$bundle" --output /var/lib/firewall-poc/hiera
node=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node"])' "$bundle")
[[ "$node" =~ ^app_[ab]-(web|api|db)$ ]]
set +e
/opt/puppetlabs/bin/puppet apply --detailed-exitcodes --certname "$node" \
  --modulepath /opt/firewall-poc/puppet/modules:/opt/firewall-poc/vendor \
  --hiera_config /opt/firewall-poc/puppet/hiera.yaml puppet/manifests/site.pp
status=$?
set -e
[[ "$status" == 0 || "$status" == 2 ]]
# Revalidate the lease after convergence; never release an expired snapshot.
python3 scripts/compile_policy.py --bundle "$bundle" --output /var/lib/firewall-poc/hiera
/usr/sbin/iptables-restore --wait 10 < image/release.rules
systemctl start demo-tier.service
