#!/bin/bash
# Freeze authored Hiera data, then let Puppet resolve groups during compilation.
set -euo pipefail
exec 9>/run/firewall-poc.lock
flock -n 9 || exit 0
cd /opt/firewall-poc
run_directory=''
cleanup() {
  local result=$?
  if (( result != 0 )); then
    /usr/sbin/iptables-restore --wait 10 < image/quarantine.rules
  fi
  if [[ -n "$run_directory" ]]; then rm -rf -- "$run_directory"; fi
  return "$result"
}
trap cleanup EXIT
trap 'exit 1' TERM INT
/usr/sbin/iptables-restore --wait 10 < image/quarantine.rules
run_directory=$(mktemp -d /run/firewall-poc.XXXXXX)
cp /etc/firewall-poc/bundle.json "$run_directory/bundle.json"
ruby=/opt/puppetlabs/puppet/bin/ruby
node=$("$ruby" scripts/stage_bundle.rb "$run_directory/bundle.json" "$run_directory")
set +e
/opt/puppetlabs/bin/puppet apply --detailed-exitcodes --certname "$node" \
  --modulepath /opt/firewall-poc/puppet/modules:/opt/firewall-poc/vendor \
  --hiera_config "$run_directory/hiera.yaml" puppet/manifests/site.pp
status=$?
set -e
[[ "$status" == 0 || "$status" == 2 ]]
# Validate the same immutable data again, so expiry during apply cannot open access.
"$ruby" scripts/validate_data.rb --data "$run_directory/data"
/usr/sbin/iptables-restore --wait 10 < image/release.rules
systemctl start demo-tier.service
