#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p vendor
for spec in puppetlabs-stdlib:9.7.0 puppetlabs-firewall:8.4.0 alexharvey-firewall_multi:8.4.0; do
  module=${spec%:*}
  version=${spec#*:}
  directory=${module#*-}
  if [[ -f "vendor/$directory/metadata.json" ]]; then
    python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["version"] == sys.argv[2], "Wrong installed module version"' "vendor/$directory/metadata.json" "$version"
  else
    puppet module install "$module" --version "$version" --ignore-dependencies --modulepath "$PWD/vendor"
  fi
done
