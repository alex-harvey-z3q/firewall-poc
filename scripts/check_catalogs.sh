#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/hiera
python3 scripts/compile_policy.py --output build/hiera
python3 - <<'PY'
from pathlib import Path
Path('build/hiera.yaml').write_text(Path('puppet/hiera.yaml').read_text().replace('/var/lib/firewall-poc/hiera', str(Path('build/hiera').resolve())))
PY
for node in app_a-web app_a-api app_a-db app_b-web app_b-api app_b-db; do
  puppet catalog compile --certname "$node" --node_name_value "$node" \
    --manifest "$PWD/puppet/manifests/site.pp" --modulepath "$PWD/puppet/modules:$PWD/vendor" \
    --hiera_config "$PWD/build/hiera.yaml" --vardir "$PWD/build/puppet-var" \
    --confdir "$PWD/build/puppet-conf" --logdir "$PWD/build/puppet-log" \
    --rundir "$PWD/build/puppet-run" --logdest "$PWD/build/compile.log" \
    --render-as json > "build/catalog-$node.json" 2> "build/facter-$node.log"
done
python3 - <<'PY'
import json
from pathlib import Path
for path in sorted(Path('build').glob('catalog-*.json')):
    # Puppet CLI can prefix JSON with a compilation notice.
    raw = path.read_text()
    catalog = json.loads(raw[raw.index('{'):])
    path.write_text(json.dumps(catalog, indent=2) + '\n')
    resources = catalog['resources']
    chains = [r for r in resources if r['type'] == 'Firewallchain']
    assert len(chains) == 3
    assert all(r['parameters']['policy'] == 'drop' and r['parameters']['purge'] for r in chains)
    rules = [r for r in resources if r['type'] == 'Firewall']
    assert rules and not any(isinstance(r['parameters'].get('source'), list) for r in rules)
    print(f'{catalog["name"]}: {len(rules)} expanded firewall resources, default deny + purge verified')
PY
