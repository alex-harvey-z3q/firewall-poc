#!/usr/bin/env python3
"""Validate a vendor-neutral IPAM export and atomically publish it. No API credentials on VMs."""
import argparse
import json
from pathlib import Path
from compile_policy import compile_policy
p = argparse.ArgumentParser()
p.add_argument('export', type=Path)
p.add_argument('--config', type=Path, default=Path('config'))
a = p.parse_args()
snapshot = json.loads(a.export.read_text())
compile_policy(json.loads((a.config / 'inventory.json').read_text()),
               json.loads((a.config / 'policy.json').read_text()), snapshot)
path = a.config / 'ipam.json'
temp = path.with_suffix('.tmp')
temp.write_text(json.dumps(snapshot, indent=2) + '\n')
temp.replace(path)
print(f"Validated IPAM revision {snapshot['revision']}: {path}")
