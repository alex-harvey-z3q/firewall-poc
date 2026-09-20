#!/usr/bin/env python3
"""Make reviewed per-host deployment bundles; transport with your existing SSH runner."""
import argparse
import json
from pathlib import Path
from compile_policy import compile_policy
p = argparse.ArgumentParser()
p.add_argument('--config', type=Path, default=Path('config'))
p.add_argument('--output', type=Path, default=Path('build/bundles'))
a = p.parse_args()
bundle = {key: json.loads((a.config / f'{key}.json').read_text()) for key in ('inventory', 'policy', 'ipam')}
compile_policy(bundle['inventory'], bundle['policy'], bundle['ipam'])
a.output.mkdir(parents=True, exist_ok=True)
for node in bundle['inventory']['nodes']:
    (a.output / f'{node}.json').write_text(json.dumps(dict(bundle, node=node), indent=2) + '\n')
