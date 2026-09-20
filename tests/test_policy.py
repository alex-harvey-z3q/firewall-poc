import datetime as dt
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from compile_policy import compile_policy
ROOT = Path(__file__).resolve().parents[1]

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads((ROOT / 'config/inventory.json').read_text())
        self.policy = json.loads((ROOT / 'config/policy.json').read_text())
        self.ipam = json.loads((ROOT / 'config/ipam.example.json').read_text())
        self.now = dt.datetime(2026, 9, 20, tzinfo=dt.timezone.utc)

    def compile(self):
        return compile_policy(self.inventory, self.policy, self.ipam, self.now)

    def test_exact_application_matrix(self):
        result = self.compile()
        actual = {(f['source'], f['target'], f['port']) for f in result['flows']
                  if f['source'] in self.inventory['nodes'] and f['target'] in self.inventory['nodes']}
        self.assertEqual(actual, {
            ('app_a-web', 'app_a-api', 9000), ('app_a-api', 'app_a-db', 15432),
            ('app_b-web', 'app_b-api', 9000), ('app_b-api', 'app_b-db', 15432),
            ('app_a-api', 'app_b-api', 9000)})

    def test_both_ends_and_no_unsolicited_return(self):
        result = self.compile()
        for f in result['flows']:
            for name in (f['source'], f['target']):
                if name not in result['catalogs']:
                    continue
                rules = result['catalogs'][name]['profile::host::rules']
                request = [r for t, r in rules.items() if t.endswith(f"{f['name']} request")]
                reply = [r for t, r in rules.items() if t.endswith(f"{f['name']} reply")]
                self.assertEqual(len(request), 1)
                self.assertEqual(len(reply), 1)
                self.assertEqual(request[0]['ctdir'], 'ORIGINAL')
                self.assertEqual(reply[0]['ctdir'], 'REPLY')
                self.assertEqual(reply[0]['ctstate'], ['ESTABLISHED'])
                for rule in request + reply:
                    self.assertTrue(rule['source'])
                    self.assertTrue(rule['destination'])
                    self.assertNotIn('0.0.0.0/0', rule['source'] + rule['destination'])

    def test_revocation_removes_both_directions(self):
        self.policy['connections'] = []
        result = self.compile()
        for catalog in result['catalogs'].values():
            self.assertFalse(any('app_a to app_b' in n for n in catalog['profile::host::rules']))

    def test_empty_group_never_wildcards(self):
        self.ipam['groups']['external.admins'] = []
        result = self.compile()
        self.assertFalse(any(f['port'] == 22 for f in result['flows']))

    def test_unknown_and_injected_groups_rejected(self):
        self.ipam['groups']['app_a-api'] = ['10.42.2.20/32']
        with self.assertRaises(ValueError): self.compile()

    def test_bad_ipam_networks_rejected(self):
        for bad in ['0.0.0.0/0', '10.42.2.10/32', '192.0.2.0/24', 'host.example', '10.60.0.10/24']:
            with self.subTest(bad=bad):
                self.ipam['groups']['external.admins'] = [bad]
                with self.assertRaises(ValueError): self.compile()

    def test_stale_or_unbounded_lease_rejected(self):
        for expiry in ['2026-09-19T00:00:00Z', '2027-01-01T00:00:00Z', '2026-09-21T00:00:00']:
            self.ipam['expires_at'] = expiry
            with self.assertRaises(ValueError): self.compile()

    def test_missing_duplicate_and_large_groups_rejected(self):
        original = json.loads(json.dumps(self.ipam))
        del self.ipam['groups']['external.clients']
        with self.assertRaises(ValueError): self.compile()
        self.ipam = original
        self.ipam['groups']['external.admins'] = ['10.60.0.10/32'] * 2
        with self.assertRaises(ValueError): self.compile()
        self.ipam['groups']['external.admins'] = [f'10.60.0.{i}/32' for i in range(1, 66)]
        with self.assertRaises(ValueError): self.compile()

    def test_failed_import_preserves_last_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / 'inventory.json').write_text(json.dumps(self.inventory))
            (directory / 'policy.json').write_text(json.dumps(self.policy))
            (directory / 'ipam.json').write_text('last approved snapshot')
            self.ipam['groups']['external.admins'] = ['0.0.0.0/0']
            candidate = directory / 'candidate.json'
            candidate.write_text(json.dumps(self.ipam))
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/import_ipam.py'),
                                     str(candidate), '--config', str(directory)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((directory / 'ipam.json').read_text(), 'last approved snapshot')

    def test_unknown_contract_rejected(self):
        self.policy['connections'][0]['contract'] = 'all_access'
        with self.assertRaises(KeyError): self.compile()

    def test_duplicate_ips_rejected(self):
        self.inventory['nodes']['app_b-api']['ip'] = '10.42.2.10'
        with self.assertRaises(ValueError): self.compile()

    def test_ipam_removal_is_replacement(self):
        original = self.compile()
        self.ipam['groups']['external.admins'] = ['10.60.0.11/32']
        changed = self.compile()
        self.assertIn('10.60.0.10/32', json.dumps(original))
        self.assertNotIn('10.60.0.10/32', json.dumps(changed))

if __name__ == '__main__': unittest.main()
