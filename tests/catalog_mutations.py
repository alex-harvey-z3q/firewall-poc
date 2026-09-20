#!/usr/bin/env python3
"""Prove Hiera-only edits alter actual catalogs compiled by Puppet and firewall_multi."""
import json
from pathlib import Path
import subprocess as sp
import tempfile
ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory(prefix='hiera-catalog-') as directory:
    directory = Path(directory)
    sp.run(['ruby', str(ROOT / 'tests/fixture.rb'), str(directory)], check=True)
    policy_file = directory / 'data/policy.yaml'
    original = json.loads(sp.check_output(['ruby', '-ryaml', '-rjson', '-e',
        'puts JSON.generate(YAML.safe_load(File.read(ARGV[0])))', str(policy_file)], text=True))
    def compile_node(node):
        result = sp.run(['puppet', 'catalog', 'compile', '--certname', node, '--node_name_value', node,
            '--manifest', str(ROOT / 'puppet/manifests/site.pp'), '--modulepath', f'{ROOT}/puppet/modules:{ROOT}/vendor',
            '--hiera_config', str(directory / 'hiera.yaml'), '--vardir', str(directory / 'var'),
            '--confdir', str(directory / 'conf'), '--logdir', str(directory / 'log'),
            '--rundir', str(directory / 'run'), '--render-as', 'json'], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr[-3000:])
        catalog = json.loads(result.stdout[result.stdout.index('{'):])
        return [r for r in catalog['resources'] if r['type'] == 'Firewall']
    def cross(node):
        return [r for r in compile_node(node) if 'a_calls_b' in r['title']]
    assert len(cross('app_a-api')) == 2
    assert len(cross('app_b-api')) == 2
    edited = json.loads(json.dumps(original))
    del edited['profile::policy::connections']['a_calls_b']
    policy_file.write_text(json.dumps(edited))  # JSON is a valid YAML document.
    assert not cross('app_a-api')
    assert not cross('app_b-api')
    edited = json.loads(json.dumps(original))
    edited['profile::policy::services']['api']['ports'] = [9443]
    policy_file.write_text(json.dumps(edited))
    for rule in cross('app_a-api'):
        params = rule['parameters']
        ports = params.get('dport', params.get('sport'))
        assert str(ports).replace("'", '') in ('9443', '[9443]'), params
    ipam_file = directory / 'data/external/ipam.json'
    ipam = json.loads(ipam_file.read_text())
    ipam['profile::policy::ipam']['groups']['external.admins'] = ['10.60.0.11/32']
    ipam_file.write_text(json.dumps(ipam))
    rules = [r for r in compile_node('app_a-web') if 'administration' in r['title']]
    text = json.dumps(rules)
    assert '10.60.0.11' in text and '10.60.0.10' not in text
    ipam['profile::policy::ipam']['groups']['external.admins'] = []
    ipam_file.write_text(json.dumps(ipam))
    assert not any('administration' in r['title'] for r in compile_node('app_a-web'))
    print('PASS: real Hiera catalog changes revoke both endpoints, change service ports, replace and empty IPAM groups')
