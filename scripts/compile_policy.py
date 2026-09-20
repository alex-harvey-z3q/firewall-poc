#!/usr/bin/env python3
"""Compile reviewed IPv4 intent and a bounded IPAM snapshot to Puppet Hiera JSON."""
import argparse
import datetime as dt
import ipaddress as ip
import json
from pathlib import Path


def network(value):
    n = ip.ip_network(value, strict=True)
    if n.version != 4 or n.prefixlen == 0 or n.is_multicast or n.is_loopback or n.is_unspecified:
        raise ValueError(f"Not an admissible IPv4 network: {value}")
    return n


def compile_policy(inventory, policy, snapshot, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if snapshot['schema_version'] != 1 or not snapshot['revision']:
        raise ValueError('IPAM schema/revision required')
    expiry = dt.datetime.fromisoformat(snapshot['expires_at'].replace('Z', '+00:00'))
    if expiry.tzinfo is None or expiry <= now or expiry > now + dt.timedelta(days=7):
        raise ValueError('IPAM expiry must be in the next seven days')
    scopes = policy['ipam_scopes']
    if set(snapshot['groups']) != set(scopes):
        raise ValueError('IPAM must supply exactly the approved external groups')
    groups = {}
    vnet = network(inventory['network'])
    addresses = set()
    nodes = inventory['nodes']
    if set(nodes) != {f'{a}-{t}' for a in ('app_a', 'app_b') for t in ('web', 'api', 'db')}:
        raise ValueError('Expected exactly two three-tier applications')
    for name, node in nodes.items():
        address = ip.IPv4Address(node['ip'])
        subnet = network(inventory['subnets'][node['tier']])
        if (address in addresses or address not in subnet or not subnet.subnet_of(vnet)
                or name != f"{node['app']}-{node['tier']}"
                or int(address) - int(subnet.network_address) < 4
                or address == subnet.broadcast_address):
            raise ValueError(f'Invalid node address or identity: {name}')
        addresses.add(address)
        groups[name] = [f'{address}/32']
    for name, values in snapshot['groups'].items():
        if not name.startswith('external.') or not isinstance(values, list) or len(values) > 64:
            raise ValueError('Invalid external group')
        approved = [network(x) for x in scopes[name]]
        parsed = [network(x) for x in values]
        if any(n.overlaps(vnet) or not any(n.subnet_of(s) for s in approved) for n in parsed):
            raise ValueError(f'IPAM group exceeds approved scope: {name}')
        if len(set(parsed)) != len(parsed):
            raise ValueError('Duplicate IPAM networks')
        groups[name] = [str(n) for n in sorted(parsed)]
    # Internal identities cannot be supplied or replaced by IPAM.
    flows = []
    def flow(label, source, target, proto, port):
        if proto not in ('tcp', 'udp') or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid service')
        if source not in groups or target not in groups:
            raise ValueError(f'Unknown group in {label}')
        if groups[source] and groups[target]:  # Empty groups mean NO grants, never wildcard.
            flows.append(dict(name=label, source=source, target=target, proto=proto, port=port))
    def service(label, source, app, key):
        s = policy['services'][key]
        flow(label, source, f"{app}-{s['tier']}", s['proto'], s['port'])
    for app in ('app_a', 'app_b'):
        service(f'{app} users', 'external.clients', app, 'web')
        service(f'{app} web to api', f'{app}-web', app, 'api')
        service(f'{app} api to database', f'{app}-api', app, 'database')
    for name in nodes:
        flow(f'admin {name}', 'external.admins', name, 'tcp', 22)
    seen = set()
    for connection in policy['connections']:
        src, dst, contract = (connection[k] for k in ('from', 'to', 'contract'))
        if src not in ('app_a', 'app_b') or dst not in ('app_a', 'app_b') or src == dst:
            raise ValueError('Unknown application or self contract')
        key = (src, dst, contract)
        if key in seen:
            raise ValueError('Duplicate contract')
        seen.add(key)
        c = policy['contracts'][contract]
        service(f'{src} to {dst} {contract}', f"{src}-{c['caller_tier']}", dst, c['service'])
    groups['platform.azure'] = ['168.63.129.16/32']
    for name in nodes:
        for proto, port in [('udp', 53), ('tcp', 53), ('tcp', 80), ('tcp', 32526)]:
            flow(f'{name} azure {proto} {port}', name, 'platform.azure', proto, port)
    catalogs = {}
    for name, node in nodes.items():
        rules = {}
        for index, f in enumerate(flows):
            if name not in (f['source'], f['target']):
                continue
            outbound = name == f['source']
            chain = 'OUTPUT' if outbound else 'INPUT'
            reverse = 'INPUT' if outbound else 'OUTPUT'
            common = dict(proto=f['proto'], jump='accept', protocol='IPv4')
            rules[f"200 {index:03} {f['name']} request"] = dict(
                common, chain=chain, source=groups[f['source']], destination=groups[f['target']],
                dport=f['port'], ctstate=['NEW', 'ESTABLISHED'], ctdir='ORIGINAL')
            rules[f"200 {index:03} {f['name']} reply"] = dict(
                common, chain=reverse, source=groups[f['target']], destination=groups[f['source']],
                sport=f['port'], ctstate=['ESTABLISHED'], ctdir='REPLY')
        catalogs[name] = {'profile::host::rules': rules,
                          'profile::host::listen_ip': node['ip'],
                          'profile::host::listen_port': next(s['port'] for s in policy['services'].values() if s['tier'] == node['tier'])}
    return {'groups': groups, 'flows': flows, 'catalogs': catalogs, 'expires_at': snapshot['expires_at'],
            'revision': snapshot['revision']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--config', type=Path, default=Path('config'))
    parser.add_argument('--output', type=Path, default=Path('build'))
    args = parser.parse_args()
    if args.bundle:
        bundle = json.loads(args.bundle.read_text())
    else:
        bundle = {k: json.loads((args.config / f'{v}.json').read_text())
                  for k, v in [('inventory', 'inventory'), ('policy', 'policy'), ('ipam', 'ipam')]}
    result = compile_policy(bundle['inventory'], bundle['policy'], bundle['ipam'])
    args.output.mkdir(parents=True, exist_ok=True)
    for name, catalog in result['catalogs'].items():
        path = args.output / f'{name}.json'
        temp = path.with_suffix('.tmp')
        temp.write_text(json.dumps(catalog, indent=2) + '\n')
        temp.replace(path)
    (args.output / 'resolved-policy.json').write_text(json.dumps(result, indent=2) + '\n')

if __name__ == '__main__':
    main()
