#!/usr/bin/env python3
"""ROOT ONLY on disposable Linux with iproute2/iptables/Puppet + pinned modules.
Uses real Puppet providers in isolated network namespaces. No Azure credentials.
"""
import itertools
import json
import os
from pathlib import Path
import subprocess as sp
import sys
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
PUPPET = '/opt/puppetlabs/bin/puppet'
assert os.geteuid() == 0 and sys.platform == 'linux', 'Use a disposable Linux test VM as root'
PREFIX = f'fw{os.getpid()}'
processes = []
namespaces = []
bridge = f'{PREFIX}br'

def run(*args, **kwargs):
    return sp.run(args, check=True, text=True, **kwargs)

def ns(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', f'{PREFIX}-{name}', *args, **kwargs)

fixture = tempfile.TemporaryDirectory(prefix='fw-hiera-')
fixture_root = Path(fixture.name)
ruby = '/opt/puppetlabs/puppet/bin/ruby'
run(ruby, str(ROOT / 'tests/fixture.rb'), str(fixture_root))
data = json.loads(sp.check_output([ruby, str(ROOT / 'scripts/validate_data.rb'),
                                  '--data', str(fixture_root / 'data'), '--json'], text=True))
inventory = data['inventory']
addresses = {n: v['ip'] for n, v in inventory['nodes'].items()}
addresses.update(admin='10.60.0.10', client='10.61.0.10', outsider='10.62.0.10')
ports = [22, 8080, 9000, 15432, 9999]
# Deliberately listen on every tested port, so a deny cannot pass by mere refusal.
listener = '''import socket, threading, sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(128)
def echo(c):
 try:
  while True:
   b=c.recv(1024)
   if not b: break
   c.sendall(b)
 finally: c.close()
while True:
 c,_=s.accept(); threading.Thread(target=echo,args=(c,),daemon=True).start()
'''
probe = '''import socket,sys
try:
 s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=.3)
 s.sendall(b'ok'); assert s.recv(2)==b'ok'; print('allow')
except socket.timeout: print('drop')
except Exception as e: print('ERROR',repr(e)); sys.exit(2)
'''
try:
    run('ip', 'link', 'add', bridge, 'type', 'bridge')
    run('ip', 'link', 'set', bridge, 'up')
    for i, (name, address) in enumerate(addresses.items()):
        namespace = f'{PREFIX}-{name}'
        run('ip', 'netns', 'add', namespace); namespaces.append(namespace)
        host = f'{PREFIX}v{i}'
        run('ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', namespace)
        run('ip', 'link', 'set', host, 'master', bridge)
        run('ip', 'link', 'set', host, 'up')
        ns(name, 'ip', 'link', 'set', 'lo', 'up')
        ns(name, 'ip', 'addr', 'add', address + '/32', 'dev', 'eth0')
        ns(name, 'ip', 'link', 'set', 'eth0', 'up')
        ns(name, 'ip', 'route', 'add', 'default', 'dev', 'eth0')
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        hiera = fixture_root / 'hiera.yaml'
        manifest = temp / 'site.pp'
        manifest.write_text('class { "profile::policy": manage_host => false }\n')
        def apply():
            for name in inventory['nodes']:
                ns(name, PUPPET, 'apply', '--certname', name, '--modulepath', f'{ROOT}/puppet/modules:{ROOT}/vendor',
                   '--hiera_config', str(hiera), '--vardir', str(temp / name), str(manifest), stdout=sp.DEVNULL)
        apply()
        for name in inventory['nodes']:
            for port in ports:
                processes.append(sp.Popen(['ip', 'netns', 'exec', f'{PREFIX}-{name}', sys.executable,
                                           '-u', '-c', listener, addresses[name], str(port)]))
        time.sleep(1)
        expected = {('app_a-web','app_a-api',9000), ('app_a-api','app_a-db',15432),
                    ('app_b-web','app_b-api',9000), ('app_b-api','app_b-db',15432),
                    ('app_a-api','app_b-api',9000)}
        expected |= {('admin', n, 22) for n in inventory['nodes']}
        expected |= {('client', n, 8080) for n in ('app_a-web', 'app_b-web')}
        count = 0
        for source, target, port in itertools.product(addresses, inventory['nodes'], ports):
            if source == target: continue
            outcome = ns(source, sys.executable, '-c', probe, addresses[target], str(port), capture_output=True).stdout.strip()
            assert outcome == ('allow' if (source,target,port) in expected else 'drop'), (source,target,port,outcome)
            count += 1
        # Hold a real established TCP session across revocation.
        ready = temp / 'ready'
        trigger = temp / 'trigger'
        held = sp.Popen(['ip','netns','exec',f'{PREFIX}-app_a-api',sys.executable,'-c',
            '''import socket,time,sys,pathlib
s=socket.create_connection(('10.42.2.20',9000),timeout=2)
s.sendall(b'ok'); assert s.recv(2)==b'ok'
pathlib.Path(sys.argv[1]).touch()
while not pathlib.Path(sys.argv[2]).exists(): time.sleep(.1)
s.sendall(b'no')
try: s.recv(2); sys.exit(1)
except socket.timeout: sys.exit(0)
''',str(ready),str(trigger)])
        processes.append(held)
        for _ in range(100):
            if ready.exists(): break
            time.sleep(.1)
        assert ready.exists(), 'Established-flow test did not connect'
        data['connections'].pop('a_calls_b')
        policy_keys = ('services', 'applications', 'contracts', 'connections', 'grants')
        (fixture_root / 'data/policy.yaml').write_text(json.dumps({f'profile::policy::{key}': data[key] for key in policy_keys}))
        apply()
        trigger.touch()
        assert held.wait(timeout=5) == 0, 'Revoked established session still passes'
        outcome = ns('app_a-api',sys.executable,'-c',probe,'10.42.2.20','9000',capture_output=True).stdout.strip()
        assert outcome == 'drop'
        # Prove foreign accepts are purged, even without Puppet-style comments.
        ns('app_a-db','iptables','-I','INPUT','1','-j','ACCEPT')
        apply()
        rules = ns('app_a-db','iptables-save',capture_output=True).stdout
        assert '-A INPUT -j ACCEPT' not in rules
        print(f'PASS: {count} matrix probes, live-session revocation, foreign-rule purge')
finally:
    for process in processes:
        process.terminate()
    for process in processes:
        try: process.wait(timeout=3)
        except sp.TimeoutExpired: process.kill()
    for namespace in namespaces:
        sp.run(['ip','netns','del',namespace],check=False)
    sp.run(['ip','link','del',bridge],check=False)

    fixture.cleanup()
