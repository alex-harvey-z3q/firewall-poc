# This profile owns the entire IPv4 filter table. Do not combine with Docker/UFW.
class profile::host (
  Hash[String, Hash] $rules,
  String $listen_ip,
  Integer[1, 65535] $listen_port,
  Boolean $manage_host = true,
) {
  ['INPUT', 'OUTPUT', 'FORWARD'].each |String $chain| {
    firewallchain { "${chain}:filter:IPv4":
      ensure         => present,
      policy         => drop,
      purge          => true,
      ignore_foreign => false,
    }
  }
  firewall { '000 drop invalid input':
    chain => 'INPUT', proto => 'all', ctstate => ['INVALID'], jump => 'drop',
  }
  firewall { '000 drop invalid output':
    chain => 'OUTPUT', proto => 'all', ctstate => ['INVALID'], jump => 'drop',
  }
  firewall { '010 loopback input':
    chain => 'INPUT', proto => 'all', iniface => 'lo', jump => 'accept',
  }
  firewall { '010 loopback output':
    chain => 'OUTPUT', proto => 'all', outiface => 'lo', jump => 'accept',
  }
  # DHCP's first request is broadcast; renewals target Azure's DHCP service.
  firewall_multi { '020 dhcp request':
    chain => 'OUTPUT', proto => 'udp', sport => 68, dport => 67,
    destination => ['255.255.255.255/32', '168.63.129.16/32'], jump => 'accept',
  }
  firewall { '020 dhcp response':
    chain => 'INPUT', proto => 'udp', source => '168.63.129.16/32',
    sport => 67, dport => 68, jump => 'accept',
  }
  # Only conntrack-related ICMP errors, including path MTU; no blanket ping.
  firewall_multi { '030 related network errors':
    chain => 'INPUT', proto => 'icmp', icmp => ['destination-unreachable', 'time-exceeded', 'parameter-problem'],
    ctstate => ['RELATED'], jump => 'accept',
  }
  $rules.each |String $title, Hash $attributes| {
    firewall_multi { $title: * => $attributes }
  }
  if $manage_host {
    file { '/etc/sysctl.d/80-firewall-poc.conf':
      content => "net.ipv4.ip_forward=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.netfilter.nf_conntrack_helper=0\n",
      notify  => Exec['firewall-sysctl'],
    }
    exec { 'firewall-sysctl':
      command     => '/sbin/sysctl -p /etc/sysctl.d/80-firewall-poc.conf',
      require     => Firewall['000 drop invalid input'],
      refreshonly => true,
    }
    # Synthetic HTTP listener: a test fixture, not a real web/API/database product.
    file { '/etc/systemd/system/demo-tier.service':
      content => "[Unit]\nDescription=Synthetic tier connectivity fixture\nAfter=network.target\n[Service]\nUser=nobody\nExecStart=/usr/bin/python3 /opt/firewall-poc/scripts/demo_listener.py ${listen_ip} ${listen_port}\nRestart=on-failure\nNoNewPrivileges=true\nProtectSystem=strict\nPrivateTmp=true\n[Install]\nWantedBy=multi-user.target\n",
      notify  => Exec['demo-daemon-reload'],
    }
    exec { 'demo-daemon-reload':
      command => '/bin/sh -c "/bin/systemctl daemon-reload && /bin/systemctl try-restart demo-tier.service"',
      refreshonly => true,
    }
  }
  # Started by the apply wrapper only AFTER successful firewall convergence.
}
