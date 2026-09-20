# Automatic parameter lookup reads the authored Hiera data. No rule preprocessor.
class profile::policy (
  Hash $inventory,
  Hash $groups,
  Hash $services,
  Hash $applications,
  Hash $contracts,
  Hash $connections,
  Hash $grants,
  Hash $ipam_scopes,
  Hash $ipam,
  Boolean $manage_host = true,
) {
  $resolved = profile::resolve_policy($trusted['certname'], {
    'inventory'    => $inventory,
    'groups'       => $groups,
    'services'     => $services,
    'applications' => $applications,
    'contracts'    => $contracts,
    'connections'  => $connections,
    'grants'       => $grants,
    'ipam_scopes'  => $ipam_scopes,
    'ipam'         => $ipam,
  })
  class { 'profile::host':
    rules       => $resolved['rules'],
    listen_ip   => $resolved['listen_ip'],
    listen_port => $resolved['listen_port'],
    manage_host => $manage_host,
  }
}
