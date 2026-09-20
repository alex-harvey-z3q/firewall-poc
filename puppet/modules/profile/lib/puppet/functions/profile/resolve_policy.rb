# frozen_string_literal: true
require_relative '../../../puppet_x/profile/policy'

Puppet::Functions.create_function(:'profile::resolve_policy') do
  dispatch :resolve do
    param 'String', :node
    param 'Hash', :data
    return_type 'Hash'
  end

  def resolve(node, data)
    FirewallPoc::Policy.new(data).for_node(node)
  rescue ArgumentError, KeyError => e
    raise Puppet::Error, "Invalid Hiera firewall policy: #{e.message}"
  end
end
