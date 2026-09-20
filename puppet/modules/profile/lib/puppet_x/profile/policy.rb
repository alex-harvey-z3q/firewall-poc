# frozen_string_literal: true
require 'ipaddr'
require 'time'

module FirewallPoc
  # A Puppet catalog-time resolver. All memberships, flows and ports are Hiera data.
  class Policy
    attr_reader :groups, :flows, :inventory

    def initialize(data, now: Time.now)
      @data = data
      @inventory = data.fetch('inventory')
      @nodes = @inventory.fetch('nodes')
      @services = data.fetch('services')
      @definitions = data.fetch('groups')
      @groups = {}
      validate_inventory
      validate_ipam(now)
      validate_services
      @definitions.each_key { |name| resolve_group(name) }
      validate_applications
      @flows = resolve_flows
    end

    def cidr(value)
      raise ArgumentError, "Expected a canonical IPv4 CIDR: #{value.inspect}" unless value.is_a?(String) && value.match?(%r{\A\d+\.\d+\.\d+\.\d+/\d+\z})
      address, prefix = value.split('/')
      net = IPAddr.new(value)
      blocked = %w[0.0.0.0/8 127.0.0.0/8 224.0.0.0/4].map { |n| IPAddr.new(n) }
      unless net.ipv4? && prefix.to_i.between?(1, 32) && net.to_s == address && blocked.none? { |b| overlap?(b, net) }
        raise ArgumentError, "Not an admissible canonical IPv4 network: #{value}"
      end
      net
    rescue IPAddr::InvalidAddressError, IPAddr::InvalidPrefixError => e
      raise ArgumentError, e.message
    end

    def overlap?(a, b)
      a.include?(b.to_range.first) || b.include?(a.to_range.first)
    end

    def contained?(network, scope)
      scope.include?(network.to_range.first) && scope.include?(network.to_range.last)
    end

    def exact_keys(value, keys, label)
      raise ArgumentError, "#{label} must contain exactly #{keys.join(', ')}" unless value.is_a?(Hash) && value.keys.sort == keys.sort
    end

    def names(value, label, empty: false)
      unless value.is_a?(Array) && (empty || !value.empty?) && value.all? { |v| v.is_a?(String) && !v.empty? } && value.uniq == value
        raise ArgumentError, "#{label} must be an array of unique names"
      end
      value
    end

    def validate_inventory
      @vnet = cidr(@inventory.fetch('network'))
      raise ArgumentError, 'Inventory has no nodes' if @nodes.empty?
      used = []
      @nodes.each do |name, node|
        raise ArgumentError, "Invalid node name #{name}" unless name.match?(/\A[a-z][a-z0-9_-]*\z/)
        address = cidr("#{node.fetch('ip')}/32")
        subnet = cidr(@inventory.fetch('subnets').fetch(node.fetch('tier')))
        if used.include?(address.to_s) || !contained?(subnet, @vnet) || !contained?(address, subnet) ||
           address.to_i - subnet.to_i < 4 || address.to_i == subnet.to_range.last.to_i
          raise ArgumentError, "Invalid/duplicate/reserved node address: #{name}"
        end
        used << address.to_s
      end
    end

    def validate_ipam(now)
      snapshot = @data.fetch('ipam')
      exact_keys(snapshot, %w[schema_version revision expires_at groups], 'IPAM snapshot')
      raise ArgumentError, 'IPAM schema/revision required' unless snapshot['schema_version'] == 1 && snapshot['revision'].is_a?(String) && !snapshot['revision'].empty?
      stamp = snapshot['expires_at']
      raise ArgumentError, 'IPAM expiry requires a timezone' unless stamp.is_a?(String) && stamp.match?(/(?:Z|[+-]\d\d:\d\d)\z/)
      expiry = Time.iso8601(stamp)
      raise ArgumentError, 'IPAM expiry must be in the next seven days' unless expiry > now && expiry <= now + 7 * 86400
      scopes = @data.fetch('ipam_scopes')
      exact_keys(snapshot['groups'], scopes.keys, 'IPAM group namespace')
      snapshot['groups'].each do |name, values|
        raise ArgumentError, 'IPAM names must use external. prefix' unless name.start_with?('external.')
        names(values, name, empty: true)
        raise ArgumentError, 'IPAM group exceeds 64 entries' if values.length > 64
        bounds = names(scopes.fetch(name), "scope #{name}").map { |v| cidr(v) }
        values.each do |value|
          net = cidr(value)
          if overlap?(net, @vnet) || bounds.none? { |b| contained?(net, b) }
            raise ArgumentError, "IPAM group exceeds reviewed scope: #{name}"
          end
        end
      end
    end

    def validate_services
      @services.each do |name, service|
        exact_keys(service, %w[protocols ports], "Service #{name}")
        protocols = names(service['protocols'], name)
        ports = service['ports']
        unless (protocols - %w[tcp udp]).empty? && ports.is_a?(Array) && !ports.empty? && ports.length <= 15 &&
               ports.uniq == ports && ports.all? { |p| p.is_a?(Integer) && p.between?(1, 65535) }
          raise ArgumentError, "Invalid protocols/ports in #{name}"
        end
      end
    end

    def resolve_group(name, trail = [])
      return @groups[name] if @groups.key?(name)
      raise ArgumentError, "Cyclic group: #{(trail + [name]).join(' -> ')}" if trail.include?(name)
      definition = @definitions.fetch(name)
      raise ArgumentError, "Group #{name} must have one kind" unless definition.is_a?(Hash) && definition.length == 1
      kind, value = definition.first
      addresses = case kind
                  when 'nodes'
                    names(value, name, empty: true).map { |n| "#{@nodes.fetch(n).fetch('ip')}/32" }
                  when 'networks'
                    names(value, name, empty: true).each { |v| cidr(v) }
                  when 'members'
                    names(value, name, empty: true).flat_map { |g| resolve_group(g, trail + [name]) }
                  when 'ipam'
                    @data.fetch('ipam').fetch('groups').fetch(value)
                  else
                    raise ArgumentError, "Unknown group kind #{kind}"
                  end
      @groups[name] = addresses.uniq.sort
    end

    def validate_applications
      @data.fetch('applications').each do |name, app|
        exact_keys(app, %w[roles listeners], "Application #{name}")
        app['roles'].each_value { |group| @groups.fetch(group) }
        app['listeners'].each do |role, service|
          app['roles'].fetch(role)
          fixture = @services.fetch(service)
          raise ArgumentError, 'Demo listener needs one TCP port' unless fixture['protocols'] == ['tcp'] && fixture['ports'].length == 1
        end
      end
      @nodes.each do |name, node|
        app = @data.fetch('applications').fetch(node.fetch('app'))
        group = app.fetch('roles').fetch(node.fetch('tier'))
        raise ArgumentError, "Node #{name} is not in its declared application role" unless member?(node['ip'], group)
        app.fetch('listeners').fetch(node['tier'])
      end
      @data.fetch('contracts').each do |name, contract|
        exact_keys(contract, %w[from_role to_role service], "Contract #{name}")
        @services.fetch(contract['service'])
      end
    end

    def member?(address, group)
      @groups.fetch(group).any? { |n| cidr(n).include?(IPAddr.new(address)) }
    end

    def resolve_flows
      flows = []
      @data.fetch('connections').each do |name, connection|
        exact_keys(connection, %w[from to contract], "Connection #{name}")
        contract = @data.fetch('contracts').fetch(connection['contract'])
        source = @data.fetch('applications').fetch(connection['from']).fetch('roles').fetch(contract['from_role'])
        target = @data.fetch('applications').fetch(connection['to']).fetch('roles').fetch(contract['to_role'])
        flows << { 'name' => "contract #{name}", 'from' => source, 'to' => target, 'service' => contract['service'] }
      end
      @data.fetch('grants').each do |name, grant|
        exact_keys(grant, %w[from to service], "Grant #{name}")
        flows << grant.merge('name' => "grant #{name}")
      end
      flows.each do |flow|
        @groups.fetch(flow['from'])
        @groups.fetch(flow['to'])
        @services.fetch(flow['service'])
        raise ArgumentError, 'Invalid flow name' unless flow['name'].match?(/\A[a-zA-Z0-9_. -]+\z/)
      end
      flows
    end

    def for_node(name)
      node = @nodes.fetch(name)
      local = ["#{node.fetch('ip')}/32"]
      rules = {}
      @flows.each do |flow|
        sources = @groups.fetch(flow['from'])
        targets = @groups.fetch(flow['to'])
        next if sources.empty? || targets.empty? # Never let an empty array become a wildcard.
        service = @services.fetch(flow['service'])
        [['OUTPUT', 'INPUT', member?(node['ip'], flow['from']), local, targets],
         ['INPUT', 'OUTPUT', member?(node['ip'], flow['to']), sources, local]].each do |chain, reverse, participates, src, dst|
          next unless participates
          common = { 'proto' => service['protocols'], 'jump' => 'accept', 'protocol' => 'IPv4' }
          title = "200 #{flow['name']} #{chain}"
          rules["#{title} request"] = common.merge('chain' => chain, 'source' => src, 'destination' => dst,
            'dport' => service['ports'], 'ctstate' => %w[NEW ESTABLISHED], 'ctdir' => 'ORIGINAL')
          rules["#{title} reply"] = common.merge('chain' => reverse, 'source' => dst, 'destination' => src,
            'sport' => service['ports'], 'ctstate' => ['ESTABLISHED'], 'ctdir' => 'REPLY')
        end
      end
      app = @data.fetch('applications').fetch(node['app'])
      listener = @services.fetch(app.fetch('listeners').fetch(node['tier']))
      { 'rules' => rules, 'listen_ip' => node['ip'], 'listen_port' => listener['ports'].first }
    end
  end
end
