# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'open3'
require_relative '../scripts/policy_data'

class PolicyTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  NOW = Time.utc(2026, 9, 20)

  def setup
    snapshot = JSON.parse(File.read(File.join(ROOT, 'puppet/data/external/ipam.example.json')))['profile::policy::ipam']
    @data = FirewallPoc::PolicyData.load(File.join(ROOT, 'puppet/data'), snapshot: snapshot)
  end

  def policy
    FirewallPoc::Policy.new(@data, now: NOW)
  end

  def test_nested_groups_resolve_inventory_addresses
    assert_equal %w[10.42.1.10/32 10.42.2.10/32 10.42.3.10/32], policy.groups['app_a']
    assert_equal 6, policy.groups['application_hosts'].size
    assert_equal ['10.60.0.10/32'], policy.groups['administrators']
  end

  def test_exact_request_matrix_on_both_endpoints
    p = policy
    nodes = @data['inventory']['nodes']
    expected = [%w[app_a-web app_a-api] + [9000], %w[app_a-api app_a-db] + [15432],
                %w[app_b-web app_b-api] + [9000], %w[app_b-api app_b-db] + [15432],
                %w[app_a-api app_b-api] + [9000]]
    addresses = nodes.transform_values { |n| n['ip'] }.merge('admin' => '10.60.0.10', 'client' => '10.61.0.10', 'outsider' => '10.62.0.10')
    expected += nodes.keys.map { |n| ['admin', n, 22] }
    expected += %w[app_a-web app_b-web].map { |n| ['client', n, 8080] }
    addresses.each do |source, source_ip|
      nodes.each do |target, target_node|
        next if source == target
        [22, 8080, 9000, 15432, 9999].each do |port|
          allowed = expected.include?([source, target, port])
          [target, (source if nodes.key?(source))].compact.each do |host|
            chain = host == source ? 'OUTPUT' : 'INPUT'
            rules = p.for_node(host)['rules'].values
            actual = rules.any? do |r|
              r['chain'] == chain && r['ctdir'] == 'ORIGINAL' && r['dport'].include?(port) &&
                r['source'].any? { |cidr| IPAddr.new(cidr).include?(source_ip) } &&
                r['destination'].any? { |cidr| IPAddr.new(cidr).include?(target_node['ip']) }
            end
            assert_equal allowed, actual, "#{host} #{chain}: #{source} -> #{target}:#{port}"
          end
        end
      end
    end
  end

  def test_hiera_only_contract_revocation_removes_request_and_reply
    @data['connections'].delete('a_calls_b')
    %w[app_a-api app_b-api].each do |node|
      refute policy.for_node(node)['rules'].keys.any? { |n| n.include?('a_calls_b') }
    end
  end

  def test_hiera_only_service_port_change
    @data['services']['api']['ports'] = [9443]
    rules = policy.for_node('app_a-api')['rules']
    cross = rules.select { |name, _| name.include?('a_calls_b') }.values
    assert_equal [9443], cross.first['dport']
    assert_equal [9443], cross.last['sport']
    assert_equal 9443, policy.for_node('app_a-api')['listen_port']
  end

  def test_no_blanket_established_rules_or_empty_endpoints
    @data['inventory']['nodes'].each_key do |node|
      policy.for_node(node)['rules'].each_value do |rule|
        refute_empty rule['source']
        refute_empty rule['destination']
        if rule['ctdir'] == 'REPLY'
          assert_equal ['ESTABLISHED'], rule['ctstate']
          refute_empty rule['sport']
        else
          assert_equal %w[NEW ESTABLISHED], rule['ctstate']
        end
      end
    end
  end

  def test_empty_ipam_group_grants_nothing
    @data['ipam']['groups']['external.admins'] = []
    refute policy.for_node('app_a-web')['rules'].keys.any? { |n| n.include?('administration') }
  end

  def test_membership_replacement
    @data['ipam']['groups']['external.admins'] = ['10.60.0.11/32']
    text = JSON.generate(policy.for_node('app_a-web'))
    refute_includes text, '10.60.0.10/32'
    assert_includes text, '10.60.0.11/32'
  end

  def test_out_of_scope_and_noncanonical_addresses
    %w[0.0.0.0/0 10.42.2.10/32 192.0.2.0/24 host.example 10.60.0.10/24].each do |bad|
      @data['ipam']['groups']['external.admins'] = [bad]
      assert_raises(ArgumentError) { policy }
    end
  end

  def test_unknown_ipam_group_cannot_replace_internal_group
    @data['ipam']['groups']['app_a.api'] = ['10.42.2.20/32']
    assert_raises(ArgumentError) { policy }
  end

  def test_expired_unbounded_and_unzoned_snapshots
    %w[2026-09-19T00:00:00Z 2027-01-01T00:00:00Z 2026-09-21T00:00:00].each do |stamp|
      @data['ipam']['expires_at'] = stamp
      assert_raises(ArgumentError) { policy }
    end
  end

  def test_duplicate_and_oversized_memberships
    @data['ipam']['groups']['external.admins'] = ['10.60.0.10/32'] * 2
    assert_raises(ArgumentError) { policy }
    @data['ipam']['groups']['external.admins'] = (1..65).map { |i| "10.60.0.#{i}/32" }
    assert_raises(ArgumentError) { policy }
  end

  def test_unknown_contract_rejected
    @data['connections']['a_calls_b']['contract'] = 'everything'
    assert_raises(KeyError) { policy }
  end

  def test_unknown_member_and_cycles_rejected
    @data['groups']['app_a']['members'] = ['missing']
    assert_raises(KeyError) { policy }
    @data['groups']['app_a']['members'] = ['application_hosts']
    assert_raises(ArgumentError) { policy }
  end

  def test_unknown_service_and_ambiguous_group_rejected
    @data['grants']['users_to_a']['service'] = 'unknown'
    assert_raises(KeyError) { policy }
    @data['grants']['users_to_a']['service'] = 'web'
    @data['groups']['app_a.web']['networks'] = ['10.42.1.0/24']
    assert_raises(ArgumentError) { policy }
  end

  def test_duplicate_node_address_rejected
    @data['inventory']['nodes']['app_b-api']['ip'] = '10.42.2.10'
    assert_raises(ArgumentError) { policy }
  end

  def test_missing_group_rejected
    @data['ipam']['groups'].delete('external.admins')
    assert_raises(ArgumentError) { policy }
  end

  def test_import_is_atomic_and_emits_only_ipam_hiera_key
    Dir.mktmpdir do |dir|
      FileUtils.cp_r(File.join(ROOT, 'puppet/data/.'), dir)
      candidate = File.join(dir, 'candidate.json')
      snapshot = @data['ipam']
      snapshot['expires_at'] = (Time.now + 3600).utc.iso8601
      File.write(candidate, JSON.generate(snapshot))
      command = [RbConfig.ruby, File.join(ROOT, 'scripts/import_ipam.rb'), '--data', dir, candidate]
      _, error, status = Open3.capture3(*command)
      assert status.success?, error
      live = File.join(dir, 'external/ipam.json')
      before = File.read(live)
      assert_equal ['profile::policy::ipam'], JSON.parse(before).keys
      snapshot['groups']['external.admins'] = ['0.0.0.0/0']
      File.write(candidate, JSON.generate(snapshot))
      _, _, status = Open3.capture3(*command)
      refute status.success?
      assert_equal before, File.read(live)
    end
  end
end
