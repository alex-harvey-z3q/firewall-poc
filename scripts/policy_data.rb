# frozen_string_literal: true
# Transport/validation helpers only. Puppet itself performs Hiera lookup and rule resolution.
require 'yaml'
require 'json'
require 'fileutils'
require_relative '../puppet/modules/profile/lib/puppet_x/profile/policy'

module FirewallPoc
  module PolicyData
    FILE_KEYS = {
      'inventory.yaml' => %w[inventory],
      'groups.yaml' => %w[groups ipam_scopes],
      'policy.yaml' => %w[services applications contracts connections grants],
      'common.yaml' => [],
      'external/ipam.json' => %w[ipam]
    }.freeze

    def self.load(directory, snapshot: nil)
      data = {}
      FILE_KEYS.each do |file, keys|
        next if file == 'common.yaml'
        document = if file == 'external/ipam.json' && snapshot
                     { 'profile::policy::ipam' => snapshot }
                   else
                     YAML.safe_load(File.read(File.join(directory, file)), permitted_classes: [], aliases: false)
                   end
        expected = keys.map { |key| "profile::policy::#{key}" }
        unless document.is_a?(Hash) && document.keys.sort == expected.sort
          raise ArgumentError, "Unexpected Hiera keys in #{file}"
        end
        keys.each { |key| data[key] = document.fetch("profile::policy::#{key}") }
      end
      data
    end

    def self.validate(data)
      policy = Policy.new(data)
      data.fetch('inventory').fetch('nodes').each_key { |node| policy.for_node(node) }
      policy
    end

    def self.bundle(directory, node)
      { 'node' => node, 'data_files' => FILE_KEYS.keys.to_h { |file| [file, File.read(File.join(directory, file))] } }
    end
  end
end
