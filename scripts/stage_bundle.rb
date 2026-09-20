#!/usr/bin/env ruby
# frozen_string_literal: true
require_relative 'policy_data'
abort 'Usage: stage_bundle.rb BUNDLE RUN_DIRECTORY' unless ARGV.length == 2
bundle = JSON.parse(File.read(ARGV[0]))
raise ArgumentError, 'Unexpected bundle keys' unless bundle.keys.sort == %w[data_files node]
raise ArgumentError, 'Unexpected Hiera files' unless bundle['data_files'].keys.sort == FirewallPoc::PolicyData::FILE_KEYS.keys.sort
node = bundle.fetch('node')
raise ArgumentError, 'Invalid node name' unless node.match?(/\A[a-z][a-z0-9_-]*\z/)
directory = File.join(ARGV[1], 'data')
bundle['data_files'].each do |relative, content|
  target = File.join(directory, relative)
  FileUtils.mkdir_p(File.dirname(target))
  File.write(target, content)
end
data = FirewallPoc::PolicyData.load(directory)
FirewallPoc::PolicyData.validate(data).for_node(node)
FileUtils.cp(File.expand_path('../puppet/hiera.yaml', __dir__), File.join(ARGV[1], 'hiera.yaml'))
puts node
