#!/usr/bin/env ruby
# frozen_string_literal: true
require 'optparse'
require_relative 'policy_data'
options = { data: 'puppet/data', output: 'build/bundles' }
OptionParser.new do |p|
  p.on('--data PATH') { |v| options[:data] = v }
  p.on('--output PATH') { |v| options[:output] = v }
end.parse!
data = FirewallPoc::PolicyData.load(options[:data])
FirewallPoc::PolicyData.validate(data)
FileUtils.mkdir_p(options[:output])
data.fetch('inventory').fetch('nodes').each_key do |node|
  File.write(File.join(options[:output], "#{node}.json"),
             JSON.pretty_generate(FirewallPoc::PolicyData.bundle(options[:data], node)) + "\n")
end
