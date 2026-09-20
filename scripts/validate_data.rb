#!/usr/bin/env ruby
# frozen_string_literal: true
require 'optparse'
require_relative 'policy_data'
options = { data: 'puppet/data', json: false }
OptionParser.new do |p|
  p.on('--data PATH') { |v| options[:data] = v }
  p.on('--json') { options[:json] = true }
end.parse!
data = FirewallPoc::PolicyData.load(options[:data])
FirewallPoc::PolicyData.validate(data)
puts(options[:json] ? JSON.pretty_generate(data) : 'Hiera policy and IPAM snapshot are valid')
