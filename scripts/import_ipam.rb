#!/usr/bin/env ruby
# frozen_string_literal: true
require 'optparse'
require 'tempfile'
require_relative 'policy_data'
directory = 'puppet/data'
OptionParser.new { |p| p.on('--data PATH') { |v| directory = v } }.parse!
abort 'Usage: import_ipam.rb [--data DIR] vendor-export.json' unless ARGV.length == 1
snapshot = JSON.parse(File.read(ARGV.first))
FirewallPoc::PolicyData.validate(FirewallPoc::PolicyData.load(directory, snapshot: snapshot))
output = File.join(directory, 'external')
FileUtils.mkdir_p(output)
Tempfile.create(['ipam', '.json'], output) do |file|
  file.write(JSON.pretty_generate('profile::policy::ipam' => snapshot) + "\n")
  file.flush
  File.rename(file.path, File.join(output, 'ipam.json'))
end
puts "Imported IPAM revision #{snapshot.fetch('revision')} into #{output}/ipam.json"
