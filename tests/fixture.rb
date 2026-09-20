#!/usr/bin/env ruby
# frozen_string_literal: true
# TEST DATA ONLY: creates an isolated copy with a short, fresh fixture lease.
require 'fileutils'
require 'json'
require 'time'
root = File.expand_path('..', __dir__)
abort 'Usage: tests/fixture.rb OUTPUT_DIRECTORY' unless ARGV.length == 1
output = File.expand_path(ARGV.first)
raise 'Refusing to overwrite live Hiera data' if output == File.join(root, 'puppet')
FileUtils.mkdir_p(File.join(output, 'data/external'))
FileUtils.cp(File.join(root, 'puppet/hiera.yaml'), File.join(output, 'hiera.yaml'))
Dir[File.join(root, 'puppet/data/*.yaml')].each { |f| FileUtils.cp(f, File.join(output, 'data')) }
ipam = JSON.parse(File.read(File.join(root, 'puppet/data/external/ipam.example.json')))
ipam['profile::policy::ipam']['expires_at'] = (Time.now + 3600).utc.iso8601
ipam['profile::policy::ipam']['revision'] = 'test-fixture-only'
File.write(File.join(output, 'data/external/ipam.json'), JSON.pretty_generate(ipam))
