#!/usr/bin/env ruby

Dir.chdir(File.dirname(__FILE__))
require './app'

# 'curl' seems to strip all newlines :(
data = STDIN.read.gsub("\n", "")
env = Dotenv.load
signature = hmac_sha1(env['GITHUB_SECRET'], data)
puts signature
