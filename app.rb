require 'sinatra'
require 'json'
require 'netaddr'
require 'openssl'

# possible attacks / things to disallow:
# * Sending github push events for repos containing nasty code
# * Sending push events from places other than GitHub
#
# mitigations:
# * Use authenticated web hooks
# * Use whitelisted github orgs/users

set :host, ENV['HOSTNAME']
set :github_secret, ENV['GITHUB_SECRET']
set :authorized_accounts, ENV['AUTHORIZED_ACCOUNTS'].split
set :working_directory, ENV['WORKING_DIRECTORY']
# set :publish_urls, JSON.parse(ENV['PUBLISH_URLS'])
# set :publish_secret, ENV['PUBLISH_SECRET']

before do
  require_https
end

get '/' do
  'hello from site-builder'
end

post '/publish' do
  body = request.body.read
  check_signature(body)
  params = parse_data(body)

  verify(params)
  build(params)
  publish(params)
end

def require_https
  if !request.secure?
    bad_request "Please use HTTPS: https://#{settings.host}#{request.path}"
  end
end

# Checks an HMAC-SHA1 signature of the request body, using a secret key
# shared with GitHub only. This is to prevent anyone other than GitHub
# initiating builds.
def check_signature(body)
  received_signature = request.env['HTTP_X_HUB_SIGNATURE'] || ''
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest(
                OpenSSL::Digest.new('sha1', settings.github_secret, body))

  if !Rack::Utils.secure_compare(signature, received_signature)
    bad_request 'signature mismatch'
  end
end

def parse_data(body)
  begin
    data = JSON.parse(body)
    {
      :repo => data['repository']['name'],
      :branch => data['ref'].split('/')[2],
      :owner => data['repository']['owner']['name'],
      :url => data['repository']['url'],
    }
  rescue => e
    puts e
    bad_request
  end
end

def verify(params)
  if !settings.authorized_accounts.contains?(data[:owner])
    bad_request "bad owner: #{data[:owner]}"
  end
end

def build(params)
  # TODO
end

def publish(params)
  # TODO
end

def bad_request(message = 'Bad request')
  content_type 'text/plain'
  halt 400, message
end
