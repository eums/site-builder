require 'sinatra'
require 'json'
require 'netaddr'
require 'openssl'
require 'httparty'
require 'jekyll'

# possible attacks / things to disallow:
# * Sending github push events for repos containing nasty code
# * Sending push events from places other than GitHub
#
# mitigations:
# * Use authenticated web hooks
# * Use whitelisted github orgs/users

def main
  set :host, ENV['HOSTNAME']
  set :secure, to_bool(ENV['SECURE'] || true)
  set :github_secret, ENV['GITHUB_SECRET']
  set :authorized_accounts, ENV['AUTHORIZED_ACCOUNTS'].split
  set :working_directory, ENV['WORKING_DIRECTORY']
  set :publish_urls, JSON.parse(ENV['PUBLISH_URLS'])
  set :publish_secret, ENV['PUBLISH_SECRET']

  if settings.secure
    before do
      require_https
    end
  end

  get '/' do
    'hello from site-builder'
  end

  post '/publish' do
    body = request.body.read
    check_signature(body)
    data = parse_data(body)
    params = make_params(data)

    verify(params)
    build(params)
    publish(params)
  end
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
                OpenSSL::Digest.new('sha1'), settings.github_secret, body)

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

def make_params(data)
  base = [settings.working_directory,
          data[:owner],
          data[:repo],
          data[:branch]
         ].join('/')

  publish_url = settings.publish_urls[data[:branch]] or
    bad_request("no publishing url configured for branch #{data[:branch]}")

  data.merge({
    :source => "#{base}/source",
    :destination => "#{base}/dest",
    :archive => "#{base}/site.tar.gz",
    :publish_url => publish_url,
  })
end

def verify(params)
  if !settings.authorized_accounts.include?(params[:owner])
    bad_request "bad owner: #{params[:owner]}"
  end
end

def build(params)
  if !Dir.exists?(params[:source])
    `git clone #{params[:url]} #{params[:source]}`
  end

  Dir.chdir(params[:source]) do
    `git checkout #{params[:branch]}`
    `git pull origin #{params[:branch]}`
  end

  site = Jekyll::Site.new(
    Jekyll.configuration(
      "source" => params[:source],
      "destination" => params[:destination]))
  site.process

  `tar -czf #{params[:archive]} -C #{params[:destination]} .`
end

def publish(params)
  HTTParty.post(
    params[:publish_url],
    :body => File.read(params[:archive]),
    :headers => { 'Content-Type' => 'application/x-compressed-tar' }})
end

def bad_request(message = 'Bad request')
  content_type 'text/plain'
  halt 400, message
end

def to_bool(x)
  case x
  when String
    if %w(F NO OFF FALSE).include?(x.upcase)
      false
    end
  else
    !!x
  end
end

main
