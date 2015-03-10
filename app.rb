require 'sinatra'
require 'json'
require 'netaddr'
require 'openssl'
require 'httparty'
require 'jekyll'
require 'dotenv'

Dotenv.load

# possible attacks / things to disallow:
# * Sending github push events for repos containing nasty code
# * Sending push events from places other than GitHub
#
# mitigations:
# * Use authenticated web hooks
# * Use whitelisted github orgs/users

class ServerState
  VALID_STATES = %i(idle preparing verifying cloning building uploading)

  attr_accessor(:last_build, :state, :last_params)
  private :state=

  def set_state(s)
    if VALID_STATES.include? s
      self.state = s
    else
      raise "invalid state: #{s}"
    end
  end

  def initialize
    set_state(:idle)
  end
end

class Build
  def initialize
    @start_time = Time.now
  end

  def success
    @succeeded = true
    @end_time = Time.now
  end

  def fail(m)
    @succeeded = false
    @fail_message = m
    @end_time = Time.now
  end

  def finished?
    !@end_time.nil?
  end

  def succeeded?
    finished? && @succeeded
  end

  def failed?
    finished? && !@succeeded
  end

  def summary
    values = [['Started at', @start_time]]

    if self.finished?
      values << ['Finished at', @end_time]
      values << ['Result', @succeeded ? 'Success' : 'Failure']
    end

    if self.failed?
      values << ['Failure reason', @fail_message]
    end

    values
  end

  def to_html
    text = summary.map {|k, v| "#{k}: #{v}" }.join("\n")
    result = "<pre>#{text}</pre>"

    if failed?
      result << '<form action="/retry" method="get">'
      result <<   '<submit type="submit" value="Retry"></submit>'
      result << '</form>'

    end
  end
end

GlobalState = ServerState.new

class Publisher
  include HTTParty

  # Give the server five minutes before giving up
  read_timeout 300

  def self.publish(url, data, signature)
    post(
      url,
      :body => data,
      :headers => {
        'Content-Type' => 'application/x-compressed-tar',
        'X-Signature' => signature
      })
  end
end

def main
  safe_set :host, ENV['HOSTNAME']
  safe_set :secure, to_bool(ENV['SECURE'] || true)
  safe_set :github_secret, ENV['GITHUB_SECRET']
  safe_set :authorized_accounts, ENV['AUTHORIZED_ACCOUNTS'].split
  safe_set :working_directory, ENV['WORKING_DIRECTORY']
  safe_set :publish_urls, JSON.parse(ENV['PUBLISH_URLS'])
  safe_set :publish_secret, ENV['PUBLISH_SECRET']

  if settings.secure
    before do
      require_https
    end
  end

  get '/' do
    values = [ "<h1>site-builder</h1>",
               "<h2>Status</h2>",
               "<p>#{GlobalState.state}</p>"
             ]

    if GlobalState.last_build.is_a? Build
      values << "<h2>Last build</h2>"
      values << GlobalState.last_build.to_html
    end

    render_layout(values.join(""))
  end

  post '/publish' do
    already_in_progress =
      [ 403, {}, "A build is already in progress. Please try again later.\n" ]
    return already_in_progress if GlobalState.state != :idle

    start_build!
    [ 201, {}, "Build started\n" ]
  end

  post '/retry' do
    params = GlobalState.last_params
    if params
      start_build!(params)
      [ 201, {}, "Build started\n" ]
    else
      [ 400, {}, "I don't know which build you want me to retry.\n" ]
    end
  end

  def build_action(state)
    begin
      GlobalState.set_state(state)
      yield
    rescue => e
      GlobalState.last_build.fail(e.to_s + "\n" + e.backtrace.join("\n"))
      GlobalState.set_state(:idle)
      puts "Build failed: #{e}"
      fail e
    end
  end

  def start_build!(params=nil)
    Thread.new do
      begin
        GlobalState.last_build = Build.new

        if !params
          body = request.body.read

          params = build_action(:preparing) {
            check_signature(body)
            data = parse_data(body)
            make_params(data)
          }
        end

        GlobalState.last_params = params

        build_action(:verifying) { verify(params) }
        build_action(:cloning)   { clone_repo(params) }
        build_action(:building)  { build(params) }
        build_action(:uploading) { publish(params) }

        GlobalState.last_build.success
        GlobalState.last_params = nil
      ensure
        GlobalState.set_state(:idle)
      end
    end
  end
end

def safe_set(key, value)
  fail "Configuration missing: #{key}" if value.nil?
  set key, value
end

def require_https
  if !request.secure?
    redirect "https://#{settings.host}#{request.path}", 301
  end
end

# Checks an HMAC-SHA1 signature of the request body, using a secret key
# shared with GitHub only. This is to prevent anyone other than GitHub
# initiating builds.
def check_signature(body)
  received_signature = request.env['HTTP_X_HUB_SIGNATURE'] || ''
  signature = 'sha1=' + hmac_sha1(settings.github_secret, body)

  if !Rack::Utils.secure_compare(signature, received_signature)
    build_failed('signature mismatch')
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
    build_failed(e)
  end
end

def make_params(data)
  base = [settings.working_directory,
          data[:owner],
          data[:repo],
          data[:branch]
         ].join('/')

  publish_url = settings.publish_urls[data[:branch]] or
    build_failed("no publishing url configured for branch #{data[:branch]}")

  data.merge({
    :source => "#{base}/source",
    :destination => "#{base}/dest",
    :archive => "#{base}/site.tar.gz",
    :publish_url => publish_url,
  })
end

def verify(params)
  if !settings.authorized_accounts.include?(params[:owner])
    build_failed("bad owner: #{params[:owner]}")
  end
end

def clone_repo(params)
  if !Dir.exists?(params[:source])
    `git clone #{params[:url]} #{params[:source]}`
  end

  Dir.chdir(params[:source]) do
    `git checkout #{params[:branch]}`
    `git pull origin #{params[:branch]}`
  end
end

def build(params)
  site = Jekyll::Site.new(
    Jekyll.configuration(
      "source" => params[:source],
      "destination" => params[:destination]))

  site.process

  set_modes(params[:destination])

  `tar -czf #{params[:archive]} -C #{params[:destination]} .`
end

# Set the mode of all files in a directory to 0644, and all directories in it
# to 0755.
def set_modes(dir)
  Dir.glob("#{dir}/**/*", File::FNM_DOTMATCH).each do |path|
    next if File.basename(path) == '.'

    if File.directory? path
      File.chmod(0755, path)
    else
      File.chmod(0644, path)
    end
  end
end

def hmac_sha1(key, data)
  OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), key, data)
end

def publish(params)
  data = File.read(params[:archive])
  signature = hmac_sha1(settings.publish_secret, data)

  Publisher.publish(params[:publish_url], data, signature)
end

class BuildFailed < StandardError
end

def build_failed(message)
  raise BuildFailed.new(message)
end

def render_layout(str)
  "<!doctype html>
  <html>
    <head>
      <meta charset=\"utf-8\">
      <title>site-builder</title>
    </head>
    <body>
      #{str}
    </body>
  </html>"
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
