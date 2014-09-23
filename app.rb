require 'sinatra'

class SiteBuilder < Sinatra::Base
  set :host, ENV['HOSTNAME']

  # force https
  before do
    if !request.secure?
      content_type 'text/plain'
      halt 400, "Please use HTTPS: https://#{settings.host}#{request.path}"
    end
  end

  get '/' do
    'hello from site-builder'
  end
end
