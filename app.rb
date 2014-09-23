require 'sinatra'

class SiteBuilder < Sinatra::Base
  # force https
  before do
    if !request.secure?
      content_type :json
      halt json_status 400,
        "Please use HTTPS: https://#{settings.host}#{request.path}"
    end
  end

  get '/' do
    'hello from site-builder'
  end
end
