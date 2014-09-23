require 'sinatra'

class SiteBuilder < Sinatra::Base
  get '/' do
    'hello from site-builder'
  end
end
