require 'omniauth-oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Tudou < OmniAuth::Strategies::OAuth
      option :name, 'tudou'
      def initialize(*args)
        super
        # taken from https://github.com/intridea/omniauth/blob/0-3-stable/oa-oauth/lib/omniauth/strategies/oauth/tsina.rb#L15-21
        options.client_options = {
          :access_token_path => '/auth/access_token.oauth',
          :authorize_path => '/auth/authorize.oauth',
          :realm => 'OmniAuth',
          :request_token_path => '/auth/request_token.oauth',
          :site => 'http://api.tudou.com/',
        }
      end

      def consumer
        consumer = ::OAuth::Consumer.new(options.consumer_key, options.consumer_secret, options.client_options)
        consumer
      end

      uid { raw_info['userId'] }

      info do
        {
          :nickname => raw_info['nickName'],
          :name => raw_info['nickName'],
          :image => raw_info['userPicUrl'],
          :urls => {
            'Tudou' => 'http://www.tudou.com/home/' + raw_info['userName']
          }
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      #taken from https://github.com/intridea/omniauth/blob/0-3-stable/oa-oauth/lib/omniauth/strategies/oauth/tsina.rb#L52-67
      def request_phase
        request_token = consumer.get_request_token(:oauth_callback => callback_url)
        session['oauth'] ||= {}
        session['oauth'][name.to_s] = {'callback_confirmed' => true, 'request_token' => request_token.token, 'request_secret' => request_token.secret}

        if request_token.callback_confirmed?
          redirect request_token.authorize_url(options[:authorize_params])
        else
          redirect request_token.authorize_url(options[:authorize_params].merge(:oauth_callback => callback_url))
        end

      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      end

      def raw_info
        @raw_info ||= MultiJson.decode(access_token.get('http://api.tudou.com/auth/verify_credentials.oauth').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end
    end
  end
end