require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedInOAuth2 < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, 'linkedin_oauth2'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :site => 'https://api.linkedin.com',
        :authorize_url => '/uas/oauth2/authorization?response_type=code',
        :token_url => '/uas/oauth2/accessToken'
      }

      option :scope, 'r_fullprofile r_emailaddress'

      private

      def linkedin_access_token
        ::OAuth2::AccessToken.new(client, self.access_token.token, {
          :mode => :query,
          :param_name => 'oauth2_access_token'
        })
      end

      def request_phase
        if signed_request_contains_access_token?
          # if we already have an access token, we can just hit the
          # callback URL directly and pass the signed request along
          params = {:signed_request => raw_signed_request}
          params[:state] = @state
          query = Rack::Utils.build_query(params)

          url = callback_url
          url << "?" unless url.match(/\?/)
          url << "&" unless url.match(/[\&\?]$/)
          url << query

          redirect url
        else
          super
        end
      end

      def authorize_params
        @state = SecureRandom.hex(15) #A unique long string that is not easy to guess
        super.tap do |params|
          # to support omniauth-oauth2's auto csrf protection
          session['omniauth.state'] = params[:state] = @state
        end
      end

      def signed_request_contains_access_token?
        signed_request &&
          signed_request['oauth_token']
      end

      def signed_request
        @signed_request ||= request.params['signed_request']
      end

    end
  end
end

OmniAuth.config.add_camelization 'linkedin_oauth2', 'LinkedInOAuth2'
