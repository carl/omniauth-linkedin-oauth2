require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedInOAuth2 < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, 'linkedin_oauth2'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :site => "https://api.linkedin.com",
        :authorize_url => 'https://www.linkedin.com/uas/oauth2/authorization',
        :token_url => "https://www.linkedin.com/uas/oauth2/accessToken",
        :token_method => :get
      }

      option :token_params, {
        :mode => :query
      }

      option :scope, 'r_fullprofile r_emailaddress'

      private

      def linkedin_access_token
        ::OAuth2::AccessToken.new(client, self.access_token.token, {
          :mode => :query,
          :param_name => 'oauth2_access_token'
        })
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
