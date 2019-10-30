# frozen_string_literal: true

# name: discourse-patreon-creator
# about: Integration features between Patreon and Discourse for Creators
# version: 1.0
# author: Dan Bosan from Mutations Limited <dan@mutations.ltd>
# url: https://github.com/discourse/discourse-patreon-creator

require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'

enabled_site_setting :patreon_creator_enabled

PLUGIN_NAME = 'discourse-patreon-creator'.freeze

register_svg_icon "fab-patreon" if respond_to?(:register_svg_icon)

after_initialize do

  require_dependency 'admin_constraint'

  module ::Patreon
    PLUGIN_NAME = 'discourse-patreon-creator'.freeze

    class Engine < ::Rails::Engine
      engine_name PLUGIN_NAME
      isolate_namespace Patreon
    end

    def self.default_image_url
      "#{Discourse.base_url}/plugins/discourse-patreon-creator/images/patreon-logomark-color-on-white.png"
    end

    def self.store
      @store ||= PluginStore.new(PLUGIN_NAME)
    end

    def self.get(key)
      store.get(key)
    end

    def self.set(key, value)
      store.set(key, value)
    end
  end

  [
    '../app/jobs/scheduled/patreon_update_tokens.rb',
    '../lib/api.rb',
    '../lib/patron.rb',
    '../lib/tokens.rb'
  ].each { |path| load File.expand_path(path, __FILE__) }

  AdminDashboardData.problem_messages << ::Patreon::Api::ACCESS_TOKEN_INVALID

  Discourse::Application.routes.prepend do
    mount ::Patreon::Engine, at: '/patreon'
  end

  class ::OmniAuth::Strategies::Patreon
    option :name, 'patreon'

    option :client_options,
      site: 'https://www.patreon.com',
      authorize_url: 'https://www.patreon.com/oauth2/authorize',
      token_url: 'https://api.patreon.com/oauth2/token'

    option :authorize_params, response_type: 'code'

    def custom_build_access_token
      verifier = request.params['code']
      client.auth_code.get_token(verifier, redirect_uri: options.redirect_uri)
    end

    alias_method :build_access_token, :custom_build_access_token

    uid {
      raw_info['data']['id'].to_s
    }

    info do
      {
        email: raw_info['data']['attributes']['email'],
        name: raw_info['data']['attributes']['full_name'],
        access_token: access_token.token,
        refresh_token: access_token.refresh_token
      }
    end

    extra do
      {
        raw_info: raw_info
      }
    end

    def raw_info
      @raw_info ||= begin
        response = client.request(:get, "https://api.patreon.com/oauth2/api/current_user", headers: {
            'Authorization' => "Bearer #{access_token.token}"
        }, parse: :json)

        campaign_response = begin
          client.request(:get, "https://api.patreon.com/oauth2/api/current_user/campaigns", headers: {
              'Authorization' => "Bearer #{access_token.token}"
          }, parse: :json).parsed
        rescue => e
          Rails.logger.warn("Error while getting campaign info with error: #{e}.\n\n #{e.backtrace.join("\n")}")

          # Return the data in the same format as the API call, just with no campaigns.
          {
            data: []
          }
        end

        response.parsed.merge({ campaign: campaign_response })
      end
    end
  end

  DiscourseEvent.on(:user_created) do |user|
    if SiteSetting.patreon_creator_enabled
      begin
        nsfw_group = Group.find_by_name(SiteSetting.patreon_creator_nsfw_group)

        user_info = Patreon.get("user_info") || {}
        user_record = user_info[user.email] || {}
        has_nsfw_campaign = user_record[:has_nsfw_campaign]

        if nsfw_group && user
          has_nsfw_campaign ? nsfw_group.add(user) : nsfw_group.remove(user)
        end

        Patreon::Patron.update_local_user(user, user_record[:patreon_id], true)
      rescue => e
        Rails.logger.warn("Patreon group membership callback failed for new user #{self.id} with error: #{e}.\n\n #{e.backtrace.join("\n")}")
      end
    end
  end
end

# Authentication with Patreon
class OmniAuth::Strategies::Patreon < OmniAuth::Strategies::OAuth2
end

class Auth::PatreonAuthenticator < Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :patreon,
                      setup: lambda { |env|
                        strategy = env['omniauth.strategy']
                        strategy.options[:client_id] = SiteSetting.patreon_creator_client_id
                        strategy.options[:client_secret] = SiteSetting.patreon_creator_client_secret
                        strategy.options[:redirect_uri] = "#{Discourse.base_url}/auth/patreon/callback"
                        strategy.options[:provider_ignores_state] = SiteSetting.patreon_creator_login_ignore_state
                      }
  end

  def after_authenticate(auth_token)
    result = super

    user = result.user
    discourse_username = SiteSetting.patreon_creator_discourse_username
    if discourse_username.present? && user && user.username == discourse_username
      SiteSetting.patreon_creator_access_token = auth_token[:info][:access_token]
      SiteSetting.patreon_creator_refresh_token = auth_token[:info][:refresh_token]
    end

    if auth_token[:extra][:raw_info][:campaign][:data].empty?
      result.failed = true
      result.failed_reason = "You need to be a Creator to use this forum."
    else
      nsfw_group = Group.find_by_name(SiteSetting.patreon_creator_nsfw_group)
      has_nsfw_campaign = auth_token[:extra][:raw_info][:campaign][:data].any? do |campaign|
        campaign[:attributes][:is_nsfw]
      end

      # Store Patreon ID and NSFW campaign flag for the user
      # It will be used in the DiscourseEvent.on(:user_created) callback
      user_info = Patreon.get("user_info") || {}
      user_record = user_info[result.email] || {}
      user_record[:has_nsfw_campaign] = has_nsfw_campaign
      user_record[:patreon_id] = result.extra_data[:uid]
      user_info[result.email] = user_record
      Patreon.set("user_info", user_info)

      if nsfw_group && user
        has_nsfw_campaign ? nsfw_group.add(user) : nsfw_group.remove(user)
      end
    end

    result
  end

  def enabled?
    SiteSetting.patreon_creator_login_enabled
  end
end

auth_provider pretty_name: 'Patreon',
              title: 'with Patreon',
              message: 'Authentication with Patreon (make sure pop up blockers are not enabled)',
              frame_width: 840,
              frame_height: 570,
              authenticator: Auth::PatreonAuthenticator.new('patreon', trusted: true),
              enabled_setting: 'patreon_creator_login_enabled'
