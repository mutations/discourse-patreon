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

    def self.get(key)
      store.get(key)
    end

    def self.get_user_info_record(email)
      get("user_info.#{email}") || {}
    end

    def self.nsfw_group
      @nsfw_group = Group.find_by_name(SiteSetting.patreon_creator_nsfw_group)
    end

    def self.remove(key)
      store.remove(key)
    end

    def self.save_user_info(user, email, patreon_id, has_nsfw_campaign, bypass_creator_logic)
      plugin_store_key = "user_info.#{email}"
      if user
        user.custom_fields["bypass_creator_logic"] = bypass_creator_logic
        user.custom_fields["has_nsfw_campaign"] = has_nsfw_campaign
        user.custom_fields["patreon_id"] = patreon_id
        user.save_custom_fields

        # Remove the temp data from the plugin store
        remove(plugin_store_key)
      else
        # Save data in PluginStore, will be saved to user in
        # :user_created call back

        user_info_record = get(plugin_store_key) || {}
        user_info_record[:bypass_creator_logic] = bypass_creator_logic
        user_info_record[:has_nsfw_campaign] = has_nsfw_campaign
        user_info_record[:patreon_id] = patreon_id
        set_user_info_record(email, user_info_record)
      end
    end

    def self.set(key, value)
      store.set(key, value)
    end

    def self.set_user_info_record(email, value)
      set("user_info.#{email}", value)
    end

    def self.store
      @store ||= PluginStore.new(PLUGIN_NAME)
    end

    def self.add_remove_nsfw_group(user, has_nsfw_campaign)
      return unless user && nsfw_group

      has_nsfw_campaign ? nsfw_group.add(user) : nsfw_group.remove(user)
    end
  end

  [
    '../app/jobs/scheduled/patreon_update_tokens.rb',
    '../lib/api.rb',
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
        user_info_record = Patreon.get_user_info_record(user.email)

        Patreon.add_remove_nsfw_group(user, user_info_record[:has_nsfw_campaign])

        Patreon.save_user_info(
          user,
          user.email,
          user_info_record[:patreon_id],
          user_info_record[:has_nsfw_campaign],
          user_info_record[:bypass_creator_logic]
        )
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

    published_campaign = auth_token[:extra][:raw_info][:campaign][:data].any? do |campaign|
      campaign[:attributes][:published_at].present?
    end

    bypass_creator_logic = /.*@patreon\.com$/.match?(result.email)

    if published_campaign || bypass_creator_logic
      has_nsfw_campaign = auth_token[:extra][:raw_info][:campaign][:data].any? do |campaign|
        campaign[:attributes][:is_nsfw]
      end

      Patreon.add_remove_nsfw_group(user, has_nsfw_campaign) unless bypass_creator_logic

      # Save the patreon_id and has_nsfw_campaign to the user in the custom fields
      # When there is no user, the data is stored in the PluginStore
      # and used in the :user_created event
      Patreon.save_user_info(
        user,
        result.email,
        result.extra_data[:uid],
        has_nsfw_campaign,
        bypass_creator_logic
      )
    else
      result.failed = true
      result.failed_reason = "This forum is for launched Patreon creators only. Visit <a href='https://patreon.com/faq'>patreon.com/faq</a> if you need further help. Thanks!".html_safe
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
