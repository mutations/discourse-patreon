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

register_asset 'stylesheets/patreon.scss'

register_svg_icon "fab-patreon" if respond_to?(:register_svg_icon)

after_initialize do

  require_dependency 'admin_constraint'

  module ::Patreon
    PLUGIN_NAME = 'discourse-patreon-creator'.freeze
    USER_DETAIL_FIELDS = ["id", "email", "amount_cents", "rewards", "declined_since"].freeze

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

    class Reward

      def self.all
        Patreon.get("rewards") || {}
      end

    end

    class RewardUser

      def self.all
        Patreon.get("reward-users") || {}
      end

    end
  end

  [
    '../app/controllers/patreon_admin_controller.rb',
    '../app/controllers/patreon_webhook_controller.rb',
    '../app/jobs/regular/sync_local_patrons_to_groups.rb',
    '../app/jobs/scheduled/patreon_sync_patrons_to_groups.rb',
    '../app/jobs/scheduled/patreon_update_tokens.rb',
    '../app/jobs/onceoff/update_brand_images.rb',
    '../app/jobs/onceoff/migrate_patreon_user_infos.rb',
    '../lib/api.rb',
    '../lib/seed.rb',
    '../lib/campaign.rb',
    '../lib/pledge.rb',
    '../lib/patron.rb',
    '../lib/tokens.rb'
  ].each { |path| load File.expand_path(path, __FILE__) }

  AdminDashboardData.problem_messages << ::Patreon::Api::ACCESS_TOKEN_INVALID

  Patreon::Engine.routes.draw do
    get '/rewards' => 'patreon_admin#rewards', constraints: AdminConstraint.new
    get '/list' => 'patreon_admin#list', constraints: AdminConstraint.new
    post '/list' => 'patreon_admin#edit', constraints: AdminConstraint.new
    delete '/list' => 'patreon_admin#delete', constraints: AdminConstraint.new
    post '/sync_groups' => 'patreon_admin#sync_groups', constraints: AdminConstraint.new
    post '/update_data' => 'patreon_admin#update_data', constraints: AdminConstraint.new
    post '/webhook' => 'patreon_webhook#index'
  end

  Discourse::Application.routes.prepend do
    mount ::Patreon::Engine, at: '/patreon'
  end

  add_admin_route 'patreon.title', 'patreon'

  Discourse::Application.routes.append do
    get '/admin/plugins/patreon' => 'admin/plugins#index', constraints: AdminConstraint.new
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
          {}
        end

        Rails.logger.info("** ** campaign_response: #{campaign_response.to_yaml}")
        response.parsed.merge({ campaign: campaign_response })
      end
    end
  end

  DiscourseEvent.on(:user_created) do |user|
    Rails.logger.info("** Entered DiscourseEvent.on(:user_created)")
    if SiteSetting.patreon_creator_enabled
      begin
        nsfw_group = Group.find_by_name(SiteSetting.patreon_creator_nsfw_group)

        user_info = Patreon.get("user_info") || {}
        user_record = user_info[user.email] || {}
        Rails.logger.info("** user_record: #{user_record.to_yaml}")
        has_nsfw_campaign = user_record[:has_nsfw_campaign]
        Rails.logger.info("** has_nsfw_campaign: #{has_nsfw_campaign}")

        if nsfw_group && user
          has_nsfw_campaign ? nsfw_group.add(user) : nsfw_group.remove(user)
        end

        Patreon::Patron.update_local_user(user, user_record[:patreon_id], true)
      rescue => e
        Rails.logger.warn("Patreon group membership callback failed for new user #{self.id} with error: #{e}.\n\n #{e.backtrace.join("\n")}")
      end
    end
  end

  ::Patreon::USER_DETAIL_FIELDS.each do |attribute|
    add_to_serializer(:admin_detailed_user, "patreon_#{attribute}".to_sym, false) do
      ::Patreon::Patron.attr(attribute, object)
    end

    add_to_serializer(:admin_detailed_user, "include_patreon_#{attribute}?".to_sym) do
      ::Patreon::Patron.attr(attribute, object).present?
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

    inspect_data = auth_token[:extra][:raw_info]
    Rails.logger.info("auth_token.keys: #{auth_token[:extra][:raw_info].keys}")
    [:data, :links].each do |key|
      Rails.logger.info("auth_token[:extra][:raw_info][#{key.to_s}].keys: #{inspect_data[key].keys}")
      Rails.logger.info("auth_token[:extra][:raw_info][#{key.to_s}].inspect: #{inspect_data[key].inspect}")
    end

    user = result.user
    discourse_username = SiteSetting.patreon_creator_creator_discourse_username
    if discourse_username.present? && user && user.username == discourse_username
      SiteSetting.patreon_creator_creator_access_token = auth_token[:info][:access_token]
      SiteSetting.patreon_creator_creator_refresh_token = auth_token[:info][:refresh_token]
    end

    Rails.logger.info("**|| auth_token[:extra][:raw_info][:campaign]: #{auth_token[:extra][:raw_info][:campaign].inspect}")
    if auth_token[:extra][:raw_info][:campaign].empty?
      result.failed = true
      result.failed_reason = "You need to be a Creator to use this forum."
    else
      Rails.logger.info("** result: #{result.inspect}")
      Rails.logger.info("** is user nil?: #{user.nil?}")
      Rails.logger.info("** user: #{user.inspect}")
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
      Rails.logger.info("** user_record: #{user_record.to_yaml}")
      Patreon.set("user_info", user_record)

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
