# frozen_string_literal: true

require 'openssl'
require 'json'

class ::Patreon::PatreonWebhookController < ApplicationController

  skip_before_action :redirect_to_login_if_required, :preload_json, :check_xhr, :verify_authenticity_token

  TRIGGERS = ['pledges:create', 'pledges:update', 'pledges:delete']

  def index
    raise Discourse::InvalidAccess.new unless is_valid?

    pledge_data = JSON.parse(request.body.read)

    if SiteSetting.patreon_creator_verbose_log
      Rails.logger.warn("Patreon verbose log for Webhook:\n #{pledge_data.inspect}")
    end

    case event
    when 'pledges:create'
      Patreon::Pledge.create!(pledge_data)
    when 'pledges:update'
      Patreon::Pledge.update!(pledge_data)
    when 'pledges:delete'
      Patreon::Pledge.delete!(pledge_data)
    end

    Jobs.enqueue(:sync_local_patrons_to_groups)

    render body: nil, status: 200
  end

  def event
    request.headers['X-Patreon-Event']
  end

  def is_valid?
    TRIGGERS.include?(event) && is_valid_signature?
  end

  private

  def is_valid_signature?
    signature = request.headers['X-Patreon-Signature']
    digest = OpenSSL::Digest::MD5.new

    signature == OpenSSL::HMAC.hexdigest(digest, SiteSetting.patreon_creator_webhook_secret, request.raw_post)
  end
end
