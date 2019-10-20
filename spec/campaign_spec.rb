# frozen_string_literal: true

require 'rails_helper'
require_relative 'spec_helper'

RSpec.describe ::Patreon::Campaign do
  include_context "spec helper"

  before do
    campaigns_url = "https://api.patreon.com/oauth2/api/current_user/campaigns?include=rewards,creator,goals,pledges&page%5Bcount%5D=100"
    pledges_url = "https://www.patreon.com/api/oauth2/api/campaigns/70261/pledges?page%5Bcount%5D=100&sort=created"
    content = { status: 200, headers: { "Content-Type" => "application/json" } }

    campaigns = content.merge(body: get_patreon_response('campaigns.json'))
    pledges = content.merge(body: get_patreon_response('pledges.json'))

    stub_request(:get, campaigns_url).to_return(campaigns)
    stub_request(:get, pledges_url).to_return(pledges)
    SiteSetting.patreon_creator_enabled = true
    SiteSetting.patreon_creator_declined_pledges_grace_period_days = 7
  end

  it "should update campaigns and group users data" do
    expect {
      described_class.update!
    }.to change { Group.count }.by(1)
      .and change { Badge.count }.by(1)

    expect(get('pledges').count).to eq(3)
    expect(Patreon::Pledge::Decline.all.count).to eq(2)
    expect(get('rewards').count).to eq(5)
    expect(get('users').count).to eq(3)
    expect(get('reward-users')["0"].count).to eq(3)
    expect(get('filters').count).to eq(1)

    expect { # To check `add_model_callback(User, :after_commit, on: :create)` in plugin.rb
      get('users').each do |id, email|
        cf = Fabricate(:user, email: email).custom_fields
        expect(cf["patreon_id"]).to eq(id)
      end
    }.to change { GroupUser.count }.by(3)
  end

end
