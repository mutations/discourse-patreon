# frozen_string_literal: true

require 'json'

module ::Patreon
  class Patron

    def self.update_local_user(user, patreon_id, skip_save = false)
      return if user.blank?

      user.custom_fields["patreon_id"] = patreon_id
      user.save_custom_fields unless skip_save || user.custom_fields_clean?

      user
    end

  end
end
