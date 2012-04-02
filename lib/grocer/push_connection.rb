require 'delegate'
require_relative 'connection'

module Grocer
  class PushConnection < SimpleDelegator

    PRODUCTION_GATEWAY = 'gateway.push.apple.com'
    SANDBOX_GATEWAY = 'gateway.sandbox.push.apple.com'

    def initialize(options)
      options = defaults.merge(options)
      super(Connection.new(options))
    end

    private

    def defaults
      {
        gateway: find_default_gateway,
        port: 2195
      }
    end

    def find_default_gateway
      Grocer.env == 'production' ? PRODUCTION_GATEWAY : SANDBOX_GATEWAY
    end

  end
end