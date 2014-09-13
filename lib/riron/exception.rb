module Riron

  class RironException < StandardError

  end

  class RironIntegrityException < RironException
    attr_reader :token

    def initialize(token)
      super(message)
      @token = token
    end

  end
end
