module Riron

  class Algorithm

    attr_accessor :name, :transformation, :key_bits, :iv_bits

    def initialize(name, transformation, key_bits, iv_bits)
      @name = name
      @transformation = transformation
      @key_bits = key_bits
      @iv_bits = iv_bits
    end
  end
end
