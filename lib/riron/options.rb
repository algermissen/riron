module Riron

  class Options

    attr_accessor :salt_bits, :algorithm, :iterations

    def initialize(salt_bits, algorithm, iterations)
      @salt_bits = salt_bits
      @algorithm = algorithm
      @iterations = iterations
    end
  end

end
