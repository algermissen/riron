require 'spec_helper'

module Riron

  describe 'generate_salt' do

    it 'generates a 64 byte hex string for 256 salt bits' do
      s = Riron.generate_salt(256)
      expect(s.length).to eq(64)
    end

    it 'generates a 32 byte hex string for 128 salt bits' do
      s = Riron.generate_salt(128)
      expect(s.length).to eq(32)
    end

    it 'generates a 2 byte hex string for 7 salt bits' do
      s = Riron.generate_salt(7)
      expect(s.length).to eq(2)
    end

  end

  describe 'generate_key' do
    it 'generates a key with the correct length' do
      salt = Riron.generate_salt(256)
      k = Riron.generate_key("geheim", salt, AES_128_CBC, DEFAULT_ENCRYPTION_OPTIONS.iterations)
      expect(k.length).to eq(16)
    end
  end

end
