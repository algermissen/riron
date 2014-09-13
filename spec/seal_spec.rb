require 'spec_helper'

module Riron

  describe 'seal' do
    it 'should correctly seal and unseal some data (using password ID and password)' do
      sealed = Riron.seal("Secret message", "someId", "password", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      unsealed = Riron.unseal(sealed,{"someId" => "password"},DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      expect(unsealed).to eq("Secret message")
    end

    it 'should correctly seal and unseal some data (using password ID and password and more options in unseal)' do
      sealed = Riron.seal("Secret message", "someId", "password", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      pwd_tab = {"someId" => "password" , "foo" => "bar"}
      unsealed = Riron.unseal(sealed,pwd_tab,DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      expect(unsealed).to eq("Secret message")
    end

    it 'should correctly seal and unseal some data (using password only)' do
      sealed = Riron.seal("Secret message", nil, "password", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      unsealed = Riron.unseal(sealed,"password",DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      expect(unsealed).to eq("Secret message")
    end
  end

end
