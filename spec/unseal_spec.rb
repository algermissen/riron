require 'spec_helper'

module Riron

  describe 'unseal' do
    #it 'raises an exception for the wrong number of parts' do
    #  begin
    #  sealed = Riron.unseal("a*bad*token", "pwd", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
    #  rescue RironIntegrityException => e
    #    #puts "eorrrror: " + e.token
    #  end
    #end

    it 'unseals a token created with the C version of iron' do
      unsealed = Riron.unseal("Fe26.1*123*8cfbb22695939029a676a31c650437bfa4c29151f5203e237114bdae216ad47f*tQRDEMleUpP33iKzOo20BQ*cCjSg-XY1eLRzJDicCvPfw*b8cf9fbf957b5b7ada6cb94f883557004e9fc31d77cc0702a080bbe4179d02c6*-jg0jPk4u5XO2WUqnZu_LAFgAjtWPHu_IFmRxeNqaKA",
                              { "123" => "password" }, DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
      expect(unsealed).to eq("Secret message")
    end
  end

end
