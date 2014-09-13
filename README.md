# Riron

This is a Ruby implementation of [iron](https://github.com/hueniverse/iron).

## Installation

Add this line to your application's Gemfile:

    gem 'riron'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install riron

## Usage

Sealing some data

    require 'riron'

    data = "My secret message"

    sealed = Riron.seal(data,"passwordId","password", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)

Or, without password rotation feature:

    sealed = Riron.seal(data,nil,"password", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)

Unsealing some sealed data, e.g. an access token:

    require 'riron'

    passwords_tab = {
      "passwordId" => "password",
      "otherId" => "otherPassword"
    }

    begin
      unsealed = Riron.unseal(sealed,passwords_tab, DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)
    rescue RironIntegrityException => e
        puts "Unable to unseal; sealed data has integrity problem: #{e.message} (#{e.token})"
    rescue RironException => e
        puts "Unable to unseal: #{e.message}"
    end

Or, without password rotation feature:

      unsealed = Riron.unseal(sealed,"password", DEFAULT_ENCRYPTION_OPTIONS, DEFAULT_INTEGRITY_OPTIONS)



