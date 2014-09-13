require "riron/version"
require "riron/algorithm"
require "riron/options"
require "riron/exception"
require "securerandom"
require 'openssl'
require 'base64'

module Riron

  # Predefined algorithms
  AES_128_CBC = Algorithm.new("aes-128-cbc", "AES-128-CBC", 128, 128)
  AES_256_CBC = Algorithm.new("aes-256-cbc", "AES-256-CBC", 256, 128)

  SHA_256 = Algorithm.new("sha256", "sha256", 256, 0)

  # Default options to make the defaults explicit
  DEFAULT_ENCRYPTION_OPTIONS = Options.new(256, AES_256_CBC, 1)
  DEFAULT_INTEGRITY_OPTIONS = Options.new(256, SHA_256, 1)

  # Constants
  MAC_FORMAT_VERSION = "1"
  MAC_PREFIX = "Fe26." + MAC_FORMAT_VERSION
  DELIMITER = "*"

  # All Riron functions are module functions
  module_function

  # Seal a piece of data
  #
  # @param data [String] The data to seal
  # @param password_id [String] The ID associated with the given password. This feature
  #   enables password rotation. If you do not want to provide a password ID, pass nil
  #   for this parameter. The ID is expected to be a UTF-8 encoded String
  # @param password [String] The UTF-8 encoded password to use for sealing
  # @param enc_opts [Riron::Options] The encryption options to use
  # @param int_opts [Riron::Options] The integrity options to use
  #
  # @return [String] The sealed data as a UTF8-encoded String
  def seal(data, password_id, password, enc_opts, int_opts)
    encryption_salt = generate_salt(enc_opts.salt_bits)
    encryption_iv = generate_iv(enc_opts.algorithm.iv_bits)
    secure_key = generate_key(password, encryption_salt, enc_opts.algorithm, enc_opts.iterations)

    cipher = OpenSSL::Cipher.new(enc_opts.algorithm.transformation)
    cipher.encrypt
    cipher.iv = encryption_iv
    cipher.key = secure_key
    encrypted = cipher.update(data)
    encrypted << cipher.final

    encryption_iv_safe_base64 = Base64.urlsafe_encode64(encryption_iv)
    encrypted_data_safe_base64 = Base64.urlsafe_encode64(encrypted)

    # Eran Hammer's original javaScript version of iron uses URL-safe
    # Base64 encoding without padding. The Ruby syandard library does
    # not offer that feature and so we have to remove the padding manually.
    encryption_iv_safe_base64.gsub!('=', '')
    encrypted_data_safe_base64.gsub!('=', '')

    # construct the base string for which we'll create the HMAC later on
    parts = [MAC_PREFIX, password_id ? password_id : '', encryption_salt, encryption_iv_safe_base64, encrypted_data_safe_base64]
    base_string = parts.join(DELIMITER)

    # Create integrity HMAC
    integrity_salt = generate_salt(int_opts.salt_bits)
    hmac = calculate_hmac(password, base_string, integrity_salt, int_opts.algorithm, int_opts.iterations)
    hmac_safe_base64 = Base64.urlsafe_encode64(hmac)
    # Deal with padding (see above)
    hmac_safe_base64.gsub!('=', '')

    # Construct '*'-delimited sealed string
    [base_string, integrity_salt, hmac_safe_base64].join(DELIMITER)
  end

  # Unseal an iron-sealed string.
  #
  # @param data [String] The sealed string (expected to be UTF-8 encoded)
  # @param password_info [String or Hash<String,String>] Iron supports optional
  #   password rotation by using password ID/password pairs. When unsealing you
  #   can either provide a simple password (as a UTF-8 encoded string) or a
  #   has of password ID/password entries from which the unsealing procedure will
  #   select the password corresponding to the password ID contained in the
  #   sealed string.
  # @param enc_opts [Riron::Options] The encryption options to use
  # @param int_opts [Riron::Options] The integrity options to use
  #
  # @return [String] The unsealed data as a UTF8-encoded String
  def unseal(data, password_info, enc_opts, int_opts)

    parts = data.split(DELIMITER)
    if (parts.length != 7)
      raise RironIntegrityException.new(data), "Wrong number of token parts; split returned #{parts.length} parts"
    end

    prefix, password_id, encryption_salt, encryption_iv_safe_base64, encrypted_data_safe_base64, integrity_salt, hmac_safe_base64 = parts

    # Reconstruct base string for HMAC checking
    # FIXME: This is subject to optimization later on
    base_string = [prefix, password_id, encryption_salt, encryption_iv_safe_base64, encrypted_data_safe_base64].join(DELIMITER)

    # Iron fixed prefix check
    if (prefix != MAC_PREFIX)
      raise RironIntegrityException.new(data), "Incorrect prefix #{prefix}"
    end

    # Are we dealing with a password map or single password?
    if (password_info.is_a?(Hash))
      if (password_id.empty?)
        raise RironException, "Using password hash for unsealing requires password ID in token"
      end
      password = password_info[password_id]
      if (!password)
        raise RironException, "No password found in password hash for password ID #{password_id}"
      end
    else
      password = password_info
    end

    # HMAC integrity check
    hmac = base64_urlsafe_decode_padding_tolerant(hmac_safe_base64)
    check_hmac = calculate_hmac(password, base_string, integrity_salt, int_opts.algorithm, int_opts.iterations)

    if(!constant_time_array_equal(hmac,check_hmac))
      raise RironIntegrityException.new(data), "Invalid integrity signature #{hmac_safe_base64}"
    end

    # Decrypting data
    encryption_iv = base64_urlsafe_decode_padding_tolerant(encryption_iv_safe_base64)
    encrypted_data = base64_urlsafe_decode_padding_tolerant(encrypted_data_safe_base64)
    secure_key = generate_key(password,encryption_salt,enc_opts.algorithm,enc_opts.iterations)

    cipher = OpenSSL::Cipher.new(enc_opts.algorithm.transformation)
    cipher.decrypt
    cipher.iv = encryption_iv
    cipher.key = secure_key

    decrypted = cipher.update(encrypted_data)
    decrypted << cipher.final

    decrypted

  end


  # Generate an initialization vector.
  # Unlike generate_salt() this method returns a byte array, that needs to be
  # further encoded (e.g. Base64Url) to be suitable for URLs or HTTP headers.
  #
  # @param nbits [Integer] The size of the vector in bits. The initialization
  #   vector will be given a size of ceil(nbits/8) bytes.
  #
  # @return [Array<Byte>] The initialization vector
  def generate_iv(nbits)
    n = nbits.fdiv(8).ceil
    SecureRandom.random_bytes(n)
  end


  # Generates a random salt and returns as a String. With each salt byte
  # being represented in the string as a hex value in two chars.
  #
  # The salt can be inserted as-is into the iron token string.
  #
  # @param nbits [String] Size of the salt in bits. The salt will be
  #   given a size of ceil(nbits/8) * 2 bytes, because each 8 bit need
  #   two hex characters.
  #
  # @return [Array<Byte>] The salt in hex-encoded form.
  def generate_salt(nbits)
    n = nbits.fdiv(8).ceil
    SecureRandom.hex(n)
  end

  # Generates a secure key from a given password using PKCS5 PBKDF2 HMAC with
  # SHA1
  #
  # @param password [String] The password (will be interpreted as UTF-8 encoded String)
  # @param salt [Array<Byte>] The salt to use
  # @param algorithm [Riron::Algorithm] The algorithm to use for key generation
  # @param iterations [Integer] Number of iterations to use for key generation
  #
  # @return [Array<Byte>] The secret key
  def generate_key(password, salt, algorithm, iterations)
    key_len = algorithm.key_bits.fdiv(8).ceil
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, key_len, OpenSSL::Digest::SHA1.new)
  end

  # Calculate an HMAC for the given base string
  #
  # @param password [String] The password (will be interpreted as UTF-8 encoded String)
  # @param base_string [String] The UTF-8 encoded string to calculate the HMAC for
  # @param salt [Array<Byte>] The salt to use
  # @param algorithm [Riron::Algorithm] The algorithm to use for hashing
  # @param iterations [Integer] Number of iterations to use for hashing
  #
  # @return [Array<Byte>] The HMAC
  def calculate_hmac(password, base_string, salt, algorithm, iterations)
    secure_key = generate_key(password, salt, algorithm, iterations)
    digest = OpenSSL::Digest.new(algorithm.transformation)
    OpenSSL::HMAC.digest(digest, secure_key, base_string)
  end

  # Eran Hammer's original javaScript version of iron uses URL-safe
  # Base64 encoding without padding. The Ruby syandard library does
  # not offer that feature and so we have to restore the padding.
  # And then call the standard decodeing function.
  # @todo Refactor the Base64 en/decoding for efficiency
  #
  # @param [String] the UTF-8 encoded string to decode
  #
  # @return [String] The decoded, UTF-8 encoded string
  def base64_urlsafe_decode_padding_tolerant(str)
    str += '=' * (4 - str.length.modulo(4))
    Base64.urlsafe_decode64(str)
  end

  # Constant time comparsion between two byte arrays.
  #
  # @param lhs [Array<Byte>]
  # @param rhs [Array<Byte>]
  #
  # @return [Boolean] true if arrays are equal, false otherwise
  def constant_time_array_equal(lhs,rhs)
    equal = (lhs.length == rhs.length ? true : false)

    # If not equal so far, work on a single operand to have same length.
    rhs = lhs if(!equal)

    len = lhs.length
    for i in 0..len
        if (lhs[i] == rhs[i])
            equal = equal && true
        else
            equal = equal && false
        end

        return equal
    end

  end
end
