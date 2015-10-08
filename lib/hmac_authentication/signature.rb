require 'base64'
require 'fast_secure_compare/fast_secure_compare'
require 'openssl'

module HmacAuthentication
  NO_SIGNATURE = 1
  INVALID_FORMAT = 2
  UNSUPPORTED_ALGORITHM = 3
  MATCH = 4
  MISMATCH = 5

  RESULT_CODE_STRINGS = %w(
    NO_SIGNATURE
    INVALID_FORMAT
    UNSUPPORTED_ALGORITHM
    MATCH
    MISMATCH
  )

  class HmacAuth
    attr_reader :digest, :secret_key, :signature_header, :headers

    def self.result_code_to_string(code)
      index = code - 1
      index >= 0 ? RESULT_CODE_STRINGS[index] : nil
    end

    def initialize(digest_name, secret_key, signature_header, headers)
      @digest = HmacAuthentication.parse_digest digest_name
      if digest.nil?
        fail "HMAC authentication digest is not supported: #{digest_name}"
      end

      @secret_key = secret_key
      @signature_header = signature_header
      @headers = headers
    end

    def string_to_sign(req)
      [req.method,
       signed_headers(req).join("\n"),
       HmacAuthentication.hash_url(req)].join("\n") + "\n"
    end

    def sign_request(req)
      req[signature_header] = request_signature req
    end

    def request_signature(request)
      request_signature_impl request, digest
    end

    def signature_from_header(request)
      request[signature_header]
    end

    def authenticate_request(request)
      header = signature_from_header request
      return NO_SIGNATURE unless header
      components = header.split ' '
      return INVALID_FORMAT, header unless components.size == 2
      parsed_digest = HmacAuthentication.parse_digest components.first
      return UNSUPPORTED_ALGORITHM, header unless parsed_digest
      computed = request_signature_impl request, parsed_digest
      [HmacAuthentication.compare_signatures(header, computed),
       header, computed]
    end

    private

    def signed_headers(request)
      headers.map { |name| (request.get_fields(name) || []).join(',') }
    end

    def request_signature_impl(request, digest_)
      hmac = OpenSSL::HMAC.new secret_key, digest_
      hmac << string_to_sign(request) << (request.body || '')
      digest_.name.downcase + ' ' + Base64.strict_encode64(hmac.digest)
    end
  end

  def self.parse_digest(name)
    OpenSSL::Digest.new name
  rescue
    nil
  end

  def self.compare_signatures(header, computed)
    FastSecureCompare.compare(computed, header) ? MATCH : MISMATCH
  end

  def self.hash_url(req)
    result = "#{req.uri.path}"
    result << '?' << req.uri.query if req.uri.query
    result << '#' << req.uri.fragment if req.uri.fragment
    result
  end
end
