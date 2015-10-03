require 'base64'
require 'openssl'

module HmacAuthentication
  class HmacAuth
    attr_reader :digest, :secret_key, :signature_header, :headers

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

    def self.result_code_to_string(code)
      index = code - 1
      index >= 0 ? RESULT_CODE_STRINGS[index] : nil
    end

    def initialize(digest_name, secret_key, signature_header, headers)
      @digest = parse_digest digest_name
      if digest.nil?
        fail "HMAC authentication digest is not supported: #{digest_name}"
      end

      @secret_key = secret_key
      @signature_header = signature_header
      @headers = headers
    end

    def signed_headers(request)
      headers.map { |name| (request.get_fields(name) || []).join(',') }
    end
    private :signed_headers

    def hash_url(req)
      result = "#{req.uri.path}"
      result << '?' << req.uri.query if req.uri.query
      result << '#' << req.uri.fragment if req.uri.fragment
      result
    end
    private :hash_url

    def string_to_sign(req)
      [req.method, signed_headers(req).join("\n"), hash_url(req)].join("\n")
    end

    def sign_request(req)
      req[signature_header] = request_signature req
    end

    def request_signature(request)
      request_signature_impl request, digest
    end

    def request_signature_impl(request, digest_)
      hmac = OpenSSL::HMAC.new secret_key, digest_
      hmac << string_to_sign(request) << (request.body || '')
      digest_.name.downcase + ' ' + Base64.strict_encode64(hmac.digest)
    end
    private :request_signature_impl

    def parse_digest(name)
      OpenSSL::Digest.new name
    rescue
      nil
    end
    private :parse_digest

    def validate_request(request)
      header = request[signature_header]
      return NO_SIGNATURE unless header
      components = header.split ' '
      return INVALID_FORMAT, header unless components.size == 2
      parsed_digest = parse_digest components.first
      return UNSUPPORTED_ALGORITHM, header unless parsed_digest
      computed = request_signature_impl request, parsed_digest
      [(header == computed) ? MATCH : MISMATCH, header, computed]
    end
  end
end
