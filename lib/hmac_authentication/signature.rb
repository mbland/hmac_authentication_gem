require 'base64'
require 'openssl'

module HmacAuthentication
  NO_SIGNATURE = 1
  INVALID_FORMAT = 2
  UNSUPPORTED_ALGORITHM = 3
  MATCH = 4
  MISMATCH = 5

  def self.signed_headers(request, headers)
    headers.map { |name| (request.get_fields(name) || []).join(',') }
  end

  def self.hash_url(req)
    result = "#{req.uri.path}"
    result << '?' << req.uri.query if req.uri.query
    result << '#' << req.uri.fragment if req.uri.fragment
    result
  end

  def self.string_to_sign(req, headers)
    [req.method, signed_headers(req, headers).join("\n"), hash_url(req)]
      .join("\n")
  end

  def self.request_signature(request, digest, headers, secret_key)
    hmac = OpenSSL::HMAC.new secret_key, digest
    hmac << string_to_sign(request, headers) << (request.body || '')
    digest.name.downcase + ' ' + Base64.strict_encode64(hmac.digest)
  end

  def self.parse_digest(name)
    OpenSSL::Digest.new name
  rescue
    nil
  end

  def self.validate_request(request, signatureHeader, headers, secret_key)
    header = request[signatureHeader]
    return NO_SIGNATURE unless header
    components = header.split ' '
    return INVALID_FORMAT, header unless components.size == 2
    digest = parse_digest components.first
    return UNSUPPORTED_ALGORITHM, header unless digest
    computed = request_signature(request, digest, headers, secret_key)
    [(header == computed) ? MATCH : MISMATCH, header, computed]
  end
end
