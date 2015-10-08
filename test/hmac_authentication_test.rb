require_relative 'test_helper'
require_relative '../lib/hmac_authentication'

require 'minitest/autorun'
require 'net/http'
require 'openssl'

module HmacAuthenticationTest
  # These correspond to the headers used in bitly/oauth2_proxy#147.
  HEADERS = %w(
    Content-Length
    Content-Md5
    Content-Type
    Date
    Authorization
    X-Forwarded-User
    X-Forwarded-Email
    X-Forwarded-Access-Token
    Cookie
    Gap-Auth
  )

  def auth
    @auth ||= HmacAuthentication::HmacAuth.new(
      'sha1', 'foobar', 'Gap-Signature', HEADERS)
  end
end

module HmacAuthentication
  class AuthenticationResultCodeTest < ::Minitest::Test
    def test_return_nil_for_out_of_range_values
      assert_nil HmacAuth.result_code_to_string(-1)
      assert_nil(
        HmacAuth.result_code_to_string(RESULT_CODE_STRINGS.size + 1))
    end

    def test_return_string_for_valid_values
      assert_equal('NO_SIGNATURE', HmacAuth.result_code_to_string(NO_SIGNATURE))
      assert_equal('MISMATCH', HmacAuth.result_code_to_string(MISMATCH))
      assert_equal('MISMATCH',
        HmacAuth.result_code_to_string(RESULT_CODE_STRINGS.size))
    end
  end

  class HmacAuthConstructorTest < ::Minitest::Test
    include HmacAuthenticationTest

    def test_constructor_fails_if_digest_is_not_supported
      HmacAuthentication::HmacAuth.new(
        'bogus', 'foobar', 'Gap-Signature', HEADERS)
    rescue RuntimeError => err
      assert_equal(
        'HMAC authentication digest is not supported: bogus', err.to_s)
    end
  end

  class RequestSignatureTest < ::Minitest::Test
    include HmacAuthenticationTest

    # rubocop:disable MethodLength
    # rubocop:disable Metrics/AbcSize
    def test_request_signature_post
      uri = URI 'http://localhost/foo/bar'
      req = Net::HTTP::Post.new uri
      payload = '{ "hello": "world!" }'
      req.body = payload
      req.content_type = 'application/json'
      req['Content-Length'] = req.body.size
      req['Content-MD5'] = 'deadbeef'
      req['Date'] = '2015-09-28'
      req['Authorization'] = 'trust me'
      req['X-Forwarded-User'] = 'mbland'
      req['X-Forwarded-Email'] = 'mbland@acm.org'
      req['X-Forwarded-Access-Token'] = 'feedbead'
      req['Cookie'] = 'foo; bar; baz=quux'
      req['Gap-Auth'] = 'mbland'

      assert_equal(
        ['POST',
         "#{payload.size}",
         'deadbeef',
         'application/json',
         '2015-09-28',
         'trust me',
         'mbland',
         'mbland@acm.org',
         'feedbead',
         'foo; bar; baz=quux',
         'mbland',
         '/foo/bar',
        ].join("\n") + "\n",
        auth.string_to_sign(req))
      assert_equal(
        'sha1 K4IrVDtMCRwwW8Oms0VyZWMjXHI=',
        auth.request_signature(req))
    end
    # rubocop:enable Metrics/AbcSize
    # rubocop:enable MethodLength

    # rubocop:disable MethodLength
    def test_request_signature_get
      uri = URI 'http://localhost/foo/bar?baz=quux%2Fxyzzy#plugh'
      req = Net::HTTP::Get.new uri
      req['Date'] = '2015-09-29'
      req['Cookie'] = 'foo; bar; baz=quux'
      req['Gap-Auth'] = 'mbland'

      assert_equal(
        ['GET',
         '',
         '',
         '',
         '2015-09-29',
         '',
         '',
         '',
         '',
         'foo; bar; baz=quux',
         'mbland',
         '/foo/bar?baz=quux%2Fxyzzy#plugh',
        ].join("\n") + "\n",
        auth.string_to_sign(req))

      assert_equal(
        'sha1 ih5Jce9nsltry63rR4ImNz2hdnk=',
        auth.request_signature(req))
    end
    # rubocop:enable MethodLength

    # rubocop:disable MethodLength
    def test_request_signature_get_with_multiple_values_for_header
      uri = URI 'http://localhost/foo/bar'
      req = Net::HTTP::Get.new uri
      req['Date'] = '2015-09-29'
      # Note that Net::HTTPHeader only honors the last header with the same
      # name, discarding earlier values. We can still approximate a cookie
      # with multiple values using the representation below.
      req['Cookie'] = ['foo', 'bar', 'baz=quux']
      req['Gap-Auth'] = 'mbland'

      assert_equal(
        ['GET',
         '',
         '',
         '',
         '2015-09-29',
         '',
         '',
         '',
         '',
         'foo,bar,baz=quux',
         'mbland',
         '/foo/bar',
        ].join("\n") + "\n",
        auth.string_to_sign(req))

      assert_equal(
        'sha1 JlRkes1X+qq3Bgc/GcRyLos+4aI=',
        auth.request_signature(req))
    end
    # rubocop:enable MethodLength
  end

  class AuthenticateRequestTest < ::Minitest::Test
    include HmacAuthenticationTest

    def request
      @request ||= Net::HTTP::Post.new URI('http://localhost/foo/bar')
    end

    def test_authenticate_request_no_signature
      result, header, computed = auth.authenticate_request request
      assert_equal NO_SIGNATURE, result
      assert_nil header
      assert_nil computed
    end

    def test_authenticate_request_invalid_format
      bad_value = 'should be algorithm and digest value'
      request['GAP-Signature'] = bad_value
      result, header, computed = auth.authenticate_request request
      assert_equal INVALID_FORMAT, result
      assert_equal bad_value, header
      assert_nil computed
    end

    def test_authenticate_request_unsupported_algorithm
      valid_signature = auth.request_signature request
      components = valid_signature.split ' '
      signature_with_unsupported_algorithm = "unsupported #{components.last}"
      request['GAP-Signature'] = signature_with_unsupported_algorithm
      result, header, computed = auth.authenticate_request request
      assert_equal UNSUPPORTED_ALGORITHM, result
      assert_equal signature_with_unsupported_algorithm, header
      assert_nil computed
    end

    def test_authenticate_request_match
      expected_signature = auth.request_signature request
      auth.sign_request request
      result, header, computed = auth.authenticate_request request
      assert_equal MATCH, result
      assert_equal expected_signature, header
      assert_equal expected_signature, computed
    end

    def test_authenticate_request_mismatch
      barbaz_auth = HmacAuth.new 'sha1', 'barbaz', 'Gap-Signature', HEADERS
      auth.sign_request request
      result, header, computed = barbaz_auth.authenticate_request request
      assert_equal MISMATCH, result
      assert_equal auth.request_signature(request), header
      assert_equal barbaz_auth.request_signature(request), computed
    end
  end
end
