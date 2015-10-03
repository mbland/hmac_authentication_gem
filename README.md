# hmac_authentication RubyGem

Signs and validates HTTP requests based on a shared-secret HMAC signature.

## Installation

If you're using [Bundler](http://bundler.io) in your project, add the
following to your `Gemfile`:

```ruby
gem 'hmac_authentication'
```

If you're not using Bundler, start.

## Validating incoming requests

Inject something resembling the following code fragment into your request
handling logic as the first thing that happens before the request body is
parsed, where `headers` is a list of headers factored into the signature and
`secret_key` is the shared secret between your application and the service
making the request:

```ruby
require 'hmac_authentication'

# When only used for validation, it doesn't matter what the first argument is,
# because the hash algorithm used for validation will be parsed from the
# incoming request signature header.
auth = HmacAuthentication::HmacAuth.new(
  'sha1', secret_key, signature_header, headers)

def request_handler(request)
  result, header_signature, computed_signature = auth.validate_request request
  if result != HmacAuthentication::HmacAuth::MATCH
    # Cancel the request, optionally logging the values above.
  end
end
```

## Signing outgoing requests

Do something similar to the following.

```ruby
digest_name = 'sha1' # Or any other available Hash algorithm.
auth = HmacAuthentication::HmacAuth.new(
  digest_name, secret_key, signature_header, headers)

def make_request(request)
  // Prepare request...
  auth.sign_request request
end
```

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0
>dedication. By submitting a pull request, you are agreeing to comply
>with this waiver of copyright interest.
