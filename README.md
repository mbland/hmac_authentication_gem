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

def my_handler(request, headers)
  result, header_signature, computed_signature = (
    HmacAuthentication.validate_request(request, headers, secret_key))
  if result != HmacAuthentication::MATCH
    # Cancel the request, optionally logging the values above.
  end
end
```

## Signing outgoing requests

Call `request_signature(request, headers, secretKey)` to sign a request before
sending.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0
>dedication. By submitting a pull request, you are agreeing to comply
>with this waiver of copyright interest.
