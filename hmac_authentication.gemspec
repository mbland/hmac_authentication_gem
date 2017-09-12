# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'hmac_authentication/version'

Gem::Specification.new do |s|
  s.name          = 'hmac_authentication'
  s.version       = HmacAuthentication::VERSION
  s.authors       = ['Mike Bland']
  s.email         = ['mbland@acm.org']
  s.summary       = 'Signs and validates HTTP requests using HMAC signatures'
  s.description   = (
    'Signs and validates HTTP requests based on a shared-secret HMAC signature'
  )
  s.homepage      = 'https://github.com/mbland/hmac_authentication_gem'
  s.license       = 'ISC'

  s.files         = `git ls-files -z *.md bin lib`.split("\x0") + [
  ]
  s.executables   = s.files.grep(%r{^bin/}) { |f| File.basename(f) }

  s.add_runtime_dependency 'bundler', '~> 1.10'
  s.add_runtime_dependency 'fast_secure_compare'
  s.add_development_dependency 'go_script', '~> 0.1'
  s.add_development_dependency 'rake', '~> 10.4'
  s.add_development_dependency 'minitest'
  s.add_development_dependency 'codeclimate-test-reporter'
  s.add_development_dependency 'coveralls'
  s.add_development_dependency 'rubocop'
  s.add_development_dependency 'about_yml'
end
