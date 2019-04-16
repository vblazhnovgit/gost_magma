# GostMagma

GOST R 34.12/13-2015 (Magma) block cipher algorithms for ECB, CBC, CTR, OFB, CFB, OMAC, CTR-ACPKM and OMAC-ACPKM modes.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'gost_magma'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install gost_magma

## Usage

```ruby
require 'gost_magma'
include GostMagma

BlockSize = Magma::BlockLengthInBytes

# GOST R 34.13-2015 Magma test data
SelfTestGostMMasterKeyData = [
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 
  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
].pack('C*').freeze
key = SelfTestGostMMasterKeyData

SelfTestGostMPlainText = [
  0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 
  0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
  0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 
  0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41,
].pack('C*').freeze
plain_text = SelfTestGostMPlainText

# ECB mode
SelfTestGostMEcbEncText = [
  0x2b, 0x07, 0x3f, 0x04, 0x94, 0xf3, 0x72, 0xa0, 
  0xde, 0x70, 0xe7, 0x15, 0xd3, 0x55, 0x6e, 0x48,
  0x11, 0xd8, 0xd9, 0xe9, 0xea, 0xcf, 0xbc, 0x1e, 
  0x7c, 0x68, 0x26, 0x09, 0x96, 0xc6, 0x7e, 0xfb
].pack('C*').freeze
encrypted_test = SelfTestGostMEcbEncText

encrypted_text = MagmaEcb.new(key).encrypt(plain_text)
puts "ECB encrypted_text == encrypted_test: #{encrypted_text == encrypted_test}" 
    
decrypted_text = MagmaEcb.new(key).decrypt(encrypted_test)
puts "ECB decrypted_text == plain_text: #{decrypted_text == plain_text}" 

# OMAC mode
SelfTestGostMMacValue = [
  0x15, 0x4e, 0x72, 0x10, 0x20, 0x30, 0xc5, 0xbb
].pack('C*').freeze
mac_test = SelfTestGostMMacValue

mac = MagmaOmac.new(key, mac_test.length).update(plain_text).final
puts "OMAC mac == mac_test: #{mac == mac_test}" 

# CTR mode 
SelfTestGostMCtrSV = [
  0x12, 0x34, 0x56, 0x78
].pack('C*').freeze
iv = SelfTestGostMCtrSV

SelfTestGostMCtrEncText = [
  0x4e, 0x98, 0x11, 0x0c, 0x97, 0xb7, 0xb9, 0x3c,
  0x3e, 0x25, 0x0d, 0x93, 0xd6, 0xe8, 0x5d, 0x69,
  0x13, 0x6d, 0x86, 0x88, 0x07, 0xb2, 0xdb, 0xef,
  0x56, 0x8e, 0xb6, 0x80, 0xab, 0x52, 0xa1, 0x2d    
].pack('C*').freeze
encrypted_test = SelfTestGostMCtrEncText

encrypted_text = MagmaCtr.new(key, iv, BlockSize).encrypt(plain_text)
puts "CTR encrypted_text == encrypted_test: #{encrypted_text == encrypted_test}"

# CTR multi-part usage    
text_len = plain_text.length
ctx = MagmaCtr.new(key, iv, BlockSize)
decrypted_text = ctx.decrypt(encrypted_test[0...text_len/3]) +
  ctx.decrypt(encrypted_test[text_len/3..-1])
puts "CTR decrypted_text == plain_text: #{decrypted_text == plain_text}" 
```

For other cipher modes see test samples in /test/gost_magma_test.rb please.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/vblazhnovgit/gost_magma.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
