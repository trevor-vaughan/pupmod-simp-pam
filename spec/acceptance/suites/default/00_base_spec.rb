require 'spec_helper_acceptance'
require 'digest/sha2'

test_name 'pam class'

# Pulled directly from puppetlabs/stdlib at
# https://github.com/puppetlabs/puppetlabs-stdlib/blob/master/lib/puppet/parser/functions/str2saltedsha512.rb
def str2saltedsha512hash
  seedint    = rand(2**31 - 1)
  seedstring = Array(seedint).pack("L")
  saltedpass = Digest::SHA512.digest(seedstring + password)
  (seedstring + saltedpass).unpack('H*')[0]
end

describe 'pam class' do

  let(:username) { 'simp_test' }
  let(:orig_password) { 'UserPassword' }
  let(:bad_password) { 'abc123abc123abc123' }
  let(:good_password) { 'CS6*AVbeYdjD#4g5X3kD' }
  let(:manifest) { 'include "::pam"' }

  hosts.each do |host|
    context 'with reliable test host' do
      it 'should work with no errors' do
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end
    end

    context "with a local user" do
      let(:user_manifest) { <<-EOM
        user { #{username}:
          forcelocal => true,
          password   => #{str2saltedsha512hash(orig_password)},
          home       => '/home/#{username}',
          managehome => true
        }
        EOM
      }

      it 'should create the local user' do
        apply_manifest_on(host, user_manifest, :catch_failures => true)
      end

      context "local user should *not* be able to login" do
        require 'pry'
        binding.pry
      end
    end
  end
end
