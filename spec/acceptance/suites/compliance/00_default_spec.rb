require 'spec_helper_acceptance'

test_name 'pam STIG enforcement'

describe 'pam STIG enforcement' do

  let(:manifest) {
    <<-EOS
      $loaded_maps = compliance_markup::loaded_maps()
      $telemetry = compliance_markup::telemetry("pam::homedir_umask")
      $full_map = lookup("compliance_markup::debug::dump", { "default_value" => {}})

      notice("compliance_engine loaded_maps => ${loaded_maps}")
      notice("compliance_engine telemetry => ${telemetry}")
      notice("compliance_engine dump => ${full_map}")

      include 'pam'

      $compliance_profile = 'disa_stig'
      include 'compliance_markup'
    EOS
  }

  let(:hieradata) { <<-EOF
---
compliance_markup::enforcement:
  - disa_stig
  EOF
  }

  hosts.each do |host|
    shared_examples 'a valid report' do
      before(:all) do
        @compliance_data = {
          :report => {}
        }
      end

      let(:fqdn) { fact_on(host, 'fqdn') }

      it 'should have a report' do
        tmpdir = Dir.mktmpdir
        begin
          Dir.chdir(tmpdir) do
            scp_from(host, "/opt/puppetlabs/puppet/cache/simp/compliance_reports/#{fqdn}/compliance_report.json", '.')

            expect {
              @compliance_data[:report] = JSON.load(File.read('compliance_report.json'))
            }.to_not raise_error
          end
        ensure
          FileUtils.remove_entry_secure tmpdir
        end
      end

      it 'should have host metadata' do
        expect(@compliance_data[:report]['fqdn']).to eq(fqdn)
      end

      it 'should have a compliance profile report' do
        expect(@compliance_data[:report]['compliance_profiles']).to_not be_empty
        expect(@compliance_data[:report]['compliance_profiles']['disa_stig']).to_not be_empty
        expect(@compliance_data[:report]['compliance_profiles']['disa_stig']['summary']).to_not be_empty
        expect(@compliance_data[:report]['compliance_profiles']['disa_stig']['summary']['percent_compliant']).to be > 80
      end
    end

    context 'when enforcing the STIG' do
      let(:hiera_yaml) { <<-EOM
---
version: 5
hierarchy:
  - name: Compliance
    lookup_key: compliance_markup::enforcement
  - name: Common
    path: default.yaml
defaults:
  data_hash: yaml_data
  datadir: "#{hiera_datadir(host)}"
  EOM
      }

      # This specifically tests that the new CE 2.0 allows us to generate the server-side reports
      #
      # The enforcement part is handled by the InSpec tests but also requires
      # this to ensure that we're using not using the legacy material.
      it 'should remove the legacy compliance maps' do
        create_remote_file(host, '/tmp/empty.json', "{}\n")
        on(host, %(find /etc/puppetlabs/code/environments/production/modules/compliance_markup/data -name "*.json" -exec cp /tmp/empty.json {} \\;))
      end

      # Using puppet_apply as a helper
      it 'should work with no errors' do
        create_remote_file(host, host.puppet['hiera_config'], hiera_yaml)
        write_hieradata_to(host, hieradata)

        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end

      it_behaves_like 'a valid report'
    end
  end
end
