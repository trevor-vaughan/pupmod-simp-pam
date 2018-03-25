require 'spec_helper'

def el6?(facts)
  return ['CentOS', 'RedHat', 'OracleLinux'].include?(facts[:os][:name]) && facts[:os][:release][:major] == '6'
end


# We have to test pam::config via pam, because pam::config is
# private.  To take advantage of hooks built into puppet-rspec, the
# class described needs to be the class instantiated, i.e., pam.
describe 'pam' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts){ os_facts }

      context 'with default values' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/pam.d').with( {
            :ensure  => 'directory',
            :mode    => '0644',
            :recurse => true
          } )
        }

        if el6?(os_facts)
          it { is_expected.to_not contain_file('/etc/security/pwquality.conf') }
          it { is_expected.to_not contain_file('/etc/security/pwquality.conf.d') }
        else
          it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content(<<-EOM.gsub(/^\s+/,'')
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              difok = 4
              minlen = 15
              dcredit = -1
              ucredit = -1
              lcredit = -1
              ocredit = -1
              minclass = 3
              maxrepeat = 2
              maxclassrepeat = 3
              maxsequence = 4
              gecoscheck = 1
              EOM
            )
          }

          it { is_expected.to contain_file('/etc/security/pwquality.conf.d').with_ensure('absent') }
          it { is_expected.to contain_file('/etc/security/pwquality.conf.d').with_force(true) }
        end

        # not managing content of /etc/pam.d/atd or /etc/pam.d/crond
        it { is_expected.to contain_file('/etc/pam.d/atd').with_ensure('file') }
        it { is_expected.to contain_file('/etc/pam.d/crond').with_ensure('file') }
        it { is_expected.to contain_file('/etc/pam.d/sudo').with_content(<<-EOM.gsub(/^\s+/,'')
            #%PAM-1.0
            auth include system-auth
            account include system-auth
            password include system-auth
            session optional pam_keyinit.so revoke
            session required pam_limits.so
            session required pam_tty_audit.so disable=* enable=root open_only
            EOM
          )
        }

        it { is_expected.to contain_file('/etc/pam.d/sudo-i').with_content(<<-EOM.gsub(/^\s+/,'')
            #%PAM-1.0
            auth include sudo
            account include sudo
            password include sudo
            session optional pam_keyinit.so force revoke
            session required pam_limits.so
            session required pam_tty_audit.so disable=* enable=root open_only
            EOM
          )
        }

        it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
            auth    required    pam_warn.so
            account    required    pam_warn.so
            password    required    pam_warn.so
            session    required    pam_warn.so
            auth    required    pam_deny.so
            account    required    pam_deny.so
            password    required    pam_deny.so
            session    required    pam_deny.so
            EOM
          )
        }

        it {
          project_dir = File.expand_path(File.join(File.dirname(__FILE__), '..', '..'))
          expected = IO.read(File.join(project_dir, 'files', 'simp_authconfig.sh'))
          is_expected.to contain_file('/usr/local/sbin/simp_authconfig.sh').with_content(expected)
        }

        [ '/usr/sbin/authconfig', '/usr/sbin/authconfig-tui'].each do |file|
          it { is_expected.to contain_file(file).with( {
              :ensure  => 'link',
              :target  => '/usr/local/sbin/simp_authconfig.sh',
              :require => 'File[/usr/local/sbin/simp_authconfig.sh]'
            } )
          }
        end

        it { is_expected.to contain_pam__auth('fingerprint') }
        it { is_expected.to contain_pam__auth('system') }
        it { is_expected.to contain_pam__auth('password') }
        it { is_expected.to contain_pam__auth('smartcard') }
      end

      unless el6?(os_facts)
        context 'with non-default parameters impacting /etc/security/pwquality.conf' do
          context 'with optional parameters set' do
            let(:params) {{
              :cracklib_badwords => ['bad1', 'bad2'],
              :cracklib_dictpath => '/path/to/cracklib/dict'
            }}

            it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content(
              /badwords = bad1 bad2/ )
            }

            it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content(
              /dictpath = \/path\/to\/cracklib\/dict/ )
            }
          end
        end

        context 'with cracklib_gecoscheck = false' do
          let(:params) {{ :cracklib_gecoscheck => false }}

          it { is_expected.to_not contain_file('/etc/security/pwquality.conf').with_content(
            /gecoscheck = 12/ )
          }
        end

        context 'with rm_pwquality_conf_d = false' do
          let(:params) {{ :rm_pwquality_conf_d => false }}

          it { is_expected.to_not contain_file('/etc/security/pwquality.conf.d') }
        end
      end

      context 'with non-default parameters impacting /etc/pam.d/sudo*' do
        context 'with empty tty_audit_users' do
          let(:params) {{ :tty_audit_users => [] }}

          it { is_expected.to contain_file('/etc/pam.d/sudo').with_content(<<-EOM.gsub(/^\s+/,'')
              #%PAM-1.0
              auth include system-auth
              account include system-auth
              password include system-auth
              session optional pam_keyinit.so revoke
              session required pam_limits.so
              EOM
            )
          }

          it { is_expected.to contain_file('/etc/pam.d/sudo-i').with_content(<<-EOM.gsub(/^\s+/,'')
              #%PAM-1.0
              auth include sudo
              account include sudo
              password include sudo
              session optional pam_keyinit.so force revoke
              session required pam_limits.so
              EOM
            )
          }
        end

        context 'with multiple tty_audit_users' do
          let(:params) {{ :tty_audit_users => ['root','foo','bar'] }}

          it { is_expected.to contain_file('/etc/pam.d/sudo').with_content(<<-EOM.gsub(/^\s+/,'')
              #%PAM-1.0
              auth include system-auth
              account include system-auth
              password include system-auth
              session optional pam_keyinit.so revoke
              session required pam_limits.so
              session required pam_tty_audit.so disable=* enable=root,foo,bar open_only
              EOM
            )
          }

          it { is_expected.to contain_file('/etc/pam.d/sudo-i').with_content(<<-EOM.gsub(/^\s+/,'')
              #%PAM-1.0
              auth include sudo
              account include sudo
              password include sudo
              session optional pam_keyinit.so force revoke
              session required pam_limits.so
              session required pam_tty_audit.so disable=* enable=root,foo,bar open_only
              EOM
            )
          }
        end
      end

      context 'with non-default parameters impacting /etc/pam.d/other' do
        context 'with other_content set' do
          let(:params) {{ :other_content => '# some other configuration' }}

          it { is_expected.to contain_file('/etc/pam.d/other').with_content('# some other configuration') }
        end

        context 'deny_if_unknown = false' do
          let(:params){{ :deny_if_unknown => false }}
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
              auth    required    pam_warn.so
              account    required    pam_warn.so
              password    required    pam_warn.so
              session    required    pam_warn.so
              EOM
            )
          }
        end

        context 'no warn_if_unknown = false' do
          let(:params){{ :warn_if_unknown => false }}
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
              auth    required    pam_deny.so
              account    required    pam_deny.so
              password    required    pam_deny.so
              session    required    pam_deny.so
              EOM
            )
          }
        end
      end

      context 'with disable_authconfig = false' do
        let(:params){{ :disable_authconfig => false }}

        it { is_expected.to_not contain_file('/usr/local/sbin/simp_authconfig.sh') }
        it { is_expected.to_not contain_file('/usr/sbin/authconfig') }
        it { is_expected.to_not contain_file('/usr/sbin/authconfig-tui') }
      end

      context 'with empty auth_sections' do
        let(:params){{ :auth_sections => [] }}

        it { is_expected.to_not contain_pam__auth('fingerprint') }
        it { is_expected.to_not contain_pam__auth('system') }
        it { is_expected.to_not contain_pam__auth('password') }
        it { is_expected.to_not contain_pam__auth('smartcard') }
      end
    end
  end
end
