require 'spec_helper'

describe 'simp_firewalld' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) { os_facts }

      context "on #{os}" do
        context 'without any parameters' do
          # The default backend comes from module data (nftables everywhere
          # except EL 8.0/8.1 and Amazon Linux)
          expected_backend =
            if os_facts[:os][:name] == 'Amazon'
              'iptables'
            else
              'nftables'
            end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('simp_firewalld').with_enable(true) }

          it {
            is_expected.to create_class('firewalld')
              .with_lockdown('yes')
              .with_default_zone('99_simp')
              .with_log_denied('unicast')
              .with_firewall_backend(expected_backend)
              .with_package_ensure('installed')
          }

          it { is_expected.to create_exec('firewalld::complete-reload').with_onlyif('/bin/false') }
          it {
            is_expected.to create_firewalld_zone('99_simp').with(
              {
                purge_rich_rules: true,
                purge_services: true,
                purge_ports: true,
                interfaces: [],
                target: 'DROP',
                require: 'Service[firewalld]',
              },
            )
          }

          it { is_expected.to create_tidy('/etc/firewalld/ipsets').with_matches(['simp_']) }
        end

        context 'with enable => false' do
          let(:params) { { enable: false } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.not_to create_class('firewalld') }
          it { is_expected.not_to create_firewalld_zone('99_simp') }
        end

        context 'with an explicit iptables firewall_backend' do
          let(:params) do
            {
              firewall_backend: 'iptables',
            }
          end

          it {
            is_expected.to create_class('firewalld')
              .with_lockdown('yes')
              .with_default_zone('99_simp')
              .with_log_denied('unicast')
              .with_firewall_backend('iptables')
              .with_package_ensure('installed')
          }
        end

        context 'adding port 22 rule' do
          let(:params) do
            {
              rules: {
                'add_port_22' => {
                  'protocol' => 'tcp',
                  'dports'   => 22,
                },
              },
            }
          end

          it {
            is_expected.to create_simp_firewalld__rule('add_port_22')
              .with_protocol('tcp')
              .with_dports('22')
          }
        end
      end
    end
  end
end
