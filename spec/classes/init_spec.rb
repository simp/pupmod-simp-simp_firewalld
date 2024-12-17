require 'spec_helper'

describe 'simp_firewalld' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) do
        os_facts.merge({
                         simplib__firewalls: ['iptables', 'firewalld']
                       })
      end

      context "on #{os}" do
        context 'without any parameters' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('simp_firewalld').with_enable(true) }

          it {
            is_expected.to create_class('firewalld')
              .with_lockdown('yes')
              .with_default_zone('99_simp')
              .with_log_denied('unicast')
              .with_firewall_backend(nil)
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
                require: 'Service[firewalld]'
              },
            )
          }

          it { is_expected.to create_tidy('/etc/firewalld/ipsets').with_matches(['simp_']) }
        end

        context 'with nftables' do
          let(:facts) do
            os_facts.merge({
                             simplib__firewalls: ['iptables', 'firewalld', 'nft']
                           })
          end
          let(:params) do
            {
              firewall_backend: 'nftables'
            }
          end

          it {
            is_expected.to create_class('firewalld')
              .with_lockdown('yes')
              .with_default_zone('99_simp')
              .with_log_denied('unicast')
              .with_firewall_backend('nftables')
              .with_package_ensure('installed')
          }
        end

        context 'adding port 22 rule' do
          let(:facts) do
            os_facts.merge({
                             simplib__firewalls: ['iptables', 'firewalld', 'nft']
                           })
          end
          let(:params) do
            {
              firewall_backend: 'nftables',
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
