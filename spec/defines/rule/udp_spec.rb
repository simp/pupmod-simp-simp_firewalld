require 'spec_helper.rb'

describe 'simp_firewalld::rule', type: :define do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(simplib__firewalls: ['iptables', 'firewalld'])
        end

        let(:ipv4_nets) do
          [
            '10.0.2.0/24',
            '10.0.2.33/32',
            '1.2.3.4/32',
            '2.3.4.0/24',
            '3.0.0.0/8',
          ]
        end

        let(:ipv6_nets) do
          [
            'fe80::/64',
            '2001:cdba:0000:0000:0000:0000:3257:9652/128',
            '2001:cdba:0000:0000:0000:0000:3257:9652/16',
          ]
        end

        context 'with trusted_nets in CIDR format' do
          let(:title) { 'allow_udp_range' }

          let(:params) do
            {
              protocol: 'udp',
              trusted_nets: ipv4_nets + ipv6_nets,
              dports: [1234, '234:567'],
            }
          end

          it { is_expected.to create_simp_firewalld__rule(title).with_dports(params[:dports]) }

          it do
            is_expected.to create_firewalld_rich_rule("simp_11_#{title}_simp-CmxLn8c8yuIQ2VyzgvzR4yi8TS")
              .with(
                ensure: 'present',
                family: 'ipv4',
                source: { 'ipset' => 'simp-CmxLn8c8yuIQ2VyzgvzR4yi8TS' },
                service: "simp_#{title}",
                action: 'accept',
                zone: '99_simp',
              )
          end

          it do
            is_expected.to create_firewalld_rich_rule("simp_11_#{title}_simp-07jxibAQvZRtfJna9ZG6dLvz2e")
              .with(
                ensure: 'present',
                family: 'ipv6',
                source: { 'ipset' => 'simp-07jxibAQvZRtfJna9ZG6dLvz2e' },
                service: "simp_#{title}",
                action: 'accept',
                zone: '99_simp',
              )
          end
        end
      end
    end
  end
end
