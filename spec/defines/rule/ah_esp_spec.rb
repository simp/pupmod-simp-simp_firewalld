require 'spec_helper.rb'

describe "simp_firewalld::rule", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge({
            :simplib__firewalls => ['iptables', 'firewalld']
          })
        end

        let(:ipv4_nets) {
          [
            '10.0.2.0/24',
            '10.0.2.33/32',
            '1.2.3.4/32',
            '2.3.4.0/24',
            '3.0.0.0/8'
          ]
        }

        let(:ipv6_nets) {
          [
            'fe80::/64',
            '2001:cdba:0000:0000:0000:0000:3257:9652/128',
            '2001:cdba:0000:0000:0000:0000:3257:9652/16'
          ]
        }

        context "ah with trusted_nets in CIDR format" do
          let( :title  ){ 'allow_ah' }
          let( :params ){{
            :protocol     => 'ah',
            :trusted_nets => ipv4_nets + ipv6_nets,
            :order        => 15
          }}
          it { is_expected.to create_simp_firewalld__rule(title) }

          it {
            is_expected.to create_firewalld_rich_rule("simp_15_#{title}_simp-sLxKcJ8Jr7GgDOF54KlBvQR2Yc").with(
              {
                :ensure     => 'present',
                :family     => 'ipv4',
                :source     => { 'ipset' => 'simp-sLxKcJ8Jr7GgDOF54KlBvQR2Yc' },
                :action     => 'accept',
                :zone       => '99_simp',
                :protocol   => 'ah',
              }
            )
          }

          it {
            is_expected.to create_firewalld_rich_rule("simp_15_#{title}_simp-l7zVcqWPK6oo3saymLCPHgjuhp").with(
              {
                :ensure     => 'present',
                :family     => 'ipv6',
                :source     => {'ipset' => 'simp-l7zVcqWPK6oo3saymLCPHgjuhp'},
                :action     => 'accept',
                :zone       => '99_simp',
                :protocol   => 'ah',
              }
            )
          }
        end

        context "esp with trusted_nets in CIDR format" do
          let( :title  ){ 'allow_esp' }
          let( :params ){{
            :protocol     => 'esp',
            :trusted_nets => ipv4_nets + ipv6_nets,
            :order        => 15
          }}
          it { is_expected.to create_simp_firewalld__rule(title) }

          it {
            is_expected.to create_firewalld_rich_rule("simp_15_#{title}_simp-sLxKcJ8Jr7GgDOF54KlBvQR2Yc").with(
              {
                :ensure     => 'present',
                :family     => 'ipv4',
                :source     => { 'ipset' => 'simp-sLxKcJ8Jr7GgDOF54KlBvQR2Yc' },
                :action     => 'accept',
                :zone       => '99_simp',
                :protocol   => 'esp',
              }
            )
          }

          it {
            is_expected.to create_firewalld_rich_rule("simp_15_#{title}_simp-l7zVcqWPK6oo3saymLCPHgjuhp").with(
              {
                :ensure     => 'present',
                :family     => 'ipv6',
                :source     => {'ipset' => 'simp-l7zVcqWPK6oo3saymLCPHgjuhp'},
                :action     => 'accept',
                :zone       => '99_simp',
                :protocol   => 'esp',
              }
            )
          }
        end
      end
    end
  end
end
