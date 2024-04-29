require 'spec_helper_acceptance'

test_name 'simp_firewalld'

hosts.each do |host|
  describe "simp_firewalld on #{host}" do
    let(:default_manifest) {
      <<-EOS
        class { 'simp_firewalld': enable => true }

        simp_firewalld::rule { 'allow_all_ssh':
          trusted_nets => ['all'],
          protocol     => tcp,
          dports       => 22
        }
      EOS
    }

    context 'default parameters' do
      it 'should work with no errors' do
        apply_manifest_on(host, default_manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, default_manifest, :catch_changes => true)
      end

      it 'should have "99_simp" as the default zone' do
        default_zone = on(host, 'firewall-cmd --get-default-zone').output.strip
        expect(default_zone).to eq('99_simp')
      end

      it 'should have the "simp_allow_all_ssh" service in the "99_simp" zone' do
        simp_services = on(host, 'firewall-cmd --list-services --zone=99_simp').output.strip.split(/\s+/)
        expect(simp_services).to include('simp_allow_all_ssh')
      end
    end

    context 'TCP listen' do
      let(:manifest) {
        <<-EOM
          #{default_manifest}

          simp_firewalld::rule { 'allow_tcp_listen':
            trusted_nets => ['1.2.3.4/24', '3.4.5.6', '5.6.7.8/32'],
            protocol     => 'tcp',
            dports       => 1234
          }
        EOM
      }

      it 'should work with no errors' do
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end

      it 'should have the "simp_allow_all_ssh" service in the "99_simp" zone' do
        simp_services = on(host, 'firewall-cmd --list-services --zone=99_simp').output.strip.split(/\s+/)
        expect(simp_services).to include('simp_allow_all_ssh')
      end

      it 'should have an appropriate ruleset configured' do
        rulesets = on(host, 'firewall-cmd --list-rich-rules --zone=99_simp').output.strip.lines

        target_ruleset = rulesets.grep(%r("simp_allow_tcp_listen"))

        expect(target_ruleset.size).to eq(2)

        hash_ip_ipset = 'simp-P2bfsoqkagK6KYomH5dgJFNq6i'
        hash_net_ipset = 'simp-tn9HkuMIqysMB38yE39eTr1BDA'

        expect(target_ruleset).to include(match(%r{ipset="#{hash_ip_ipset}"}))
        expect(target_ruleset).to include(match(%r{ipset="#{hash_net_ipset}"}))

        hash_ip_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_ip_ipset}").output

        hash_ip_ipset_contents = hash_ip_ipset_contents.lines.delete_if{|x| x !~ /: /}

        expect(hash_ip_ipset_contents).to_not be_empty

        hash_ip_ipset_contents = Hash[hash_ip_ipset_contents.map{|x| x.strip.split(': ')}]
        hash_ip_ipset_contents['entries'] = hash_ip_ipset_contents['entries'].split(/\s+/)

        expect(hash_ip_ipset_contents['entries']).to include(match(%r{3\.4\.5\.6}))
        expect(hash_ip_ipset_contents['entries']).to include(match(%r{5\.6\.7\.8}))

        hash_net_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_net_ipset}").output

        hash_net_ipset_contents = hash_net_ipset_contents.lines.delete_if{|x| x !~ /: /}

        expect(hash_net_ipset_contents).to_not be_empty

        hash_net_ipset_contents = Hash[hash_net_ipset_contents.map{|x| x.strip.split(': ')}]
        hash_net_ipset_contents['entries'] = hash_net_ipset_contents['entries'].split(/\s+/)

        expect(hash_net_ipset_contents['entries']).to include(match(%r{1\.2\.3\.0/24}))
      end

      context 'UDP listen' do
        let(:manifest) {
          <<-EOM
            #{default_manifest}

            simp_firewalld::rule { 'allow_udp_listen':
              trusted_nets => ['2.3.4.5/8', '3.4.5.6', '5.6.7.8/32'],
              protocol     => 'tcp',
              dports       => 2345
            }
          EOM
        }

        it 'should work with no errors' do
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host, manifest, :catch_changes => true)
        end

        it 'should have the "simp_allow_all_ssh" service in the "99_simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=99_simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_allow_all_ssh')
        end

        it 'should have an appropriate ruleset configured' do
          rulesets = on(host, 'firewall-cmd --list-rich-rules --zone=99_simp').output.strip.lines

          target_ruleset = rulesets.grep(%r("simp_allow_udp_listen"))

          expect(target_ruleset.size).to eq(2)

          hash_ip_ipset = 'simp-O9NSV0JsGTTti0eoSoRle4FzWr'
          hash_net_ipset = 'simp-c53N50IHUI62MAHDArAdokw4kI'

          expect(target_ruleset).to include(match(%r{ipset="#{hash_ip_ipset}"}))
          expect(target_ruleset).to include(match(%r{ipset="#{hash_net_ipset}"}))

          hash_ip_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_ip_ipset}").output

          hash_ip_ipset_contents = hash_ip_ipset_contents.lines.delete_if{|x| x !~ /: /}

          expect(hash_ip_ipset_contents).to_not be_empty

          hash_ip_ipset_contents = Hash[hash_ip_ipset_contents.map{|x| x.strip.split(': ')}]
          hash_ip_ipset_contents['entries'] = hash_ip_ipset_contents['entries'].split(/\s+/)

          expect(hash_ip_ipset_contents['entries']).to include(match(%r{3\.4\.5\.6}))
          expect(hash_ip_ipset_contents['entries']).to include(match(%r{5\.6\.7\.8}))

          hash_net_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_net_ipset}").output

          hash_net_ipset_contents = hash_net_ipset_contents.lines.delete_if{|x| x !~ /: /}

          expect(hash_net_ipset_contents).to_not be_empty

          hash_net_ipset_contents = Hash[hash_net_ipset_contents.map{|x| x.strip.split(': ')}]
          hash_net_ipset_contents['entries'] = hash_net_ipset_contents['entries'].split(/\s+/)

          expect(hash_net_ipset_contents['entries']).to include(match(%r{2\.0\.0\.0/8}))
        end
      end
    end
  end
end
