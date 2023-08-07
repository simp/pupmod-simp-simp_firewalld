# @summary This is a `firewalld` profile that sets "safe" defaults as is usual in SIMP modules
#
# If you want to override any element not present in the `firewalld` class
# resource below then you should use Hiera directly on the `firewalld` class.
#
# @param rules
#   A hash of firewalld::rules that should be created
# @example creating a new rule via class declaration:
#   simp_firewalld::rules => {
#     'allow_port_22' => {
#       'protocol' => 'tcp',
#       'dports'   => 22,
#     }
#   }
# @example same example, but with hieradata
#   simp_firewalld::rules:
#     allow_port_22:
#       protocol: tcp
#       dports: 22
#
# @param firewall_backend
#   Allows you to set the backend that firewalld will use.
#
#   * Currently set to 'iptables' due to bugs in nftables
#
# @param enable
#   Activate the firewalld management capabilties.
#
#   * The class will not be enabled if firewalld is not detected on the remote
#     system. This can be overridden by setting this option to `true`
#     explicitly in Hiera.
#
# @param complete_reload
#   The current firewalld module has the capability to perform a complete reload
#   of firewalld which breaks any existing connections. This is extremely
#   dangerous and this class overrides and disables this capability by default.
#
#   * Set to ``true`` to re-enable this capability.
#
# @param lockdown
#   Set ``firewalld`` in ``lockdown`` mode which disallows manipulation by
#   applications.
#
#   * This makes sense to do by default since puppet is meant to be
#     authoritative on the system.
#
# @param default_zone
#   The 'default zone' to set on the system.
#
#   This is set to ``99_simp`` so that regular, alternative, zone manipulation
#   can occur without interference.
#
#   **IMPORTANT:** If this is set to anything besides ``99_simp``, all rules in
#   this module will **NOT** apply to the default zone! This module is set to
#   only populate ``99_simp`` zone rules.
#
# @param log_denied
#   What types of logs to process for denied packets.
#
#   @see LogDenied in firewalld.conf(5)
#
# @param enable_tidy
#   Enable the ``Tidy`` resources that help keep the system clean from cruft
#
# @param tidy_dirs
#   The directories to target for tidying
#
# @param tidy_prefix
#   The name match to use for tidying files
#
# @param tidy_minutes
#   Number of **minutes** to consider a configuration file 'stale' for the
#   purposes of tidying.
#
# @param simp_zone_interfaces
#   The network interfaces to which the underlying 99_simp zone should apply
#
# @param simp_zone_target
#   The default target for the 99_simp zone
#
# @param package_ensure
#   The 'ensure' value for package resources
#
class simp_firewalld (
  Optional[Hash]                                       $rules,               # data in module
  Enum['iptables','nftables']                          $firewall_backend,    # data in module
  Boolean                                              $enable               = 'firewalld' in pick($facts['simplib__firewalls'], 'none'),
  Boolean                                              $complete_reload      = false,
  Boolean                                              $lockdown             = true,
  String[1]                                            $default_zone         = '99_simp',
  Enum['off', 'all','unicast','broadcast','multicast'] $log_denied           = 'unicast',
  Boolean                                              $enable_tidy          = true,
  # lint:ignore:2sp_soft_tabs
  Array[Stdlib::Absolutepath]                          $tidy_dirs            = [
                                                                                 '/etc/firewalld/icmptypes',
                                                                                 '/etc/firewalld/ipsets',
                                                                                 '/etc/firewalld/services',
                                                                               ],
  # lint:endignore
  String[1]                                            $tidy_prefix          = 'simp_',
  Integer[1]                                           $tidy_minutes         = 10,
  Array[Optional[String[1]]]                           $simp_zone_interfaces = [],
  Enum['default', 'ACCEPT', 'REJECT', 'DROP']          $simp_zone_target     = 'DROP',
  String[1]                                            $package_ensure       = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) {
  if $enable {
    Exec { path => '/usr/bin:/bin' }

    # Upstream module only takes yes/no values
    $_lockdown_xlat = $lockdown ? { true => 'yes', default => 'no' }

    # The upstream module should handle this properly but it looks like CentOS
    # may have diverted from the upstream firewalld code making version
    # matching impossible.
    if 'nft' in pick($facts.dig('simplib__firewalls'), []) {
      $_firewall_backend = $firewall_backend
    }
    else {
      $_firewall_backend = undef
    }

    class { 'firewalld':
      lockdown         => $_lockdown_xlat,
      default_zone     => $default_zone,
      log_denied       => $log_denied,
      firewall_backend => $_firewall_backend,
      package_ensure   => $package_ensure,
    }

    unless $complete_reload {
      # This breaks all firewall connections and should never be done unless forced
      Exec <| command == 'firewall-cmd --complete-reload' |> { onlyif => '/bin/false' }
    }

    firewalld_zone { '99_simp':
      ensure           => 'present',
      purge_rich_rules => true,
      purge_services   => true,
      purge_ports      => true,
      interfaces       => $simp_zone_interfaces,
      target           => $simp_zone_target,
      require          => Service['firewalld'],
    }

    if $default_zone == '99_simp' {
      Firewalld_zone['99_simp'] -> Exec['firewalld::set_default_zone']
    }

    if $enable_tidy {
      tidy { $tidy_dirs:
        age     => "${tidy_minutes}m",
        backup  => false,
        matches => [$tidy_prefix],
        recurse => true,
        type    => 'mtime',
      }
    }

    $rules.each |String $key, Hash $rule| {
      simp_firewalld::rule { $key:
        * => $rule,
      }
    }
  }
}
