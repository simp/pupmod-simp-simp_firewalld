[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/simp_firewalld.svg)](https://forge.puppetlabs.com/simp/simp_firewalld)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/simp_firewalld.svg)](https://forge.puppetlabs.com/simp/simp_firewalld)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-simp_firewalld.svg)](https://travis-ci.org/simp/pupmod-simp-simp_firewalld)

#### Table of Contents

<!-- vim-markdown-toc GFM -->

* [Overview](#overview)
* [This is a SIMP module](#this-is-a-simp-module)
* [Module Description](#module-description)
* [Setup](#setup)
  * [Beginning with simp_firewalld](#beginning-with-simp_firewalld)
* [Usage](#usage)
  * [Opening a specific port](#opening-a-specific-port)
  * [Allowing full access from a specific node](#allowing-full-access-from-a-specific-node)
  * [Allowing a range of TCP ports over IPv4](#allowing-a-range-of-tcp-ports-over-ipv4)
* [Reference](#reference)
* [Limitations](#limitations)
* [Development](#development)
  * [Acceptance tests](#acceptance-tests)

<!-- vim-markdown-toc -->

## Overview

`simp_firewalld` provides a profile class and defined type to manage the
system's firewalld with "safe" defaults and safety checks for firewalld rules.
It uses the [puppet/firewalld][puppet-firewalld] module to update the system's
firewalld configuration.


## This is a SIMP module

This module is a component of the [System Integrity Management
Platform](https://simp-project.com), a compliance-management framework built on
Puppet.

If you find any issues, submit them to our [bug
tracker](https://simp-project.atlassian.net/).

This module is optimally designed for use within a larger SIMP ecosystem, but
it can be used independently:

 * When included within the SIMP ecosystem, security compliance settings will
   be managed from the Puppet server.
 * If used independently, all SIMP-managed security subsystems are disabled by
   default and must be explicitly opted into by administrators.  Please review
   the parameters in
   [`simp/simp_options`](https://github.com/simp/pupmod-simp-simp_options) for
   details.


## Module Description

On systems containing the `firewalld` service, `simp_firewalld` manages the
system's firewalld configuration with "safe" defaults and safety checks for firewalld rules.

* The [puppet/firewalld][puppet-firewalld] module is used to update the
  system's firewalld configuration.

## Setup

### Beginning with simp_firewalld

Start by classifying the node with `simp_firewalld` and start adding rules with
`simp_firewalld::rule`:

```puppet
  include 'simp_firewalld'

  # Add rules with simp_firewalld::rule
  simp_firewalld::rule { 'allow_all_ssh':
    trusted_nets => ['all'],
    protocol     => tcp,
    dports       => 22
  }
```

See the [Usage](#usage) section and [REFERENCE.md](REFERENCE.md) file for
examples of setting firewall rules.


## Usage

### Opening a specific port

```puppet
  simp_firewalld::rule { 'allow_all_ssh':
    trusted_nets => ['all'],
    protocol     => tcp,
    dports       => 22
  }
```

Note that **when using `simp_firewalld::rule` as part of the full SIMP
framework**, the `trusted_nets` parameter will default to the value of
`$simp_options::trusted_nets`:

```puppet
  simp_firewalld::rule { 'allow_ssh_to_trusted_nets':
    trusted_nets => $simp_options::trusted_nets, 
    protocol     => tcp,
    dports       => 22
  }
```

### Allowing full access from a specific node

```puppet
simp_firewalld::rule { 'allow_all_to_central_management':
  trusted_nets => ['10.10.35.100'],
  protocol     => 'all',
}
```

### Allowing a range of TCP ports over IPv4

```puppet
simp_firewalld::rule { 'allow_tcp_range':
  trusted_nets => ['192.168.1.0/24'],
  dports       => ['1024:60000'],
  apply_to     => 'ipv4',
}
```

## Reference

See [REFERENCE.md](./REFERENCE.md)

## Limitations

* This module is intended to be used on a Redhat Enterprise Linux-compatible
  distribution such as EL7 and EL8.
* IPv6 support has not been fully tested, use with caution

## Development

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).

### Acceptance tests

This module includes [Beaker](https://github.com/puppetlabs/beaker) acceptance
tests using the SIMP [Beaker Helpers](https://github.com/simp/rubygem-simp-beaker-helpers).
By default the tests use [Vagrant](https://www.vagrantup.com/) with
[VirtualBox](https://www.virtualbox.org) as a back-end; Vagrant and VirtualBox
must both be installed to run these tests without modification. To execute the
tests, run the following:

```shell
bundle install
bundle exec rake beaker:suites[default]
```

Please refer to the [SIMP Beaker Helpers
documentation](https://github.com/simp/rubygem-simp-beaker-helpers/blob/master/README.md)
for more information.

[puppet-firewalld]: https://github.com/voxpupuli/puppet-firewalld
