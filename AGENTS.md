# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-simp_firewalld` is a SIMP Puppet module that provides a SIMP-integrated
interface to **firewalld**. It is a thin, opinionated wrapper around the
`puppet/firewalld` (voxpupuli) module: it declares the upstream `firewalld`
class with "safe" SIMP defaults, carves out a dedicated `99_simp` firewalld
zone, and offers a `simp_firewalld::rule` defined type that turns simple
port/protocol/`trusted_nets` inputs into firewalld services, rich rules, and
ipsets.

The design intent is that SIMP owns a single, high-priority zone (`99_simp`)
and drives everything through it, leaving the rest of the firewalld
configuration free for other, non-interfering manipulation
(`manifests/init.pp:45-53`).

### Business logic

The module has exactly two manifests: the `simp_firewalld` class
(`manifests/init.pp`) and the `simp_firewalld::rule` defined type
(`manifests/rule.pp`). Neither is `assert_private()`'d.

- **`simp_firewalld` (`manifests/init.pp:93-179`)** — Public entry class.
  Everything is gated on `$enable`; when disabled the class is effectively a
  no-op. Key parameters:
  - `$rules` (`Hash`, **no default in signature**) — supplied from module data
    (`data/common.yaml` → `{}`, `init.pp:94`). Each entry is passed splat-style
    to `simp_firewalld::rule` (`init.pp:173-177`).
  - `$firewall_backend` (`Enum['iptables','nftables']`, **no default in
    signature**) — supplied from module data (`data/common.yaml` → `nftables`;
    overridden per-OS in `data/os/*.yaml`, e.g. `iptables` for Amazon and
    RedHat-8.0/8.1, `init.pp:95`).
  - `$enable` (`Boolean`) — the master switch. Defaults to whether `firewalld`
    appears in the `simplib__firewalls` fact:
    `'firewalld' in pick($facts['simplib__firewalls'], 'none')` (`init.pp:96`).
    Set `true` explicitly in Hiera to force management even when the fact does
    not report firewalld.
  - `$complete_reload` (`Boolean`, default `false`) — when `false`, the class
    **disables** the upstream `firewall-cmd --complete-reload` exec by
    collector-overriding it with `onlyif => '/bin/false'` (`init.pp:143-146`),
    because a complete reload breaks all existing connections.
  - `$lockdown` (`Boolean`, default `true`) — translated to the upstream
    module's `yes`/`no` string (`init.pp:123`) and passed to the `firewalld`
    class.
  - `$default_zone` (`String[1]`, default `'99_simp'`) — **IMPORTANT:** if set
    to anything other than `99_simp`, this module's rules will NOT apply to the
    default zone, because the module only populates the `99_simp` zone
    (`init.pp:45-53`).
  - `$package_ensure` (`String[1]`) — defaults to
    `simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' })`
    (`init.pp:117`).
  - Zone-purge / zone-target / interface / masquerade / tidy parameters
    (`init.pp:100-116`) feed the `firewalld_zone { '99_simp' }` resource and
    the tidy resources below.

  Control flow and resources (only when `$enable`):
  - Sets a default `Exec { path => '/usr/bin:/bin' }` (`init.pp:120`).
  - **firewall_backend guard** (`init.pp:128-133`): the backend is only passed
    through to the upstream class if `nft` appears in the `simplib__firewalls`
    fact; otherwise `$_firewall_backend = undef`. This works around CentOS
    diverging from upstream firewalld and breaking version matching.
  - `class { 'firewalld': }` (`init.pp:135-141`) — declares the upstream class
    with the translated lockdown, default zone, log_denied, backend, and
    package_ensure.
  - `firewalld_zone { '99_simp' }` (`init.pp:148-157`) — the SIMP zone;
    `require => Service['firewalld']`. Purge flags default to `true`, so
    unmanaged rich rules / services / ports in the zone are removed.
  - Orders `Firewalld_zone['99_simp'] -> Exec['firewalld::set_default_zone']`
    only when `$default_zone == '99_simp'` (`init.pp:159-161`).
  - `tidy { $tidy_dirs }` (`init.pp:163-171`) when `$enable_tidy` — cleans stale
    `simp_`-prefixed files older than `$tidy_minutes` from the firewalld config
    dirs.
  - Iterates `$rules` and declares a `simp_firewalld::rule` per entry
    (`init.pp:173-177`).

- **`simp_firewalld::rule` (`manifests/rule.pp:50-301`)** — Defined type that
  builds firewalld resources from simple inputs. `include simp_firewalld`
  (`rule.pp:60`), then everything is gated on `$simp_firewalld::enable`; if the
  class is disabled it emits a `warning()` and does nothing (`rule.pp:298-300`).
  Key parameters:
  - `$protocol` (`Enum['ah','esp','icmp','tcp','udp','all']`, **required**).
  - `$trusted_nets` (`Simplib::Netlist`) — defaults to
    `simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] })`
    (`rule.pp:52`).
  - `$dports` (`Optional[Simp_firewalld::DestPort]`), `$icmp_blocks`, `$order`
    (`Integer[0]`, default `11`), `$apply_to` (`Simp_firewalld::ApplyTo`,
    default `'auto'`), `$prefix`, `$zone`.
  - `$prefix` defaults to `pick($simp_firewalld::tidy_prefix, 'simp_')`
    (`rule.pp:63-68`); `$zone` defaults to
    `pick($simp_firewalld::default_zone, '99_simp')` (`rule.pp:70-75`).

  Logic (`rule.pp:77-296`):
  - Sanitizes the resource name into `$_safe_name` (`rule.pp:77`).
  - Protocol branching: `icmp` uses `$icmp_blocks`; `ah`/`esp` take no ports;
    otherwise ports are normalized (IPTables `:` range → firewalld `-`) and a
    `firewalld_custom_service` is created (`rule.pp:79-116`).
  - **allow-from-all detection** (`rule.pp:118-128`): if `trusted_nets`
    contains `0.0.0.0/0`, `::/0`, `[::]/0`, `ALL`, or `any`, it adds a plain
    `firewalld_service` to the zone (when ports exist) instead of building
    ipsets, since source matching is irrelevant.
  - Otherwise it splits `trusted_nets` into per-family (`ipv4`/`ipv6`) hosts vs.
    nets via `simplib::ip::family_hash`, builds deterministic `firewalld_ipset`
    resources (`hash:ip` / `hash:net`, name seeded via `seeded_rand_string`,
    truncated to 31 chars), and emits `firewalld_rich_rule` resources per family
    (`rule.pp:138-295`).
  - **Hostname warning** (`rule.pp:153-162`): firewalld cannot handle hostnames,
    so any unresolvable/hostname entries in `trusted_nets` trigger a `notify`
    with `loglevel => 'warning'` and are dropped from the hash.
  - Works around a `puppet-firewalld` bug by ordering the custom service before
    its rich rule (`rule.pp:287-290`).

### Gotchas / non-obvious details

- **Everything is gated on `$enable`.** The class body and the entire
  `simp_firewalld::rule` body only run when `$simp_firewalld::enable` is true.
  `$enable` auto-detects from the `simplib__firewalls` fact (`init.pp:96`); a
  rule declared while the class is disabled just logs a warning
  (`rule.pp:298-300`).
- **This module only manages the `99_simp` zone.** Changing `$default_zone`
  away from `99_simp` means the module's rules no longer apply to the default
  zone (`init.pp:45-53`). To override arbitrary firewalld settings, use Hiera on
  the upstream `firewalld` class directly, not on `simp_firewalld`
  (`init.pp:3-4`).
- **Complete reloads are disabled by default.** `$complete_reload => false`
  neuters the upstream `firewall-cmd --complete-reload` exec via a resource
  collector (`init.pp:143-146`), because a full reload drops all connections.
- **The firewall backend is conditionally suppressed.** Even though
  `$firewall_backend` has a value, it is only forwarded to the upstream class
  when `nft` is in the `simplib__firewalls` fact (`init.pp:128-133`) — a
  workaround for CentOS's divergence from upstream firewalld version matching.
- **firewalld cannot use hostnames in `trusted_nets`.** Hostname entries are
  warned about and silently dropped (`rule.pp:153-162`); only IP addresses /
  CIDRs make it into ipsets.
- **ipset names are deterministic but truncated.** They are seeded with
  `seeded_rand_string` over the family/type/nets and cut to 31 chars
  (`rule.pp:206-213`) due to ipset name-length limits; the acceptance spec
  hard-codes the expected names (`spec/acceptance/suites/default/00_default_spec.rb:72-73`).
- **`simp/simp_options` is NOT a declared dependency** in `metadata.json`, yet
  both manifests consume the `simp_options::*` seam via `simplib::lookup`
  (provided by `simp/simplib`). `simp_options` appears only as a fixture
  (`.fixtures.yml:6`).
- **No `assert_private()` calls** — both the class and the define are public and
  intended to be declared directly.

## The `simp_options` / `simplib::lookup` seam

This is the module's SIMP-integration seam (the natural target for a
lookup-path unit test):

| Line | Key | `default_value` |
|------|-----|-----------------|
| `init.pp:117` | `simp_options::package_ensure` | `'installed'` |
| `rule.pp:52` | `simp_options::trusted_nets` | `['127.0.0.1']` |

Keep routing SIMP feature toggles through `simplib::lookup('simp_options::*', {
'default_value' => ... })` with an explicit default rather than assuming
`simp_options` is included.

## Dependencies

Module dependencies (from `metadata.json`):

- `puppet/firewalld` `>= 4.2.3 < 6.0.0` — the upstream firewalld module this
  module wraps (provides the `firewalld` class and the `firewalld_zone`,
  `firewalld_service`, `firewalld_custom_service`, `firewalld_rich_rule`, and
  `firewalld_ipset` types).
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0`.
- `simp/simplib` `>= 4.9.0 < 5.0.0` (provides `simplib::lookup`,
  `simplib::ip::family_hash`, `seeded_rand_string`, the `Simplib::Netlist` /
  `Simplib::Port` data types, and the `simplib__firewalls` fact).

There are **no optional dependencies**.

Fixture-only dependencies (from `.fixtures.yml`, present for test compilation,
not runtime deps): `augeas_core`, `simp_options` (plus the runtime deps above
are also checked out as fixtures).

Runtime requirement (from `metadata.json` `requirements`): `puppet
>= 7.0.0 < 9.0.0`. This is an older baseline that still names **puppet**, not
openvox. (SIMP is migrating Puppet → OpenVox; when `metadata.json` switches this
to `openvox`, update this line to match.)

Supported OS matrix (from `metadata.json`): Amazon 2; CentOS 8/9/10; RedHat
8/9/10; OracleLinux 8/9/10; Rocky 8/9/10; AlmaLinux 8/9/10. (Note the Amazon 2
entry — unusual for this module family.)

## Repository layout

- `manifests/init.pp` — the `simp_firewalld` class (wrapper + `99_simp` zone).
- `manifests/rule.pp` — the `simp_firewalld::rule` defined type (rule builder).
- `types/applyto.pp` — `Simp_firewalld::ApplyTo` (`ipv4`/`ipv6`/`all`/`auto`).
- `types/destport.pp` — `Simp_firewalld::DestPort` (port / range / array).
- `types/portrange.pp` — `Simp_firewalld::PortRange` (firewalld `NNN:NNN`
  range pattern).
- `data/common.yaml` — defaults: `firewall_backend: nftables`, `rules: {}`.
- `data/os/*.yaml` — per-OS `firewall_backend` overrides (`iptables` for Amazon
  and RedHat-8.0/8.1; `nftables` for RedHat-8/9/10).
- `hiera.yaml` — module data hierarchy (v5): OS family+major.minor → OS
  family+major → OS name → OS family → common.
- `metadata.json` — deps, OS matrix, Puppet requirement.
- `spec/classes/init_spec.rb` — rspec-puppet unit tests for the class.
- `spec/defines/rule/*.rb` — rspec-puppet unit tests for the define, one file
  per protocol style (`ah_esp`, `all`, `icmp`, `tcp_stateful`, `udp`).
- `spec/unit/data_types/*.rb` — data-type specs (`destport`, `portrange`).
- `spec/acceptance/suites/default/00_default_spec.rb` — beaker acceptance suite
  (applies rules and asserts firewalld zone/service/rich-rule/ipset state);
  nodesets under `spec/acceptance/nodesets/` (19 files).
- `REFERENCE.md` — generated Puppet Strings reference (if present).
- No `lib/` or `templates/` — this module has no custom Ruby
  types/providers/functions/facts or templates. The custom types it uses come
  from the dependencies above; the only local custom types are the Puppet data
  types in `types/`.
- **Acceptance runs in CI:** `.github/workflows/pr_tests.yml` has an
  `acceptance` job (`pr_tests.yml:120`) that runs on **docker nodes** via
  podman — matrix `docker_alma8/9/10`, `docker_centos9/10`, `docker_oel8/9/10`,
  `docker_rocky8/9/10` — setting
  `DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock` (`pr_tests.yml:151`)
  rather than a `BEAKER_HYPERVISOR: vagrant_libvirt` var. It runs
  `bundle exec rake beaker:suites[default,<node>]`. Alongside it are the
  standard `puppet-syntax`, `puppet-style`, `ruby-style`, `file-checks`,
  `releng-checks`, and `spec-tests` jobs.

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Run a single spec
bundle exec rspec spec/classes/init_spec.rb
bundle exec rspec spec/defines/rule/tcp_stateful_spec.rb

# Puppet lint
bundle exec rake lint

# Ruby lint
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run the default beaker acceptance suite against a docker node
bundle exec rake beaker:suites[default,docker_alma9]
```

Relevant gem pins (from `Gemfile`): the Puppet gem range defaults to
`['>= 7', '< 9']` (`Gemfile:23`) and only the **puppet** gem is installed —
`gem 'puppet', puppet_version` (`Gemfile:29`), no openvox gem. Other pins:
`rubocop ~> 1.88.0` (`Gemfile:16`), `puppetlabs_spec_helper ~> 8.0.0`
(`Gemfile:30`), `simp-rake-helpers ~> 5.24.0` (`Gemfile:36`),
`simp-beaker-helpers ~> 2.0.0` (`Gemfile:53`).
`spec/spec_helper.rb:11` requires `puppetlabs_spec_helper/module_spec_helper`.

## Conventions

- Preserve the `@summary` / `@param` puppet-strings docstrings on the class and
  define — they drive `REFERENCE.md`. Regenerate `REFERENCE.md` after changing
  docs or parameters.
- Keep `$firewall_backend` and `$rules` defaults in module data (`data/*.yaml`),
  not hard-coded in the manifest signature.
- Continue routing SIMP feature toggles through
  `simplib::lookup('simp_options::*', { 'default_value' => ... })` rather than
  assuming `simp_options` is included.
- Only manage the `99_simp` zone; do not spread rules across the default zone.
  To override upstream firewalld settings, apply Hiera to the `firewalld` class
  directly.
- `Gemfile`, `spec/spec_helper.rb`, and `.github/workflows/pr_tests.yml` carry a
  **puppetsync** notice — they are baseline-managed and the next sync overwrites
  local edits. Push changes to those files upstream to the baseline, not here.
- Match the existing 2-space Puppet indentation and aligned-arrow parameter
  style used in `manifests/init.pp` and `manifests/rule.pp`.
