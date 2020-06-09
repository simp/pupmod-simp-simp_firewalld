# Valid families to which rules should apply
type Simp_firewalld::ApplyTo = Enum[
  'ipv4',
  'ipv6',
  'all',
  'auto'
]
