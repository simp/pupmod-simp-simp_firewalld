# A firewalld-compatible Port Range
type Simp_firewalld::PortRange = Pattern['^([0-5]?\d?\d?\d?\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]):([0-5]?\d?\d?\d?\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5])$']
