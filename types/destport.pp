# A ``firewalld::rule`` compatible port range or Array
type Simp_firewalld::DestPort = Variant[Simplib::Port, Simp_firewalld::PortRange, Array[Variant[Simplib::Port, Simp_firewalld::PortRange]]]
