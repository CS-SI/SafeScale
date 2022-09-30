resource "openstack_networking_subnet_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    id                      = "{{ .Resource.ID }}"
    name                    = "{{ .Resource.Name }}"
    network_id              = "{{ .Resource.NetworkID }}"
    cidr                    = "{{ .Resource.CIDR }}"
    ip_version              = "{{ .Resource.IPVersion }}"
    region                  = "{{ .Provider.Authentication.Region }}"
    enable_dhcp             = true
}
