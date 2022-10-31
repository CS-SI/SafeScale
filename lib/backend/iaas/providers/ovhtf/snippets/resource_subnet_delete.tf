resource "openstack_networking_subnet_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
{{- if .Resource.ID }}
    subnet_id               = "{{ .Resource.ID }}"
{{- end }}
{{- if .Resource.Name }}
    name                    = "{{ .Resource.Name }}"
{{- end }}
    network_id              = "{{ .Resource.NetworkID }}"
    cidr                    = "{{ .Resource.CIDR }}"
    ip_version              = "{{ .Resource.IPVersion }}"
    region                  = "{{ .Provider.Authentication.Region }}"
    enable_dhcp             = true
}
