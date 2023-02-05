{{- if not .Extra.MarkedForDestruction }}
resource "openstack_networking_subnet_v2" "{{ .Resource.Name }}" {
	provider    = openstack.ovh
	name        = "{{ .Resource.Name }}"
	network_id  = "{{ .Resource.Network }}"
	cidr        = "{{ .Resource.CIDR }}"
	ip_version  = {{ eq .Resource.IPVersion 6 | ternary 6 4 }}
	region      = "{{ .Provider.Authentication.Region }}"
	enable_dhcp = true
}

output "subnet_{{ .Resource.Name }}" {
	value = "${openstack_networking_subnet_v2.{{ .Resource.Name }}}"
	sensitive = true
}

{{-   if .Provider.Configuration.UseLayer3Networking }}
resource "openstack_networking_router_v2" "{{ .Resource.Name }}" {
	provider            = openstack.ovh
	name                = "{{ .Resource.Name }}"
	external_network_id = "{{ .Provider.Configuration.ProviderNetworkID }}"
	tenant_id           = "{{ .Provider.Authentication.TenantID }}"
	region              = "{{ .Provider.Authentication.Region }}"
}

resource "openstack_networking_router_interface_v2" "router_interface_1" {
	router_id = "${openstack_networking_router_v2.{{ .Resource.Name }}.id}"
	subnet_id = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.id}"
}

output "router_{{ .Resource.Name }}" {
	value = "${openstack_networking_router_v2.{{ .Resource.Name }}}"
	sensitive = true
}

{{   end }}
{{- end }}
