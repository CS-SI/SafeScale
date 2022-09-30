resource "openstack_networking_subnet_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}" 					# var.request.subnets[count.index].Name
    network_id              = "{{ .Resource.NetworkID }}"				# var.request.subnets[count.index].NetworkID
    cidr                    = "{{ .Resource.CIDR }}" 					# var.request.subnets[count.index].CIDR
    ip_version              = "{{ .Resource.IPVersion }}"				# var.request.subnets[count.index].IPVersion
    region                  = "{{ .Provider.Authentication.Region }}"	#"${var.tenant.compute.Region}"
    enable_dhcp             = true
}

output "subnet_id" {
    value = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.id}"
}

{{- if .Provider.Configuration.UseLayer3Networking }}
resource "openstack_networking_router_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}"
    external_network_id     = "{{ .Provider.Configuration.ProviderNetworkID }}"
    tenant_id               = "{{ .Provider.Authentication.TenantID }}"
    region                  = "{{ .Provider.Authentication.Region }}"
}

resource "openstack_networking_router_interface_v2" "router_interface_1" {
    router_id = "${openstack_networking_router_v2.{{ .Resource.Name }}.id}"
    subnet_id = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.id}"
}

output "router_id" {
    value = "${openstack_networking_router_v2.{{ .Resource.Name }}.id}"
}
{{- end }}

