resource "openstack_networking_network_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}"					# var.request.networks[count.index].Name
    admin_state_up          = true
    port_security_enabled   = true
    shared                  = false
    tenant_id               = "{{ .Provider.Authentication.TenantID }}"	# "${var.tenant.identity.ApplicationKey}"
    region                  = "{{ .Provider.Authentication.Region }}"	# "${var.tenant.compute.Region}"
}

output "network_id" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.id}"
}
