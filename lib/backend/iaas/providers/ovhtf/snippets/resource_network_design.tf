resource "openstack_networking_network_v2" "{{ .Resource.Name }}" {
    provider              = openstack.ovh
    name                  = "{{ .Resource.Name }}"
    admin_state_up        = true
    port_security_enabled = true
    shared                = false
    tenant_id             = "{{ .Provider.Authentication.TenantID }}"
    region                = "{{ .Provider.Authentication.Region }}"
}

output "network_{{ .Resource.Name }}_id" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.id}"
}
