resource "openstack_networking_network_v2" "{{ .Resource.Name }}" {
    provider              = openstack.ovh
{{ if .Resource.ID }}
    network_id            = "{{ .Resource.ID }}"
{{ end }}
    name                  = "{{ .Resource.Name }}"
    admin_state_up        = true
    port_security_enabled = true
    shared                = false
    tenant_id             = "{{ .Provider.Authentication.TenantID }}"
    region                = "{{ .Provider.Authentication.Region }}"
}

output "id" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.id}"
}
