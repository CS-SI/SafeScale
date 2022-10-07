resource "openstack_networking_network_v2" "network_delete" {
    provider                = openstack.ovh
{{- if .Resource.ID }}
    network_id              = "{{ .Resource.ID }}"
{{- end }}
{{- if .Resource.Name }}
    name                    = "{{ .Resource.Name }}"
{{- end }}
    admin_state_up          = true
    port_security_enabled   = true
    shared                  = false
    tenant_id               = "{{ .Provider.Authentication.TenantID }}"
    region                  = "{{ .Provider.Authentication.Region }}"
}
