resource "openstack_networking_network_v2" "network_inspect" {
    provider              = openstack.ovh
{{ if .Resource.Name }}
    name                  = "{{ .Resource.Name }}"
{{ end }}
    admin_state_up        = true
    port_security_enabled = true
    shared                = false
    tenant_id             = "{{ .Provider.Authentication.TenantID }}"
    region                = "{{ .Provider.Authentication.Region }}"
}

data "openstack_networking_network_v2" "network_inspect" {
    provider = openstack.ovh
{{- if .Resource.ID }}
    network_id = "{{ .Resource.ID }}"
{{- else }}
{{-   if .Resource.Name }}
    name = "{{ .Resource.Name }}"
{{-   end }}
{{- end }}
    tenant_id = "{{ or .Provider.Authentication.TenantID .Provider.Authentication.TenantName }}"
    region = "{{ .Provider.Authentication.Region }}"
}

output "id" {
    value = "${data.openstack_networking_network_v2.network_inspect.id}"
}
output "name" {
    value = "${data.openstack_networking_network_v2.network_inspect.name}"
}
output "subnets" {
    value = "${data.openstack_networking_network_v2.network_inspect.subnets}"
}
output "tags" {
    value = "${data.openstack_networking_network_v2.network_inspect.all_tags}"
}
