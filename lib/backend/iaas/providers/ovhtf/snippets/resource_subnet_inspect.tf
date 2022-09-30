data "openstack_networking_subnet_v2" "{{ .ResourceName }}" {
{{- if .Resource.ID }}
    id = "{{ .Resource.ID }}"
{{- else }}
{{-   if .Resource.Name }}
    name = "{{ .Resource.Name }}"
{{-   end }}
{{- end }}
    network_id = "{{ .Resource.NetworkID }}"
    tenant_id = "{{ or .Provider.Authentication.TenantID .Provider.Authentication.TenantName }}"
}

output "id" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.id}"
}
output "name" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.name}"
}
output "allocation_pools" {
    value = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.allocation_pools}"
}
output "host_routes" {
    value = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.hoist_routes}"
}
output "tags" {
    value = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.all_tags}"
}
