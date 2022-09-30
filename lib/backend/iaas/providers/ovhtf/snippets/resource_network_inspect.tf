data "openstack_networking_network_v2" "{{ .ResourceName }}" {
{{- if .Resource.ID }}
    id = "{{ .Resource.ID }}"
{{- else }}
{{-   if .Resource.Name }}
    name = "{{ .Resource.Name }}"
{{-   end }}
{{- end }}
    tenant_id = "{{ or .Provider.Authentication.TenantID .Provider.Authentication.TenantName }}"
}

output "id" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.id}"
}
output "name" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.name}"
}
output "subnets" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.subnets}"
}
output "tags" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.all_tags}"
}
