data "openstack_blockstorage_volume_v2" "{{ or .Resource.Name .Resource.ID }}" {
    provider = openstack.ovh
{{- if .Resource.ID }}
    id = "{{ .Resource.ID }}"
{{- else }}
{{-   if .Resource.Name }}
    name = "{{ .Resource.Name }}"
{{-   end }}
{{- end }}
    tenant_id = "{{ or .Provider.Authentication.TenantID .Provider.Authentication.TenantName }}"
    region = "{{ .Provider.Authentication.Region }}"
}

output "id" {
    value = "${data.openstack_blockstorage_volume_v2.{{ or .Resource.Name .Resource.ID }}.id}"
}
output "name" {
    value = "${data.openstack_blockstorage_volume_v2.{{ or .Resource.Name .Resource.ID }}.name}"
}
output "tags" {
    value = "${data.openstack_blockstorage_volume_v2.{{ or .Resource.Name .Resource.ID }}.all_tags}"
}
