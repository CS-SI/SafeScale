resource "openstack_blockstorage_volume_v2" "{{ .Resource.Name }}" {
    provider    = openstack.ovh
    name        = "{{ .Resource.Name }}"
    description = "{{ .Resource.Description }}"
    size        = {{ .Resource.Size }}
    region      = "{{ .Provider.Authentication.Region }}"
    tenant_id   = "{{ .Provider.Authentication.TenantID }}"
}

output "volume_{{ .Resource.Name }}_id" {
    value = "${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}"
}
