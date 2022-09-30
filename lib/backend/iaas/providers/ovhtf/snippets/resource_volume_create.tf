resource "openstack_blockstorage_volume_v2" "{{ .Resource.Name }}" {
    provider    = openstack.ovh
    name        = "{{ .Resource.Name }}"
    description = "{{ .Resource.Description }}"
    region      = "{{ .Provider.Authentication.Region }}"
    size        = {{ .Resource.Size }}
}

output "id" {
    value = "${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}"
}
