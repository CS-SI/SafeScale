resource "openstack_blockstorage_volume_v2" "{{ .Resource.Name }}" {
    provider    = openstack.ovh
    id          = "{{ .Resource.ID }}"
    name        = "{{ .Resource.Name }}"
    description = "{{ .Resource.Description }}"
    region      = "{{ .Provider.Authentication.Region }}"
    size        = {{ .Resource.Size }}
}
