resource "openstack_compute_volume_attach_v2" "{{ .Resource.Name }}" {
    provider    = openstack.ovh
    instance_id = "{{ .Resource.HostID }}"
    volume_id   = "{{ .Resource.VolumeID }}"
}

output "id" {
    value = "${openstack_compute_volume_attach_v2.{{ .Resource.Name }}.id}"
}
