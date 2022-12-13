resource "openstack_compute_volume_attach_v2" "{{ .Resource.Name }}" {
    provider    = openstack.ovh
    instance_id = "{{ .Resource.HostID }}"
    volume_id   = "{{ .Resource.VolumeID }}"
    region      = "{{ .Provider.Authentication.Region }}"
    tenant_id   = "{{ .Provider.Authentication.TenantID }}"

    lifecycle {
{{- if and (not .Extra.MarkedForCreation) (not .Extra.MarkedForDestruction) }}
        prevent_destroy = true
{{- end }}
    }
}

output "volume_attach_{{ .Username.Name }}_id" {
    value = "${openstack_compute_volume_attach_v2.{{ .Resource.Name }}.id}"
}
