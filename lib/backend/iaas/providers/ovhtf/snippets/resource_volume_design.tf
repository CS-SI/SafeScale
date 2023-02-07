{{- if not .Extra.MarkedForDestruction }}
{{-   $extra := .Extra }}
{{-   $az := "nova" }}
{{-   if hasField $extra "AvailabilityZone" }}
{{-     $az := $extra.AvailabilityZone }}
{{-   end }}
resource "openstack_blockstorage_volume_v2" "{{ .Resource.Name }}" {
	provider          = openstack.ovh
	name              = "{{ .Resource.Name }}"
	description       = "{{ .Resource.Description }}"
	size              = {{ .Resource.Size }}
	region            = "{{ .Provider.Authentication.Region }}"
	availability_zone = "{{ $az }}"
	tenant_id         = "{{ .Provider.Authentication.TenantID }}"
	volume_type       = "{{ .Resource.Speed }}"

	metadata = {
{{-   range $t, $v := .Resource.Tags }}
		{{ $t }} = "{{ $v }}"
{{-   end }}
    }
}

output "volume_{{ .Resource.Name }}_id" {
	value = "${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}"
}

{{   if .Extra.Attachment }}
resource "openstack_compute_volume_attach_v2" "{{ .Extra.Attachment.Name }}" {
	provider    = openstack.ovh
	instance_id = "{{ .Extra.Attachment.ServerID }}"
	volume_id   = ${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}
	region      = "{{ .Provider.Authentication.Region }}"
	tenant_id   = "{{ .Provider.Authentication.TenantID }}"
}

output "volumeattachment_{{ .Extra.Attachment.Name }}_id" {
	value = "${openstack_compute_volume_attach_v2.{{ .Resource.Name }}.id}"
}
{{   end }}

{{ end }}
