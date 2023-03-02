{{- if not .Extra.MarkedForDestruction }}
{{-   $extra := .Extra }}
{{-   $az := "nova" }}
{{-   if hasField $extra "AvailabilityZone" }}
{{-     $az := $extra.AvailabilityZone }}
{{-   end }}
resource "openstack_blockstorage_volume_v2" "{{ .Resource.Name }}" {
	provider          = openstack.ovh
	name              = "{{ .Resource.Name }}"
	size              = {{ .Resource.Size }}
	region            = "{{ .Provider.Authentication.Region }}"
	availability_zone = "{{ $az }}"
	volume_type       = "{{ index $extra.VolumeTypes .Resource.Speed }}"

	metadata = {
{{-   range $t, $v := .Resource.Tags }}
		{{ $t }} = "{{ $v }}"
{{-   end }}
	}

	lifecycle {
		ignore_changes = [ volume_type ]
	}
}

output "volume_{{ .Resource.Name }}_id" {
	value = "${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}"
}

{{    range $k, $v := $extra.Attachments }}
resource "openstack_compute_volume_attach_v2" "volume_{{ .Resource.Name }}_host_{{ $v }}" {
	provider    = openstack.ovh
	instance_id = "{{ $k }}"
	volume_id   = ${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}
	region      = "{{ .Provider.Authentication.Region }}"
}

output "volume_{{ .Resource.Name }}_host_{{ $v }}_id" {
	value = "${openstack_compute_volume_attach_v2.volume_{{ .ResourceName }}_host_{{ $v }}.id}"
}
{{    end }}

{{ end }}
