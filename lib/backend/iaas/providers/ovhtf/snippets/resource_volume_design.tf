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

{{    range $k, $v := $extra.Attachments }}
resource "openstack_compute_volume_attach_v2" "volume_{{ .Resource.Name }}_host_{{ $v }}" {
	provider    = openstack.ovh
	instance_id = "{{ $k }}"
	volume_id   = ${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}
	region      = "{{ .Provider.Authentication.Region }}"
	tenant_id   = "{{ .Provider.Authentication.TenantID }}"
}

output "volume_{{ .Resource.Name }}_host_{{ $v }}_id" {
	value = "${openstack_compute_volume_attach_v2.volume_{{ .ResourceName }}_host_{{ $v }}.id}"
}
{{    end }}

{{ end }}
