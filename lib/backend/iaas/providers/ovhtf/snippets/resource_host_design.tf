{{- for $k, $v := range .Resource.Networking.SubnetByName }}
resource "openstack_networking_port_v2" "port_{{ .Resource.Name }}_$k" {
    provider           = openstack.ovh
    name               = "port-{{ .Resource.Name }}-$k"
    network_id         = "{{ .Resource.NetworkID }}"
    admin_state_up     = true
    region             = "{{ .Provider.Authentication.Region }}"
    # security_group_ids = var.request.ports[count.index].SecurityGroupIDs
    fixed_ip {
        subnet_id = "{{ $v }}"
    }

    tags = {
{{ for $t, $v := range .Resource.Tags }}
        {{ $t }} = "{{ $v }}"
{{ end }}
    }

    lifecycle {
{{- if not .Extra.MarkedForDestroy }}
        prevent_destroy = true
{{ end }}
    }
}

output "port_{{ .Resource.Name}}_$k_id" {
    value = "${openstack_networking_port_v2.port_{{ .Resource.Name }}_$k.id}"
}
output "port_{{ .Resource.Name}}_$k_ip" {
    value = "${openstack_networking_port_v2.port_{{ .Resource.Name }}_$k.fixed_ip}"
}
{{ end }}

resource "openstack_compute_instance_v2" "{{ .Resource.Name }}" {
    provider        = openstack.ovh
    name            = "{{ .Resource.Name }}"
    # key_pair        = var.request.hosts[count.index].KeyPairID
    flavor_name     = "{{ .Resource.TemplateID }}"
    image_id        = "{{ .Resource.ImageID }}"
    security_groups = [ "default" ]
    region          = "{{ .Provider.Authentication.Region }}"
    availability_zone = "{{ .Extra.AvailabilityZone }}"
    power_state = "{{ or .Extra.WantedHostState active }}"

{{- for $k, $v := range .Resource.Networking.SubnetByName }}
    network {
        port = openstack_networking_port_v2.port_{{ .Resource.Name }}_$k.id
    }
{{ end }}
{{- if or .Resource.Networking.IsGateway .Supplemental.PublicIP }}
    network {
        name = "Ext-Net"
    }
{{ end }}

    block_device {
        uuid                  = {{ .Resource.Sizing.ImageID }}
        source_type           = "image"
        destination_type      = "local"
        volume_size           = {{ .Resource.Sizing.DiskSize }}
        boot_index            = 0
        delete_on_termination = true
    }

    user_data = "${file("{{ .Resource.Name }}_userdata")}"

    tags = {
{{ for $t, $v := range .Resource.Tags }}
        {{ $t }} = "{{ $v }}"
{{ end }}
    }

    lifecycle {
        ignore = [block_device, user_data]
{{- if not .Extra.MarkedForDestroy }}
        prevent_destroy = true
{{ end }}
    }
}

output "host_{{ .Resource.Name }}_id" {
    value = "${openstack_compute_instance_v2.{{ .Resource.Name }}.id}"
}
