resource "openstack_networking_port_v2" "{{ .Resource.Name }}" {
    provider       = openstack.ovh
    name           = "{{ .Resource.Name }}"
    network_id     = "{{ .Resource.NetworkID }}"
    admin_state_up = true
    region         = "{{ .Provider.Authentication.Region }}"
    security_group_ids = var.request.ports[count.index].SecurityGroupIDs
    fixed_ip {
        subnet_id  = "{{ .Resource.SubnetID }}"
    }
}

output "port_id" {
    value = "${openstack_networking_port_v2.{{ .Resource.Name }}.id}"
}

resource "openstack_compute_instance_v2" "{{ .Resource.Name }}" {
    provider        = openstack.ovh
    name            = "{{ .Resource.Name }}"
    # key_pair        = var.request.hosts[count.index].KeyPairID
    flavor_name     = "{{ .Resource.TemplateID }}"
    image_name      = "{{ .Resource.ImageID }}"
    security_groups = [ "default" ]
    region          = "{{ .Provider.Authentication.Region }}"
    network {
        port = ${openstack_networking_port_v2.{{ .Resource.Name }}.id}
    }
}

output "host_id" {
    value = "${openstack_compute_instance_v2.{{ .Resource.Name }}.id}"
}
