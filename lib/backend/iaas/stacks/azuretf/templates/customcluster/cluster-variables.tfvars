module customcluster_{{.Name}}_module {
    source = "./customcluster_{{.Name}}"
    module_directory = "./customcluster_{{.Name}}"

    customcluster_name = "{{ .Name }}"
    customcluster_identity = "{{ .Identity }}"
    region = "{{ .Region }}"
    debug = true
    gw-disk-size = {{if le .GwDiskSize 0 }}30{{else}}{{ .GwDiskSize }}{{end}}
    master-disk-size = {{if le .MasterDiskSize 0}}30{{else}}{{ .MasterDiskSize }}{{end}}

    netcidr = "{{ .Cidr }}"

    creation_date = "{{ .CreationDate }}"

    default_instance_type = "Standard_DS1_v2"
    gw_instance_type = "{{if .GwTemplate }}{{ .GwTemplate }}{{else}}Standard_DS1_v2{{end}}"
    master_instance_type = "{{if .MasterTemplate }}{{ .MasterTemplate }}{{else}}Standard_DS1_v2{{end}}"

    masters_count = {{ .Masters }}

    linux_user = "{{if .OperatorUsername }}{{ .OperatorUsername }}{{else}}safescale{{end}}"
    resource_group_location = "{{ .Region }}"
    resource_group_name_prefix = "rg"

    {{if .GwOsSku }}
    os_gw = {
        publisher = "{{ .GwOsPublisher }}"
        offer     = "{{ .GwOsOffer }}"
        sku       = "{{ .GwOsSku }}"
        version   = "{{ .GwOsVersion }}"
    }
    {{else}}
    os_gw = {
        publisher = "Canonical"
        offer     = "0001-com-ubuntu-minimal-focal"
        sku       = "minimal-20_04-lts"
        version   = "latest"
    }
    {{end}}

    {{if .MasterOsSku }}
    os_master = {
        publisher = "{{ .MasterOsPublisher }}"
        offer     = "{{ .MasterOsOffer }}"
        sku       = "{{ .MasterOsSku }}"
        version   = "{{ .MasterOsVersion }}"
    }
    {{else}}
    os_master = {
        publisher = "Canonical"
        offer     = "0001-com-ubuntu-minimal-focal"
        sku       = "minimal-20_04-lts"
        version   = "latest"
    }
    {{end}}
}

# Create output for the gateway username
output "customcluster_{{.Name}}_module-operator" {
  value = module.customcluster_{{.Name}}_module.operator
}

# Create output for the gateway cidr
output "customcluster_{{.Name}}_module-cidr" {
  value = module.customcluster_{{.Name}}_module.cidr
}

# Create output for the subnetwork cidr
output "customcluster_{{.Name}}_module-subnet_cidr" {
  value = module.customcluster_{{.Name}}_module.subnet_cidr
}

# Create output for the network id
output "customcluster_{{.Name}}_module-network_id" {
  value = module.customcluster_{{.Name}}_module.network_id
}

# Create output for subnetwork id
output "customcluster_{{.Name}}_module-subnet_id" {
  value = module.customcluster_{{.Name}}_module.subnet_id
}

# Create output for os_node id
output "customcluster_{{.Name}}_module-os_installed_id" {
  value = module.customcluster_{{.Name}}_module.os_installed_id
}

output "customcluster_{{.Name}}_module-cluster-gateways" {
  sensitive = true
  value = module.customcluster_{{.Name}}_module.cluster-gateways
}

output "customcluster_{{.Name}}_module-gw-public-ip" {
  value = module.customcluster_{{.Name}}_module.gw-public-ip
}

output "customcluster_{{.Name}}_module-private-key" {
  sensitive = true
  value = module.customcluster_{{.Name}}_module.private-key
}
