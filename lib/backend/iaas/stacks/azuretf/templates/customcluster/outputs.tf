# Create output for the gateway username
output "operator" {
  value = azurerm_linux_virtual_machine.gateway.admin_username
}

# Create output for the gateway cidr
output "cidr" {
  value = var.netcidr
}

output "creation_date" {
  value = var.creation_date
}

# Create output for the gateway public ip
output "gw-public-ip" {
  value = azurerm_linux_virtual_machine.gateway.public_ip_address
}

# Create output for the subnetwork cidr
output "subnet_cidr" {
  value = azurerm_subnet.customcluster_subnet.address_prefixes[0]
}

# Create output for the network id
output "network_id" {
  value = azurerm_virtual_network.customcluster_network.id
}

# Create output for subnetwork id
output "subnet_id" {
  value = azurerm_subnet.customcluster_subnet.id
}

# Create output for os_node id
output "os_installed_id" {
  value = {
    offer: azurerm_linux_virtual_machine.gateway.source_image_reference[0].offer,
    publisher: azurerm_linux_virtual_machine.gateway.source_image_reference[0].publisher,
    sku: azurerm_linux_virtual_machine.gateway.source_image_reference[0].sku,
    version: azurerm_linux_virtual_machine.gateway.source_image_reference[0].version,
  }
}

output "private-key" {
  sensitive = true
  value = tls_private_key.ssh.private_key_pem
}

output "cluster-gateways" {
  sensitive = true
  value = var.gateways_count >= 2 ? [for master in [azurerm_linux_virtual_machine.gateway] : {
    id : master.virtual_machine_id,
    name : master.name,
    private_ip : master.private_ip_address,
    public_ip : master.public_ip_address,
    user : master.admin_username,
    password : master.admin_password,
    public_key : flatten([for k, v in master.admin_ssh_key : v.public_key if !contains([""], v.public_key)]),
    private_key: tls_private_key.ssh.private_key_pem,
  }] : [{
    id : azurerm_linux_virtual_machine.gateway.virtual_machine_id
    name : azurerm_linux_virtual_machine.gateway.name,
    private_ip : azurerm_linux_virtual_machine.gateway.private_ip_address,
    public_ip : azurerm_linux_virtual_machine.gateway.public_ip_address,
    user : azurerm_linux_virtual_machine.gateway.admin_username,
    password : azurerm_linux_virtual_machine.gateway.admin_password,
    public_key : flatten([for k, v in azurerm_linux_virtual_machine.gateway.admin_ssh_key : v.public_key if !contains([""], v.public_key)]),
    private_key: tls_private_key.ssh.private_key_pem,
  }]
}

output "installed_features" {
  value = var.installed_features
}

output "disabled_features" {
  value = var.disabled_features
}
