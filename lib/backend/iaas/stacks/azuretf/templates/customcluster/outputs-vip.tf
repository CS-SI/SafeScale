output "cluster-gateways-vip" {
  sensitive = true
  value = var.gateways_count >= 2 ? [for master in [azurerm_linux_virtual_machine.gateway, azurerm_linux_virtual_machine.gateway2] : {
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