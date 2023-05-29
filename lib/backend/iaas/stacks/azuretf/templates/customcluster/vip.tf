# Create 2nd network interface for the gateway
resource "azurerm_network_interface" "gateway2_nic" {
  name                = "gw2-nic-${var.customcluster_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ip_nic_cfg_gw2-${var.customcluster_name}"
    subnet_id                     = azurerm_subnet.customcluster_subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = cidrhost(cidrsubnet(var.netcidr, 1, 1), var.last_byte+1)
  }

  enable_accelerated_networking = true
  enable_ip_forwarding          = true

  depends_on = [azurerm_resource_group.rg]
}

# Create 2nd gateway VM
resource "azurerm_linux_virtual_machine" "gateway2" {
  name                  = "gw2-${var.customcluster_name}"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.gateway2_nic.id]
  size                  = var.gw_instance_type

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = var.gw-disk-size
  }

  source_image_reference {
    publisher = var.os_ubuntu_22.publisher
    offer     = var.os_ubuntu_22.offer
    sku       = var.os_ubuntu_22.sku
    version   = "latest"
  }

  computer_name                   = "gw2-${var.customcluster_name}"
  admin_username                  = var.linux_user
  disable_password_authentication = true
  admin_password                  = var.debug == true ? var.default_gateways_password : random_password.password_gateways[0].result

  admin_ssh_key {
    username   = var.linux_user
    public_key = tls_private_key.ssh.public_key_openssh
  }

  user_data = base64encode(file("./${var.module_directory}/gw-init.sh"))

  tags = merge(var.tags_gw, {
    Name = "gw2-${var.customcluster_name}"
    CreationDate = var.creation_date
  })

  depends_on = [azurerm_resource_group.rg]
}