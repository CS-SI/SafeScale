resource "random_password" "password-{{.MachineName}}" {
  length           = 16
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  special          = true
  override_special = "_%@"

  depends_on = [azurerm_resource_group.rg]
}

resource "tls_private_key" "ssh-{{.MachineName}}" {
  algorithm = "RSA"
  rsa_bits  = 4096

  depends_on = [azurerm_resource_group.rg]
}

resource "local_file" "ssh_private_key_pem-{{.MachineName}}" {
  content         = tls_private_key.ssh-{{.MachineName}}.private_key_pem
  filename        = ".ssh/azure_compute_engine-${var.customcluster_name}-{{.MachineName}}"
  file_permission = "0600"

  depends_on = [azurerm_resource_group.rg]
}

resource "local_file" "ssh_public_key_pem-{{.MachineName}}" {
  content         = tls_private_key.ssh-{{.MachineName}}.public_key_openssh
  filename        = ".ssh/azure_compute_engine-${var.customcluster_name}-{{.MachineName}}.pub"
  file_permission = "0600"

  depends_on = [azurerm_resource_group.rg]
}

# Create network interface for others
resource "azurerm_network_interface" "nic-{{.MachineName}}" {
  name                = "nic-{{.MachineName}}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ip_nic_cfg-{{.MachineName}}-${var.customcluster_name}"
    subnet_id                     = azurerm_subnet.customcluster_subnet.id
    private_ip_address_allocation = "Dynamic"
  }

  depends_on = [azurerm_resource_group.rg, azurerm_network_interface.gateway_nic]
}

# Create virtual machine
resource "azurerm_linux_virtual_machine" "vm-{{.MachineName}}" {
  name                  = "{{.MachineName}}"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.nic-{{.MachineName}}.id]
  size                  = var.master_instance_type

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = var.os_master.publisher
    offer     = var.os_master.offer
    sku       = var.os_master.sku
    version   = "latest"
  }

  computer_name                   = "{{.MachineName}}"
  admin_username                  = var.linux_user
  disable_password_authentication = !var.debug
  admin_password                  = var.debug == true ? var.default_instance_password : random_password.password-{{.MachineName}}.result

  admin_ssh_key {
    username   = var.linux_user
    public_key = tls_private_key.ssh-{{.MachineName}}.public_key_openssh
  }

  user_data = base64encode(file("./${var.module_directory}/init.sh"))

  tags = merge(var.master_tags, var.default-tags-{{.MachineName}}, var.tags-{{.MachineName}}, {
    NetworkID = azurerm_virtual_network.customcluster_network.id
    SubnetID = azurerm_subnet.customcluster_subnet.id
  })

  depends_on = [azurerm_resource_group.rg]
}

variable "default-tags-{{.MachineName}}" {
  type = map(string)
  default = {
    Name = "{{.MachineName}}"
    CreationDate = "{{.TimeStamp}}"
    NetworkName = "{{.NetworkName}}"
  }
}

output "host-{{.MachineName}}" {
  sensitive = true
  value = [for master in [azurerm_linux_virtual_machine.vm-{{.MachineName}}] : {
    id : master.virtual_machine_id,
    name : master.name,
    private_ip : master.private_ip_address,
    user : master.admin_username,
    password : master.admin_password,
    public_key : flatten([for k, v in master.admin_ssh_key : v.public_key if !contains([""], v.public_key)]),
    private_key: tls_private_key.ssh-{{.MachineName}}.private_key_pem,
    network: var.customcluster_name,
  }]
}

output "private-key-{{.MachineName}}" {
  sensitive = true
  value = tls_private_key.ssh-{{.MachineName}}.private_key_pem
}
