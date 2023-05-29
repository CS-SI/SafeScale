resource "azurerm_resource_group" "rg" {
  location = var.resource_group_location
  name     = "resourcegroup-${var.resource_group_name_prefix}-${var.customcluster_name}"

  tags = var.rg_tags

  timeouts {
    create = "1m"
    delete = "2m"
  }
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096

  depends_on = [azurerm_resource_group.rg]
}

resource "local_file" "ssh_private_key_pem" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = ".ssh/azure_compute_engine-${var.customcluster_name}"
  file_permission = "0600"

  depends_on = [azurerm_resource_group.rg]
}

resource "local_file" "ssh_public_key_pem" {
  content         = tls_private_key.ssh.public_key_openssh
  filename        = ".ssh/azure_compute_engine-${var.customcluster_name}.pub"
  file_permission = "0600"

  depends_on = [azurerm_resource_group.rg]
}

# Create virtual network for the cluster
resource "azurerm_virtual_network" "customcluster_network" {
  name                = "network-${var.customcluster_name}"
  address_space       = [var.netcidr]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  depends_on          = [azurerm_resource_group.rg]
  tags = {
    Kind = var.masters_count == 0 ? "Network" : "Cluster"
    Operator = "${var.linux_user}"
  }
}

# Create subnet for the cluster
resource "azurerm_subnet" "customcluster_subnet" {
  name                 = "subnet-${var.customcluster_name}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.customcluster_network.name
  address_prefixes     = [cidrsubnet(var.netcidr, 1, 1)]
  depends_on           = [azurerm_resource_group.rg]
}

# Create public IP for the gateway
resource "azurerm_public_ip" "gw_public_ip" {
  name                = "publicip-gw-${var.customcluster_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
  depends_on          = [azurerm_resource_group.rg]
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "customcluster_network_sg" {
  name                = "NetworkSecurityGroup-${var.customcluster_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  depends_on = [azurerm_resource_group.rg]
}

resource "azurerm_subnet_network_security_group_association" "nsg-assoc" {
  subnet_id                 = azurerm_subnet.customcluster_subnet.id
  network_security_group_id = azurerm_network_security_group.customcluster_network_sg.id
}

# Create network interface for the gateway
resource "azurerm_network_interface" "gateway_nic" {
  name                = "gw-nic-${var.customcluster_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ip_nic_cfg_gw-${var.customcluster_name}"
    subnet_id                     = azurerm_subnet.customcluster_subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = cidrhost(cidrsubnet(var.netcidr, 1, 1), var.last_byte)
    public_ip_address_id          = azurerm_public_ip.gw_public_ip.id
  }

  enable_accelerated_networking = true
  enable_ip_forwarding          = true

  depends_on = [azurerm_resource_group.rg]
}

# Create gateway VM
resource "azurerm_linux_virtual_machine" "gateway" {
  name                  = "gw-${var.customcluster_name}"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.gateway_nic.id]
  size                  = var.gw_instance_type

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = var.gw-disk-size
  }

  source_image_reference {
    publisher = var.os_gw.publisher
    offer     = var.os_gw.offer
    sku       = var.os_gw.sku
    version   = "latest"
  }

  computer_name                   = "gw-${var.customcluster_name}"
  admin_username                  = var.linux_user
  disable_password_authentication = true
  admin_password                  = var.debug == true ? var.default_gateways_password : random_password.password_gateways[0].result

  admin_ssh_key {
    username   = var.linux_user
    public_key = tls_private_key.ssh.public_key_openssh
  }

  user_data = base64encode(file("./${var.module_directory}/gw-init.sh"))

  tags = merge(var.tags_gw, var.tags-gw, {
    Name = "gw-${var.customcluster_name}"
    CreationDate = var.creation_date
    NetworkID = azurerm_virtual_network.customcluster_network.id
    SubnetID = azurerm_subnet.customcluster_subnet.id
    Kind = var.masters_count == 0 ? "Network" : "Cluster"
  })

  depends_on = [azurerm_resource_group.rg]
}

resource "random_password" "password_gateways" {
  count            = var.gateways_count
  length           = 16
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  special          = true
  override_special = "_%@"

  depends_on = [azurerm_resource_group.rg]
}
