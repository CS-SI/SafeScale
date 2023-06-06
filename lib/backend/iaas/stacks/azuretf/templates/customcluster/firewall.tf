resource "azurerm_network_security_rule" "SSH" {
  name                        = "${var.customcluster_name}-SSH"
  priority                    = 1001
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.customcluster_network_sg.name

  depends_on = [azurerm_resource_group.rg, azurerm_network_security_group.customcluster_network_sg]
}
