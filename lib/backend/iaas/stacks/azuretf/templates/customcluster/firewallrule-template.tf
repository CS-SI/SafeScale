resource "azurerm_network_security_rule" "{{.RuleName}}" {
  name                        = "${var.customcluster_name}-{{.RuleName}}"
  priority                    = {{.Priority}}
  direction                   = "{{.Direction}}"
  access                      = "Allow"
  protocol                    = "{{.Protocol}}"
  source_port_range           = "*"
  destination_port_range      = "{{.PortRange}}"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.customcluster_network_sg.name

  depends_on = [azurerm_resource_group.rg, azurerm_network_security_group.customcluster_network_sg]
}
