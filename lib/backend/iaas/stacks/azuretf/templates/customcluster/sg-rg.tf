# Create another network Security Group and rule named customcluster_network_sg-{{.SecurityGroupName}}
resource "azurerm_network_security_group" "customcluster_network_sg-{{.SecurityGroupName}}" {
  name                = "NetworkSecurityGroup-${var.customcluster_name}-{{.SecurityGroupName}}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  depends_on = [azurerm_resource_group.rg]
}