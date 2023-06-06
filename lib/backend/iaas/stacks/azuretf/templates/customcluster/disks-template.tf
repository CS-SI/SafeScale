resource "azurerm_managed_disk" "disk_{{.Name}}" {
  name                 = "{{.Name}}"
  location             = azurerm_resource_group.rgdrives.location
  resource_group_name  = azurerm_resource_group.rgdrives.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "{{.Size}}"

  tags = {
    CreationDate = "{{.TimeStamp}}"
  }

  depends_on = [azurerm_resource_group.rgdrives]
}