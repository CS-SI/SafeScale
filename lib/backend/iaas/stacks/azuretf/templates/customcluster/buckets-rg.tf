resource "azurerm_resource_group" "rgbuckets" {
  location = "{{.Region}}"
  name     = "resourcegroup-buckets"

  timeouts {
    create = "1m"
    delete = "2m"
  }
}

resource "azurerm_storage_account" "storage_{{.StorageAccount}}" {
  name                     = "{{.StorageAccount}}"
  resource_group_name      = azurerm_resource_group.rgbuckets.name
  location                 = azurerm_resource_group.rgbuckets.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  depends_on = [azurerm_resource_group.rgbuckets]
}