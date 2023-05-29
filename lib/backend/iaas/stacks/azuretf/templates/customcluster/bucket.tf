resource "azurerm_storage_container" "bucket_{{.Name}}" {
  name                  = "{{.Name}}"
  storage_account_name  = azurerm_storage_account.storage_{{.StorageAccount}}.name
  container_access_type = "private"

  depends_on = [azurerm_resource_group.rgbuckets]
}
