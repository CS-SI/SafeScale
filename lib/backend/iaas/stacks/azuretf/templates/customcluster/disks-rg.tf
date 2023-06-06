resource "azurerm_resource_group" "rgdrives" {
  location = "{{.Region}}"
  name     = "resourcegroup-drives"

  timeouts {
    create = "1m"
    delete = "2m"
  }
}
