resource "azurerm_virtual_machine_data_disk_attachment" "attachment-{{.MachineName}}-{{.DiskName}}" {
  managed_disk_id    = azurerm_managed_disk.disk_{{.DiskName}}.id
  virtual_machine_id = "{{.MachineId}}"
  lun                = "10"
  caching            = "ReadWrite"
}