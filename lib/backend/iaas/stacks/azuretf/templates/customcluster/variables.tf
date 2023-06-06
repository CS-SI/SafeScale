variable "module_directory" {
  description = "The directory where the module is located"
  type        = string
  default     = "customcluster"
}

variable "customcluster_name" {
  description = "Name of the cluster"
  type        = string
}

variable "customcluster_identity" {
  description = "The identity"
  type        = string
  default     = ""
}

variable "region" {
  description = "The region"
  type        = string
  default     = "francecentral"
}

variable "debug" {
  description = "debug mode"
  type        = bool
  default     = true
}

variable "flavor" {
  description = "flavor"
  type = number
  default = 4 // clusterflavor.BOH
}

variable "complexity" {
  description = "complexity"
  type = number
  default = 1 // clustercomplexity.Small
}

variable "creation_date" {
  description = "cluster creation date"
  type        = string
}

variable "gw-disk-size" {
  description = "gateway boot disk size in Gb"
  type = number
  default = 60
}

variable "master-disk-size" {
  description = "master boot disk size in Gb"
  type = number
  default = 60
}

variable "netcidr" {
  description = "cidr"
  type = string
  default = "10.0.0.0/16"
}

variable "subnetcidr" {
  description = "subnet cidr"
  type = string
  default = "10.0.1.0/24"
}

variable "last_byte" {
  description = "the last byte of the internal ip"
  type = number
  default = 4
}

variable "default_instance_type" {
  description = "ec2 instance type"
  type        = string
  default     = "Standard_DS1_v2"
}

variable "gw_instance_type" {
  description = "gateway instance type"
  type        = string
  default     = "Standard_F2s"
}

variable "master_instance_type" {
  description = "master instance type"
  type        = string
  default     = "Standard_B4ms"
}

variable "gateways_count" {
  description = "gateways count"
  type        = number
  default     = 1
}

variable "default_gateways_password" {
  description = "default gws password"
  type = string
  default = "SSafe_scale01"
}

variable "default_masters_password" {
  description = "default masters password"
  type = string
  default = "SSafe_scale13"
}

variable "default_instance_password" {
  description = "default instance password"
  type = string
  default = "SSafe_scale14"
}

variable "masters_count" {
  description = "masters count"
  type        = number
  default     = 3
}

variable "linux_user" {
  description = "default username"
  type        = string
  default     = "safescale"
}

variable "linux_customcluster_user" {
  description = "default username"
  type        = string
  default     = "cladm"
}

variable "resource_group_location" {
  default     = "francecentral"
  description = "Location of the resource group."
}

variable "resource_group_name_prefix" {
  default     = "rg"
  description = "Prefix of the resource group name that's combined with a random ID so name is unique in your Azure subscription."
}

variable "tags_gw" {
  type = map(string)
  default = {
    type = "gateway"
    managedBy = "safescale"
  }
}

variable "master_tags" {
  type = map(string)
  default = {
    type = "master"
    managedBy = "safescale"
    renderer = "terraform"
  }
}

variable "rg_tags" {
  type    = map(string)
  default = {
    managedBy = "safescale"
    renderer   = "terraform"
  }
}

variable "os_ubuntu_20" {
  type = map(string)
  default = {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-minimal-focal"
    sku       = "minimal-20_04-lts"
    version   = "latest"
  }
}

data "azurerm_platform_image" "os_ubuntu_20" {
  location  = var.resource_group_location
  publisher = "Canonical"
  offer     = "0001-com-ubuntu-minimal-focal"
  sku       = "minimal-20_04-lts"
}

variable "os_ubuntu_18" {
  type = map(string)
  default = {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

data "azurerm_platform_image" "os_ubuntu_18" {
  location  = var.resource_group_location
  publisher = "Canonical"
  offer     = "UbuntuServer"
  sku       = "18.04-LTS"
}

variable "os_ubuntu_22" {
  type = map(string)
  default = {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

data "azurerm_platform_image" "os_ubuntu_22" {
  location  = var.resource_group_location
  publisher = "Canonical"
  offer     = "0001-com-ubuntu-server-jammy"
  sku       = "22_04-lts-gen2"
}

variable "os_centos_8" {
  type = map(string)
  default = {
    publisher = "OpenLogic"
    offer     = "CentOS"
    sku       = "8_5-gen2"
    version   = "latest"
  }
}

data "azurerm_platform_image" "os_centos_8" {
  location  = var.resource_group_location
  publisher = "OpenLogic"
  offer     = "CentOS"
  sku       = "8_5-gen2"
}

variable "os_gw" {
  type = map(string)
  default = {}
}

variable "os_master" {
  type = map(string)
  default = {}
}

variable "installed_features" {
  type = map(string)
  default = {}
}

variable "disabled_features" {
  type = map(string)
  default = {}
}
