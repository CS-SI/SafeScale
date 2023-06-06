# Define providers and set versions
terraform {
  backend "consul" {
    address = "{{.ConsulURL}}"
    scheme  = "http"
    path    = "azure"
  }
}
