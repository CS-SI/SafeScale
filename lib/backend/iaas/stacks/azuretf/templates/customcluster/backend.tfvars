# Define providers and set versions
terraform {
  backend "consul" {
    address = {{ .ConsulAddress }}
    scheme  = "http"
    path    = {{ .ConsulPath }}
  }
}
