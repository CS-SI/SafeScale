ui_config {
  enabled = true
}
log_level = "INFO"
addresses {
  http = "0.0.0.0"
}
ports {
  dns = -1
  grpc = -1
}
data_dir = "var/data"
pid_file = "var/consul.pid"
connect {
  enabled = false
}
disable_update_check = true