listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/vault/data"
}

disable_mlock = true
api_addr = "http://127.0.0.1:8200"
