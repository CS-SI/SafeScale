Sample AWS tentants.toml configuration:

```toml

[[tenants]]
    client = "aws"
    name = "our-amazon-cloud"

    [tenants.identity]
        User = "...................."
        SecretKey = "........................................"
        
    [tenants.compute]
        Region = "eu-central-1"
        Zone = "eu-central-1a"

    [tenants.objectstorage]
        Type        = "s3"
        User = "...................."
        SecretKey = "........................................"
        Region      = "eu-central-1"

    [tenants.network]
        ProviderNetwork = "our-network-name"
```