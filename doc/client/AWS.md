```
[[tenants]]
    name = "TenantName"
    client = "aws"

    # This part defines how to authenticate with the provider
    [tenants.identity]
        IdentityEndpoint = "<IdentityEndpoint>"
        Username = "<Username>"
        Password = "<Password>"
        TenantName = "<TenantName>"
        
        Region = "<IdentityEndpoint>"
```
