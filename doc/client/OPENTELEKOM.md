```
[[tenants]]
    name = "TenantName"
    client = "opentelekom"

    # This part defines how to authenticate with the provider
    [tenants.identity]
        IdentityEndpoint = "<IdentityEndpoint>"
        Username = "<Username>"
        Password = "<Password>"
        DomainName = "<DomainName>"
        TenantName = "<TenantName>"
        AllowReauth = "<AllowReauth>"
```
