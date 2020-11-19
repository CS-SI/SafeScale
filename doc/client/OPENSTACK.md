```
[[tenants]]
    name = "TenantName"
    client = "openstack"

    # This part defines how to authenticate with the provider
    [tenants.identity]
        IdentityEndpoint = "<IdentityEndpoint>"
        Username = "<Username>"
        Password = "<Password>"
        DomainID = "<DomainID>"
        DomainName = "<DomainName>"
        TenantName = "<TenantName>"
        TokenID = "<TokenID>"
```
