[[tenants]]
    name = "myCloudFerro"
    client = "cloudferro"

    [tenants.identity]
        ProjectID = "abcdefgh........................"
        Username = "user@somewhere"
        Password = "ABCDEF.............."
        DomainName = "dom_12345"

    [tenants.compute]
        Region = "RegionOne"
        AvailabilityZone = "nova"
        ProjectName = "my project name"

    [tenants.network]
        ProviderNetwork = "external2"

    [tenants.objectstorage]
        Type = "swift"
        AuthURL = "https://cf2.cloudferro.com:5000/v3"
