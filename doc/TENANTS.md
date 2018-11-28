# File tenants.toml: Syntax

##(introduction)

The tenant file contains the list of credentials and configuration used to access providers.

Here is an example of a TOML encoded configuration file :

```toml
[[tenants]]
    name = "TenantName"
    client = "ovh"

    # This part defines how to authenticate with the provider
    [tenants.identity]
        Username = "<Username>"
        Password = "<Password>"
        DomainName = "<Domain Name>"

    # This part defines configuration specifically applied to compute resources (AWS EC2, OpenStack Nova, ...)
    [tenants.compute]
        ProjectID = "<Project ID>"
        Region = "<Region>"
        DefaultImage = "<OS Image Name to use as default, ex: Ubuntu 18.04>"

    # This part defines configuration specifically applied to network resources (optional)
    [tenants.network]
        VPCName = "<VPC Name>"
        VPCCIDR = "<VPC CIDR, ex: 192.168.0.0/16>"
        ProviderNetwork = "<Provider network for public access, ex:Ext-Net>"

    # This part defines object storage protocol and associated authentication parameters
    [tenants.objectstorage]
        Type = "s3"
        Endpoint = "https://oss.eu-west-0.prod-cloud-ocb.orange-business.com"
        AccessKey = "<Access Key>"
        SecretKey = "<Secret Key>"

    # This part defines object storage protocol and associated authentication parameters (optional)
    # if not provided, metadata are stored using tenants.objectstorage section
    # if provided, missing fields are reused from tenants.objectstorage section
    [tenants.metadata]
        Type = "swift"
        AuthURL = "https://auth.cloud.ovh.net/v2.0"
        ApplicationKey = "<Openstack Application Key>"
        OpenstackID = "<Openstack ID>"
        OpenstackPassword = "<Openstack password>"
        CryptKey = "<metadata crypt password>"
```

The same configuration can be provided in JSON or in YAML.

Here is the JSON equivalent of the example TOML configuration file :

Here is the YAML equivalent of the example TOML configuration file :


When SafeScale commands are invoked, they search for a tenant configuration file in these folders, in that order :

- ./ (current dir)
- $HOME/.safescale/
- $HOME/.config/.safescale/
- /etc/safescale/

Thanks to [viper](https://github.com/spf13/viper), the file can be named ``tenants.toml`` (encoded in TOML), ``tenants.json`` (encoded in JSON) or ``tenants.yaml`` (encoded in YAML), allowing you to use the format you are the most comfortable with.

__Note__: If you are not familiar with all the supported encoding formats, you can use the tool [remarshal](https://github.com/dbohdan/remarshal) which
allows to convert between them. You should be able to invest yourself in learning the TOML format and would be able nevertheless to generate in other formats if necessary.

___
## Structure of TOML file


A TOML configuration file must contains at least one ``[[tenants]]`` entry. There can be multiple entries.<br>
Each entry defines a tenant, using the field ``name`` to identify it, and the field ``client`` to define the driver.

Inside a ``[[tenants]]`` item, you can have these sections :

- ``[tenant.identity]``
- ``[tenant.compute]``
- ``[tenant.network]``
- ``[tenant.objectstorage]``
- ``[tenant.metadata]``

In the description of sections hereafter, each keyword is annotated with these tags:

- MANDATORY: this means the keyword must be present and must be in the section
- INHERIT: this means the keyword can inherit from another section
- OPTIONAL: this means the keyword is optional
- CLIENT: this means the keyword presence depends on driver used

Combinaisons are possible :

- MANDATORY, CLIENT means the keyword is mandatory for specific driver(s)
- MANDATORY, INHERIT means the keyword is mandatory but can inherit from same keyword from other section
- MANDATORY, CLIENT, INHERIT means the keyword is mandatory, valid only for specific driver(s) but can inherit from same keyword from other section
- OPTIONAL, CLIENT means the keyword is optional and restricted to specific driver(s)
- OPTIONAL, CLIENT, INHERIT means the keyword is optional, valid only for some specific driver(s) and can inherit from same keyword from other section

### Section ``[tenant.identity]``

The valid keywords in this section are :

| keyword     | presence    |
| --- | --- |
| ``AccessKey`` | MANDATORY, CLIENT |
| ``ApplicationKey`` | MANDATORY, CLIENT |
| ``OpenstackID`` | MANDATORY, CLIENT |
| ``OpenstackPassword`` | MANDATORY, CLIENT |
| ``Password`` | MANDATORY, CLIENT |
| ``SecretKey`` | MANDATORY, CLIENT |
| ``Username`` | MANDATORY, CLIENT |

### Section ``[tenant.compute]``

The valid keywords in this section are :

| keyword     | presence    |
| --- | --- |
| ``DefaultImage`` | OPTIONAL |
| ``Domain`` | OPTIONAL, CLIENT |
| ``DomainName`` | OPTIONAL, CLIENT |
| ``ProjectName`` | OPTIONAL, CLIENT |
| ``ProjectID`` | OPTIONAL, CLIENT |

### Section ``[tenant.network]``

The valid keywords in this section are :

| keyword     | presence    |
| --- | --- |
| ``ProviderNetwork`` | OPTIONAL, CLIENT |
| ``VPCCIDR`` | OPTIONAL, CLIENT |
| ``VPCName`` | OPTIONAL, CLIENT |

### Section ``[tenant.objectstorage]``

The valid keywords in this section are :

| keyword     | presence    |
| --- | --- |
| ``AccessKey`` | MANDATORY, INHERIT |
| ``AuthURL`` | OPTIONAL, CLIENT |
| ``Domain`` | OPTIONAL, CLIENT |
| ``DomainName`` | OPTIONAL, CLIENT |
| ``Endpoint`` | OPTIONAL, CLIENT |
| ``OpenstackPassword`` | MANDATORY, INHERIT |
| ``ProjectID`` | OPTIONAL, CLIENT |
| ``ProjectName`` | OPTIONAL, CLIENT |
| ``Password`` | MANDATORY, INHERIT |
| ``Region`` | OPTIONAL |
| ``SecretKey`` | MANDATORY, INHERIT |
| ``Tenant`` | OPTIONAL, CLIENT |
| ``Type`` | MANDATORY |
| ``Username`` | MANDATORY, INHERIT |

### Section [tenant.metadata]

The valid keywords in this section are :

| keyword     | presence    |
| --- | --- |
| ``AccessKey`` | MANDATORY, INHERIT |
| ``AuthURL`` | OPTIONAL, CLIENT, INHERIT |
| ``Domain`` | OPTIONAL, CLIENT, INHERIT |
| ``DomainName`` | OPTIONAL, CLIENT, INHERIT |
| ``Endpoint`` | OPTIONAL, CLIENT, INHERIT |
| ``OpenstackPassword`` | MANDATORY, INHERIT |
| ``ProjectID`` | OPTIONAL, CLIENT, INHERIT |
| ``ProjectName`` | OPTIONAL, CLIENT, INHERIT |
| ``Password`` | MANDATORY, INHERIT |
| ``Region`` | OPTIONAL |
| ``SecretKey`` | MANDATORY, INHERIT |
| ``Tenant`` | OPTIONAL, CLIENT, INHERIT |
| ``Type``| MANDATORY, INHERIT |
| ``Username`` | MANDATORY, INHERIT |

## Fields in details

### name

This field contains a string giving a name to the tenant

### client

It defines the driver to communicate with the provider. It can contain:

- ``cloudwatt``
- ``cloudferro``
- ``flexibleengine``
- ``opentelekom``
- ``ovh``

###