# File tenants.toml: Syntax

## Introduction

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

```json
{
  "tenants": [
    {
      "name": "TenantName",
      "client": "ovh",
      "compute": {
        "DefaultImage": "<OS Image Name to use as default, ex: Ubuntu 18.04>",
        "ProjectID": "<Project ID>",
        "Region": "<Region>"
      },
      "identity": {
        "DomainName": "<Domain Name>",
        "Password": "<Password>",
        "Username": "<Username>",
      },
      "metadata": {
        "ApplicationKey": "<Openstack Application Key>",
        "AuthURL": "https://auth.cloud.ovh.net/v2.0",
        "CryptKey": "<metadata crypt password>",
        "OpenstackID": "<Openstack ID>",
        "OpenstackPassword": "<Openstack password>",
        "Type": "swift"
      },

      "network": {
        "ProviderNetwork": "<Provider network for public access, ex:Ext-Net>",
        "VPCCIDR": "<VPC CIDR, ex: 192.168.0.0/16>",
        "VPCName": "<VPC Name>"
      },
      "objectstorage": {
        "AccessKey": "<Access Key>",
        "Endpoint": "https://oss.eu-west-0.prod-cloud-ocb.orange-business.com",
        "SecretKey": "<Secret Key>",
        "Type": "s3"
      }
    }
  ]
}
```

Here is the YAML equivalent of the example TOML configuration file :

```yaml
tenants:
- client: ovh
  compute:
    DefaultImage: '<OS Image Name to use as default, ex: Ubuntu 18.04>'
    ProjectID: <Project ID>
    Region: <Region>
  identity:
    DomainName: <Domain Name>
    Password: <Password>
    Username: <Username>
  metadata:
    ApplicationKey: <Openstack Application Key>
    AuthURL: https://auth.cloud.ovh.net/v2.0
    CryptKey: <metadata crypt password>
    OpenstackID: <Openstack ID>
    OpenstackPassword: <Openstack password>
    Type: swift
  name: TenantName
  network:
    ProviderNetwork: <Provider network for public access, ex:Ext-Net>
    VPCCIDR: '<VPC CIDR, ex: 192.168.0.0/16>'
    VPCName: <VPC Name>
  objectstorage:
    AccessKey: <Access Key>
    Endpoint: https://oss.eu-west-0.prod-cloud-ocb.orange-business.com
    SecretKey: <Secret Key>
    Type: s3
```
When SafeScale commands are invoked, they search for a tenant configuration file in these folders, in that order :

- ./ (current dir)
- $HOME/.safescale/
- $HOME/.config/.safescale/
- /etc/safescale/

Thanks to [viper](https://github.com/spf13/viper), the file can be named ``tenants.toml`` (encoded in TOML), ``tenants.json`` (encoded in JSON) or ``tenants.yaml`` (encoded in YAML), allowing you to use the format you are the most comfortable with.

__Note__: If you are not familiar with all the supported encoding formats, you can use the tool [remarshal](https://github.com/dbohdan/remarshal) which
allows to convert between them. You should be able to invest yourself in learning the TOML format and would be able nevertheless to generate in other formats if necessary.

## Structure of TOML file


A TOML configuration file must contains at least one `[[tenants]]` entry. There can be multiple entries.<br>
Each entry defines a tenant, using the field `name` to identify it, and the field `client` to define the driver.

Inside a `[[tenants]]` item, you can have these sections :

- `[tenant.identity]`
- `[tenant.compute]`
- `[tenant.network]`
- `[tenant.objectstorage]`
- `[tenant.metadata]`

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

### Section `[tenant.identity]`

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `AccessKey` | MANDATORY, CLIENT |
> | `ApplicationKey` | MANDATORY, CLIENT |
> | `OpenstackID` | MANDATORY, CLIENT |
> | `OpenstackPassword` | MANDATORY, CLIENT |
> | `Password` | MANDATORY, CLIENT |
> | `SecretKey` | MANDATORY, CLIENT |
> | `Username` | MANDATORY, CLIENT |
> | `AlternateApiApplicationKey` | OPTIONAL, CLIENT |
> | `AlternateApiApplicationSecret` | OPTIONAL, CLIENT |
> | `AlternateApiConsumerKey` | OPTIONAL, CLIENT |

### Section ``[tenant.compute]``

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `DefaultImage` | OPTIONAL |
> | `Domain` | OPTIONAL, CLIENT |
> | `DomainName` | OPTIONAL, CLIENT |
> | `ProjectName` | OPTIONAL, CLIENT |
> | `ProjectID` | OPTIONAL, CLIENT |
> | `Scannable` | OPTIONAL |
> | `OperatorUsername` | OPTIONAL |

### Section ``[tenant.network]``

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `ProviderNetwork` | OPTIONAL, CLIENT |
> | `VPCCIDR` | OPTIONAL, CLIENT |
> | `VPCName` | OPTIONAL, CLIENT |

### Section ``[tenant.objectstorage]``

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `AccessKey` | MANDATORY, INHERIT |
> | `AuthURL` | OPTIONAL, CLIENT |
> | `Domain` | OPTIONAL, CLIENT |
> | `DomainName` | OPTIONAL, CLIENT |
> | `Endpoint` | OPTIONAL, CLIENT |
> | `OpenstackPassword` | MANDATORY, INHERIT |
> | `ProjectID` | OPTIONAL, CLIENT |
> | `ProjectName` | OPTIONAL, CLIENT |
> | `Password` | MANDATORY, INHERIT |
> | `Region` | OPTIONAL |
> | `SecretKey` | MANDATORY, INHERIT |
> | `Tenant` | OPTIONAL, CLIENT |
> | `Type` | MANDATORY |
> | `Username` | MANDATORY, INHERIT |

### Section [tenant.metadata]

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `AccessKey` | MANDATORY, INHERIT |
> | `AuthURL` | OPTIONAL, CLIENT, INHERIT |
> | `DomainName` | OPTIONAL, CLIENT, INHERIT |
> | `Endpoint` | OPTIONAL, CLIENT, INHERIT |
> | `Domain` | OPTIONAL, CLIENT, INHERIT |
> | `OpenstackPassword` | MANDATORY, INHERIT |
> | `ProjectID` | OPTIONAL, CLIENT, INHERIT |
> | `ProjectName` | OPTIONAL, CLIENT, INHERIT |
> | `Password` | MANDATORY, INHERIT |
> | `Region` | OPTIONAL |
> | `SecretKey` | MANDATORY, INHERIT |
> | `Tenant` | OPTIONAL, CLIENT, INHERIT |
> | `Type`| MANDATORY, INHERIT |
> | `Username` | MANDATORY, INHERIT |

<br>

## Keywords in details

### <a name="kw_name"></a> `name`

This field contains a string giving a name to the tenant.

### <a name="kw_client"></a> `client`

It defines the "driver" to communicate with the provider. Valid values are:

> | Providers |
> | --- |
> | `"cloudwatt"` |
> | `"cloudferro"` |
> | `"flexibleengine"` |
> | `"opentelekom"` |
> | `"ovh"` |

### <a name="kw_AccessKey"></a> `AccessKey`: alias, see [`Username`](#kw_Username)

### <a name="kw_AlternateApiApplicationKey"></a> `AlternateApiApplicationKey`

Only available on OVH.<br>
Contains OVH api application key (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### <a name="kw_AlternateApiApplicationSecret"></a> `AlternateApiApplicationSecret`

Only available on OVH.<br>
Contains OVH api application secret (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### <a name="kw_AlternateApiConsumerKey"></a> `AlternateApiConsumerKey`

Only available on OVH.<br>
Contains OVH api consumer key, who have to be previously validated (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### `ApplicationKey`

### <a name="kw_AuthURL"></a> `AuthURL`

Contains the URL used to authenticate.<br>
May be used in sections `tenants.objectstorage` and `tenants.metadata`, especially when `Type` == `"swift"`.

### <a name="kw_Domain"></a> `Domain`

Contains the Domain name wanted by the provider.<br>
May be used in every section.

### <a name="kw_DomainName"></a> `DomainName`: alias, see [`Domain`](#kw_Domain)

### <a name="kw_Endpoint"></a> `Endpoint`

Contains the URL of the Object Storage backend to use.<br>
May be used in sections `tenants.objectstorage` and `tenants.metadata`, especially when `Type` == `"s3"`.

### <a name="kw_OpenStackID"></a> `OpenstackID`: alias, see [`Username`](#kw_Username)

### <a name="kw_OperatorUsername"></a> `OperatorUsername`

Contains the username that will be used to create the default user (safescale if unset).

### <a name="kw_OpenstackPassword"></a> `OpenstackPassword`: alias, see [`Password`](#kw_Password)

### <a name="kw_Password"></a> `Password`

Contains the password for the authentication necessary to connect to the provider.<br>
May be used in sections `tenants.identity`, `tenants.objectstorage` and `tenants.metadata`.

### <a name="kw_ProjectID"></a> `ProjectID`

### <a name="kw_ProjectName"></a> `ProjectName`

### <a nale="kw_ProviderNetwork"></a> `ProviderNetwork`

Contains the name of the provider network connected host resources to public network.<br>
Is meaningful for some providers:

> | |
> | --- |
> | `ovh` |
> | --- |
>
### <a name="kw_Region"></a> `Region`

Contains the region to connect to. Values depend on provider.<br>
May be used in `tenants.compute`, `tenants.objectstorage` and `tenants.metadata`.

### <a name="kw_Scannable"></a> `Scannable`

If set to true, allow the scanner to scan the tennant ([cf. SCANNER](SCANNER.md))

### <a name="k<_SecretKey"></a> `SecretKey`: alias, see [`Password`](#kw_Password)

### <a name="kw_Username"></a>`Username`

Contains the username for the authentication necessary to connect to the provider.

It (or one of its aliases) must be present in section `tenants.identity`, and may be present in sections `tenants.objectstorage` and `tenants.metadata`.

### <a name="kw_Tenant"></a> `Tenant`

### <a name="kw_Type"></a> `Type`

Allows to specify the type of Object Storage protocol.<br>
Valid values are:

> | | |
> | --- | --- |
> | `"s3"` | S3 protocol as proposed by AWS or tools like minio |
> | `"swift"` | SwiftKS protocol proposed by OpenStack Cloud implementations |
> | `"azure"` | Azure protocol (not tested) |
> | `"gce"` | Google GCE protocol (not tested) |

### <a name="kw_VPCCIDR"></a> `VPCCIDR`

Contains the name of the VPC where networks will be created. If the VPC doesn't exist, will be created.<br>
Is meaningful for some drivers only:

> | |
> | --- |
> | `flexibleengine` |
> | `opentelekom` |

### <a name="kw_VPCName"></a> `VPCName`

Contains the CIDR of the VPC where networks will be created.<br>
Is meaningful for some drivers only:

> | |
> | --- |
> | `flexibleengine` |
> | `opentelekom` |
