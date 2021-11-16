# File tenants.toml: Syntax

## Introduction

The tenant file contains the list of credentials and configuration used to access providers.

Here is an example of a TOML encoded configuration file:

```toml
[[tenants]]
    name = "TenantName"
    client = "ovh"

    # This part defines how to authenticate with the provider
    [tenants.identity]
        ApplicationKey = "<Openstack Application Key>"
        OpenstackID = "<Openstack ID>"
        OpenstackPassword = "<Openstack password>"

    # This part defines configuration specifically applied to compute resources (AWS EC2, OpenStack Nova, ...)
    [tenants.compute]
        ProjectName = "<Project Name>"
        Region = "<Region>"
        AvailabilityZone = "<Availability Zone>"
        DefaultImage = "<OS Image Name to use as default, ex: Ubuntu 20.04>"

    # This part defines configuration specifically applied to network resources (optional)
    [tenants.network]
        ProviderNetwork = "<Provider network for public access, ex:Ext-Net>"

    # This part defines object storage protocol and associated authentication parameters
    [tenants.objectstorage]
        Type = "swift"
        AuthURL = "https://auth.cloud.ovh.net/v3"

    # This part defines object storage protocol and associated authentication parameters (optional)
    # if not provided, metadata are stored using tenants.objectstorage section
    # if provided, missing fields are reused from tenants.objectstorage section
    [tenants.metadata]
        Type = "swift"
        AuthURL = "https://auth.cloud.ovh.net/v3"
```

The same configuration can be provided in JSON or in YAML.

Here is the JSON equivalent of the TOML configuration file example:

```json
{
  "tenants": [
    {
      "name": "TenantName",
      "client": "ovh",
      "compute": {
        "DefaultImage": "<OS Image Name to use as default, ex: Ubuntu 20.04>",
        "ProjectName": "<Project Name>",
        "Region": "<Region>",
        "AvailabilityZone": "<Availability Zone>"
      },
      "identity": {
        "ApplicationKey": "<Openstack Application Key>",
        "OpenstackID": "<Openstack ID>",
        "OpenstackPassword": "<Openstack Password>"
      },
      "metadata": {
        "ApplicationKey": "<Openstack Application Key>",
        "AuthURL": "https://auth.cloud.ovh.net/v3",
        "OpenstackID": "<Openstack ID>",
        "OpenstackPassword": "<Openstack Password>",
        "Type": "swift"
      },
      "network": {
        "ProviderNetwork": "<Provider network for public access, ex:Ext-Net>",
      },
      "objectstorage": {
        "ApplicationKey": "<Openstack Application Key>",
        "AuthURL": "https://auth.cloud.ovh.net/v3",
        "OpenstackID": "<Openstack ID>",
        "OpenstackPassword": "<Openstack password>",
        "Type": "swift"
      }
    }
  ]
}
```

Here is the YAML equivalent of the TOML configuration file example:

```yaml
tenants:
- client: ovh
  compute:
    DefaultImage: '<OS Image Name to use as default, ex: Ubuntu 20.04>'
    ProjectName: <Project Name>
    Region: <Region>
    AvailabilityZone: <Availability Zone>
  identity:
    ApplicationKey: <Openstack Application Key>
    OpenstackID: <Openstack ID>
    OpenstackPassword: <Openstack Password>
  metadata:
    ApplicationKey: <Openstack Application Key>
    AuthURL: https://auth.cloud.ovh.net/v3
    OpenstackID: <Openstack ID>
    OpenstackPassword: <Openstack password>
    Type: swift
  name: TenantName
  network:
    ProviderNetwork: <Provider network for public access, ex:Ext-Net>
  objectstorage:
    ApplicationKey: <Openstack Application Key>
    AuthURL: https://auth.cloud.ovh.net/v3
    OpenstackID: <Openstack ID>
    OpenstackPassword: <Openstack password>
    Type: swift
```
When SafeScale commands are invoked, they search for a tenant configuration file in these folders, in that order :

- ./ (current dir)
- $HOME/.safescale/
- $HOME/.config/safescale/
- /etc/safescale/

Thanks to [viper](https://github.com/spf13/viper), the file can be named ``tenants.toml`` (encoded in TOML), ``tenants.json`` (encoded in JSON) or ``tenants.yaml`` (encoded in YAML), allowing you to use the format you are the most comfortable with.

__Note__: If you are not familiar with all the supported encoding formats, you can use the tool [remarshal](https://github.com/dbohdan/remarshal) which allows to convert between them. You should be able to invest yourself in learning the TOML format (or not) and would be able nevertheless to generate in other formats if necessary.

## Structure of TOML file

A TOML configuration file must contains at least one `[[tenants]]` entry. There can be multiple entries.<br>
Each entry defines a tenant, using the field `name` to identify it, and the field `client` to define the driver.

Inside a `[[tenants]]` item, you can have these sections :

- `[tenants.identity]`
- `[tenants.compute]`
- `[tenants.network]`
- `[tenants.objectstorage]`
- `[tenants.metadata]`

In the description of sections hereafter, each keyword is annotated with these tags:

- `MANDATORY`: this means the keyword must be present and must be in the section
- `INHERIT`: this means the keyword can inherit from another section
- `OPTIONAL`: this means the keyword is optional
- `CLIENT`: this means the keyword presence depends on driver used

Combinations are possible :

- MANDATORY, CLIENT means the keyword is mandatory for specific driver(s)
- MANDATORY, INHERIT means the keyword is mandatory but can inherit from same keyword from other section
- MANDATORY, CLIENT, INHERIT means the keyword is mandatory, valid only for specific driver(s) but can inherit from same keyword from other section
- OPTIONAL, CLIENT means the keyword is optional and restricted to specific driver(s)
- OPTIONAL, CLIENT, INHERIT means the keyword is optional, valid only for some specific driver(s) and can inherit from same keyword from other section

### Section `[tenants.identity]`

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

### Section ``[tenants.compute]``

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `DefaultImage` | OPTIONAL |
> | `Domain` | OPTIONAL, CLIENT |
> | `DomainName` | OPTIONAL, CLIENT |
> | `ProjectName` | OPTIONAL, CLIENT |
> | `ProjectID` | OPTIONAL, CLIENT |
> | `Region` | MANDATORY |
> | `AvailabilityZone` | MANDATORY |
> | `Scannable` | OPTIONAL |
> | `OperatorUsername` | OPTIONAL |

### Section ``[tenants.network]``

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | `ProviderNetwork` | OPTIONAL, CLIENT |
> | `VPCCIDR` | OPTIONAL, CLIENT |
> | `VPCName` | OPTIONAL, CLIENT |

### Section ``[tenants.objectstorage]``

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
> | `Region` | OPTIONAL, INHERIT |
> | `AvailabilityZone` | OPTIONAL, INHERIT |
> | `SecretKey` | MANDATORY, INHERIT |
> | `Tenant` | OPTIONAL, CLIENT |
> | `Type` | MANDATORY |
> | `Username` | MANDATORY, INHERIT |

### Section [tenants.metadata]

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
> | `Region` | OPTIONAL, INHERIT |
> | `AvailabilityZone` | OPTIONAL, INHERIT |
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
> | `"aws"` |
> | `"cloudferro"` |
> | `"ebrc"` |
> | `"flexibleengine"` |
> | `"gcp"` |
> | `"local"` |
> | `"openstack"` |
> | `"opentelekom"` |
> | `"outscale"` |
> | `"ovh"` |

### AccessKey: alias, see [`Username`](#Username)

### `AlternateApiApplicationKey`

Only available on `OVH`.<br>
Contains OVH API application key (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### `AlternateApiApplicationSecret`

Only available on `OVH`.<br>
Contains OVH api application secret (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### `AlternateApiConsumerKey`

Only available on `OVH`.<br>
Contains OVH api consumer key, who have to be previously validated (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### `ApplicationKey`

### `AuthURL`

Contains the URL used to authenticate.<br>
May be used in sections `tenants.objectstorage` and `tenants.metadata`, especially when `Type` == `"swift"`.

### `AvailabilityZone`

Contains the zone to connect to. Values depend on provider.<br>
Is mandatory in `tenants.compute`
May be used in `tenants.objectstorage` and `tenants.metadata`.
If the AvailabilityZone is empty in `tenants.metadata`, safescale searches for valid values in `tenants.objectstorage`, then in `tenants.compute` (where is mandatory)

### `Domain`

Contains the Domain name wanted by the provider.<br>
May be used in every section.

### `DomainName`: alias, see [`Domain`](#Domain)

### `Endpoint`

Contains the URL of the Object Storage backend to use.<br>
May be used in sections `tenants.objectstorage` and `tenants.metadata`, especially when `Type` == `"s3"`.

### `OpenstackID`: alias, see [`Username`](#Username)

### `OperatorUsername`

Contains the username that will be used to create the default user (safescale if unset).

### `OpenstackPassword`: alias, see [`Password`](#Password)

### `Password`

Contains the password for the authentication necessary to connect to the provider.<br>
May be used in sections `tenants.identity`, `tenants.objectstorage` and `tenants.metadata`.

### `ProjectID`

### `ProjectName`

### `ProviderNetwork`

Contains the name of the provider network connected host resources to public network.<br>
Is meaningful for some providers:

> | |
> | --- |
> | `ovh` |
>
### `Region`

Contains the region to connect to. Values depend on provider.<br>
Is mandatory in `tenants.compute`
May be used in `tenants.objectstorage` and `tenants.metadata`.
If the Region is empty in `tenants.metadata`, safescale searches for valid values in `tenants.objectstorage`, then in `tenants.compute` (where is mandatory)

### `Scannable`

If set to true, allow the scanner to scan the tenant ([cf. SCANNER](SCANNER.md))

### `SecretKey`: alias, see [Password](#Password)

### `Username`

Contains the username for the authentication necessary to connect to the provider.

It (or one of its aliases) must be present in section `tenants.identity`, and may be present in sections `tenants.objectstorage` and `tenants.metadata`.

### `Tenant`

### `Type`

Allows to specify the type of Object Storage protocol.<br>
Valid values are:

> | | |
> | --- | --- |
> | `"s3"` | S3 protocol as proposed by AWS or tools like minio |
> | `"swift"` | SwiftKS protocol proposed by OpenStack Cloud implementations |
> | `"azure"` | Azure protocol (not tested) |
> | `"gce"` | Google GCE protocol |

### `VPCCIDR`

Contains the name of the VPC where networks will be created. If the VPC doesn't exist, will be created.<br>
Is meaningful for some drivers only:

> | |
> | --- |
> | `flexibleengine` |
> | `opentelekom` |

### `VPCName`

Contains the CIDR of the VPC where networks will be created.<br>
Is meaningful for some drivers only:

> | |
> | --- |
> | `flexibleengine` |
> | `opentelekom` |


### GCP-specific

Get project number from project settings:
https://console.cloud.google.com/iam-admin/settings/project?project=<your-project-here>

Get service account keys in json format from:
https://console.developers.google.com/apis/credentials?project=<your-project-here>

The file retrieved from there has the following format:

```json
{
  "type": "service_account",
  "project_id": "*****************",
  "private_key_id": "*****************",
  "private_key": "-----BEGIN PRIVATE KEY-----\n*****************\n-----END PRIVATE KEY-----\n",
  "client_email": "*****************",
  "client_id": "*****************",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "*****************"
}
```

For now (this will change in the future to be more consistent with the other drivers), the `tenants.toml` file contains the same fields as the service account json file AND the project number from the project settings page:

```yaml
[[tenants]]
    client = "gcp"
    name = "my-google-account-project-x"

    [tenants.identity]
        User = "******@****"
        Password = "**********"
        ProjectNumber = "*****************"
        project_id = "************"
        private_key_id = "******************"
        private_key = "-----BEGIN PRIVATE KEY-----\n**********************************\n-----END PRIVATE KEY-----\n"
        client_email = "*****************************"
        client_id = "******************"
        auth_uri = "https://accounts.google.com/o/oauth2/auth"
        token_uri = "https://oauth2.googleapis.com/token"
        auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
        client_x509_cert_url = "*********************************************************"

    [tenants.compute]
        Region = "europe-west1"
        Zone = "europe-west1-b"

    [tenants.objectstorage]
        Type        = "google"
        Region      = "europe-west1-b"
```