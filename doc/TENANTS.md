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

- `[tenants.identity]` : MANDATORY
- `[tenants.compute]` : MANDATORY
- `[tenants.network]` : OPTIONAL
- `[tenants.objectstorage]` : OPTIONAL
- `[tenants.metadata]` : OPTIONAL

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

> | keyword                         | presence          | client                                |
> |---------------------------------|-------------------|---------------------------------------|
> | `AccessKey`                     | MANDATORY, CLIENT | outscale                              |
> | `ApplicationKey`                | MANDATORY, CLIENT | ovh                                   |
> | `OpenstackID`                   | MANDATORY, CLIENT | ovh                                   |
> | `OpenstackPassword`             | MANDATORY, CLIENT | ovh                                   |
> | `Password`                      | MANDATORY, CLIENT | all providers except ooutscal and ovh |
> | `SecretKey`                     | MANDATORY, CLIENT | outscale                              |
> | `Username`                      | MANDATORY, CLIENT | all providers except ooutscal and ovh |
> | `AlternateApiApplicationKey`    | OPTIONAL, CLIENT  | ovh                                   |
> | `AlternateApiApplicationSecret` | OPTIONAL, CLIENT  | ovh                                   |
> | `AlternateApiConsumerKey`       | OPTIONAL, CLIENT  | ovh                                   |
> | `UserID`                        | MANDATORY, CLIENT | outscale                              | 
> | `AccessKeyID`                   | MANDATORY, CLIENT | aws                                   |
> | `SecretAccessKey`               | MANDATORY, CLIENT | aws                                   |
> | `IdentityEndpoint`              | MANDATORY, CLIENT | openstack                             |
> | `auth_uri`                      | MANDATORY, CLIENT | gcp                                   |
> | `DomainNAme`                    | MANDATORY, CLIENT | cloudferro, flexibleengine            |
> | `Endpoint`                      | MANDATORY, CLIENT | flexibleengine                        | 
> | `project_id`                    | MANDATORY, CLIENT | gcp                                   |
> | `private_key_id`                | MANDATORY, CLIENT | gcp                                   |
> | `private_key`                   | MANDATORY, CLIENT | gcp                                   |
> | `client_email`                  | MANDATORY, CLIENT | gcp                                   |
> | `toekn_uri`                     | MANDATORY, CLIENT | gcp                                   |
> | `auth_provider_x509_cert_url`   | MANDATORY, CLIENT | gcp                                   |
> | `client_x509_cert_url`          | MANDATORY, CLIENT | gcp                                   |

### Section ``[tenants.compute]``

The valid keywords in this section are :

> | keyword                          | presence          | client                         |
> |----------------------------------|-------------------|--------------------------------|
> | `DefaultImage`                   | OPTIONAL, CLIENT  | all except ovh                 |
> | `ProjectName`                    | OPTIONAL, CLIENT  | aws, cloudferro, gcp, ovh      |
> | `ProjectID`                      | OPTIONAL, CLIENT  | aws, flexibleengine, gcp       |
> | `Region`                         | MANDATORY         | all                            |
> | `AvailabilityZone`               | MANDATORY, CLIENT | flexibleengine, openstack, ovh |
> | `DNS`                            | OPTIONAL          | all                            |
> | `Scannable`                      | OPTIONAL, CLIENT  | ovh                            |
> | `OperatorUsername`               | OPTIONAL          | all                            |
> | `Owners`                         | OPTIONAL, CLIENT  | aws                            |
> | `MaxLiftimeInHours`              | OPTIONAL          | all                            |
> | `ConcurrentMachineCreationLimit` | OPTIONAL          | all                            |
> | `Safe`                           | OPTIONAL          | all                            |
> | `Zone`                           | MANDATORY, CLIENT | gcp, aws                       |
> | `TenantName`                     | OPTIONAL, CLIENT  | openstack                      |
> | `TenantID`                       | OPTIONAL, CLIENT  | openstack                      |
> | `URL`                            | OPTIONAL, CLIENT  | outscale                       |
> | `Service`                        | MANDATORY, CLIENT | outscale                       |
> | `Subregion`                      | MANDATORY, CLIENT | outscale                       |
> | `DefaultTenancy`                 | OPTIONAL, CLIENT  | outscale                       |
> | `DefaultVolumeSpeed`             | OPTIONAL, CLIENT  | outscale                       |
> | `S3`                             | OPTIONAL, CLIENT  | aws                            |
> | `EC2`                            | OPTIONAL, CLIENT  | aws                            |
> | `SSM`                            | OPTIONAL, CLIENT  | aws                            |

### Section ``[tenants.network]``

The valid keywords in this section are :

> | keyword              | presence         | client                        |
> |----------------------|------------------|-------------------------------|
> | `ProviderNetwork`    | OPTIONAL, CLIENT | cloudferro, gcp, ovh          |
> | `VPCCIDR`            | OPTIONAL, CLIENT | flexibleengine, gcp, outscale |  
> | `VPCName`            | OPTIONAL, CLIENT | flexibleengine, gcp, outscale | 
> | `FloatingIPPool`     | OPTIONAL, CLIENT | cloudferro, openstack         |
> | `DefaultNetworkName` | OPTIONAL, CLIENT | flexibleengine, outscale      |
> | `DefaultNetworkCIDR` | OPTIONAL, CLIENT | flexibleengine, outscale      |
> | `ExternalNetwork`    | OPTIONAL, CLIENT | openstack                     |

### Section ``[tenants.objectstorage]``

The valid keywords in this section are :

> | keyword       | presence                   | client                        |
> |---------------|----------------------------|-------------------------------|
> | `AccessKey`   | MANDATORY, CLIENT, INHERIT | aws, flexibleengine, outscale |
> | `AuthURL`     | OPTIONAL, CLIENT           | openstack, ovh                |
> | `Endpoint`    | OPTIONAL, CLIENT           | flexibleengine                |
> | `Region`      | OPTIONAL, CLIENT, INHERIT  | gcp, ovh                      |
> | `SecretKey`   | MANDATORY, CLIENT, INHERIT | aws, flexibleengine, outscale |
> | `Type`        | MANDATORY                  | all                           |
> | `Endpoint`    | MANDATORY, CLIENT          | flexibleengine, outscale      |
> | `ProjectName` | OPTIONAL, CLIENT           | openstack, ovh                |
> | `Suffix`      | OPTIONAL                   | all                           |

### Section [tenants.metadata]

The valid keywords in this section are :

> | keyword     | presence                          | client        |
> |-------------|-----------------------------------|---------------|
> | `AccessKey` | MANDATORY, CLIENT, INHERIT        | aws, outscale |
> | `Endpoint`  | OPTIONAL, CLIENT, CLIENT, INHERIT | outscale      |
> | `SecretKey` | MANDATORY, CLIENT, INHERIT        | aws, outscale |
> | `Type`      | MANDATORY, INHERIT                | all           |
> | `CryptKey`  | OPTIONAL , CLIENT                 | outscale, ovh |
> | `Bucket`    | OPTIONAL, CLIENT                  | outscale      |
> | `Suffix`    | OPTIONAL                          | all           |

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
> | `"flexibleengine"` |
> | `"gcp"` |
> | `"openstack"` |
> | `"outscale"` |
> | `"ovh"` |

### AccessKey: alias, see [`Username`](#Username)

### AccessKeyID: alias, see [`Username`](#Username)

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

Only available on `OVH`.<br>
Contains OVH API application key (see [First Steps with OVH API](https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/))

### `AuthURL`

Contains the URL used to authenticate.<br>
May be used in sections `tenants.objectstorage` and `tenants.metadata`, especially when `Type` == `"swift"`.

### `AvailabilityZone`

Contains the zone to connect to. Values depend on provider.<br>
Is mandatory in `tenants.compute`
May be used in `tenants.objectstorage` and `tenants.metadata`.
If the AvailabilityZone is empty in `tenants.metadata`, safescale searches for valid values in `tenants.objectstorage`, then in `tenants.compute` (where is mandatory)

### `Bucket`

Contain the name of the bucket to use to store metadata.

### `ConcurrentMachineCreationLimit`

Contains the maximum number of machines that can be created concurrently.

### `CryptKey`

Contains the key used to encrypt the metadata.

### `DefaultImage`

Contains the name of the image to use by default.

### `DefaultNetworkCIDR`

Contains the CIDR of the default network.

### `DefaultNetworkName`

Contains the name of the default network.

### `DefaultVolumeSpeed`

Contains the type of volume to use by default.
Value :
    - "HDD" : for HDD volume
    - "SSD" : for SSD volume

### `DNS`

Contains a list of IP addresses of DNS servers separated by commas.

### `Domain`

Contains the Domain name wanted by the provider.<br>
May be used in every section.

### `DomainName`: alias, see [`Domain`](#Domain)

### `EC2`

Contains the EC2 endpoint to use.

### `Endpoint`

Contains the URL of the Object Storage backend to use.<br>
May be used in sections `tenants.objectstorage` and `tenants.metadata`, especially when `Type` == `"s3"`.

### `ExternalNetwork`

Contains the name of the external network connected host resources to public network.

### `FloatingIPPool`

Contains the name of the floating IP pool to use.

### `IdentityEndpoint`

Contains the URL of the Identity backend to use.

### `MaxLifeTimeInHours` (integer)

Contains the maximum lifetime of a machine in hours.

### `OpenstackID`: alias, see [`Username`](#Username)

### `OperatorUsername`

Contains the username that will be used to create the default user (safescale if unset).

### `OpenstackPassword`: alias, see [`Password`](#Password)

### `Password`

Contains the password for the authentication necessary to connect to the provider.<br>
May be used in sections `tenants.identity`, `tenants.objectstorage` and `tenants.metadata`.

### `ProjectID`

Contains the project ID to connect to.

### `ProjectName`

Contains the project name to connect to.

### `ProviderNetwork`

Contains the name of the provider network connected host resources to public network.<br>

### `Region`

Contains the region to connect to. Values depend on provider.<br>
Is mandatory in `tenants.compute`
May be used in `tenants.objectstorage` and `tenants.metadata`.
If the Region is empty in `tenants.metadata`, safescale searches for valid values in `tenants.objectstorage`, then in `tenants.compute` (where is mandatory)

### `S3`

Contains the S3 endpoint to use.

### `Safe`

If set to true, the tenant will be protected from deletion.

### `Scannable`

If set to true, allow the scanner to scan the tenant ([cf. SCANNER](SCANNER.md))

### `SecretAccessKey` : alias, see [`Password`](#Password)

### `SecretKey`: alias, see [Password](#Password)

### `Service`

Contains the name of the service to use.

### `SSM`

Contains the SSM endpoint to use.

### `Subregion`

Contains the subregion to connect to.

### `Suffix`

Contains the suffix to use for the tenant.

### `TenantID`

Contains the tenant ID to connect to.

### `TenantName`

Contains the tenant name to connect to.

### `URL`

Contains the URL of the provider to connect to.

### `UserID`

Contains the user ID to connect to.

### `Username`

Contains the username for the authentication necessary to connect to the provider.

It (or one of its aliases) must be present in section `tenants.identity`, and may be present in sections `tenants.objectstorage` and `tenants.metadata`.

### `Owners`

Only for AWS, optional.
Contains the comma-separated list of AMI Owners that will be used for AMI image search/selection.

### `Type`

Allows to specify the type of Object Storage protocol.<br>
Valid values are:

> | value     | description                                                  |
> |-----------|--------------------------------------------------------------|
> | `"s3"`    | S3 protocol as proposed by AWS or tools like minio           |
> | `"swift"` | SwiftKS protocol proposed by OpenStack Cloud implementations |
> | `"azure"` | Azure protocol (not tested)                                  |
> | `"gce"`   | Google GCE protocol                                          |

### `VPCCIDR`

Contains the name of the VPC where networks will be created. If the VPC doesn't exist, will be created.

### `VPCName`

Contains the CIDR of the VPC where networks will be created.

### `Zone`

Contains the zone to connect to.

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
