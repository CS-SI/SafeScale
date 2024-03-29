# SafeScale: metadata in Object Storage

SafeScale stores metadata of the objects it uses in Object Storage. This document describes how this storage is organized.

## SafeScale metadata Bucket

The bucket name format is ``0.safescale-<unique provider-dependent value>[.<$SAFESCALE_METADATA_SUFFIX>]``; every metadata is stored in there.

SAFESCALE_METADATA_SUFFIX is an optional environment variable that can specialized even further the name of the bucket.
For example, with SAFESCALE_METADATA_SUFFIX=dev, the bucket name will be `0.safescale-<unique provider-dependent value>.dev`.
The variable needs to be defined before running any SafeScale CLI (safescaled, safescale, ...).

Each object in this bucket is stored as a JSON representation of Go structs, optionally encrypted (cf. MetadataKey in TENANTS.md).

In the following, each reference to this bucket name will be simplified to `<SAFESCALE>`.

### SafeScale Hosts

The hosts informations are stored in folder `<SAFESCALE>/hosts`.

Inside this folder, the metadata of a host is stored in object named with its ID in subfolder ``byID``,
and in object named with its name in subfolder ``byName``.

### SafeScale Networks

The metadata for network informations are stored in `<SAFESCALE>/networks`.

Inside this folder, the metadata of a network are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

### SafeScale Subnets

The metadata for subnet informations are stored in `<SAFESCALE>/subnets`.

Inside this folder, the metadata of a subnet are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

### SafeScale Security Groups

The metadata for security group  informations are stored in `<SAFESCALE>/security-groups`.

Inside this folder, the metadata of a security group are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

### SafeScale Shares

The metadata for Shares informations are stored in `<SAFESCALE>/shares`.

Inside this folder, the metadata of a share are stored in an object named with its ID in subfolder `byID`,
and in an object named with its name in subfolder `byName`.

### SafeScale Volumes

The metadata for volume informations are stored in `<SAFESCALE>/volumes`.

Inside this folder, the metadata of a volume are stored in an object named with its ID in subfolder `byID`,
and in an object named with its name in subfolder `byName`.

### SafeScale Clusters

The metadata for Cluster informations are stored in `<SAFESCALE>/clusters`.

Inside this folder, the metadata are stored in an object named as the cluster name.

## Example

```shell
0.safescale-xxxxxxxxxxx (dir)
|
+- hosts (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- 4856512f-fca1-4129-b1d5-3c2a19a7b747 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- myhost (obj)
|     |
|     +- ...
|
+- networks (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- net-dev (obj)
|     |
|     +- ...
|
+- subnets (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- e019445f-4d17-de45-b746-9ab0805008a7 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- subnet-dev (obj)
|     |
|     +- ...
|
+- security-groups (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- 22854344-8b97-ddfc-b35e-f441d990b004 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- sg-dev-hosts (obj)
|     |
|     +- ...
|
+- shares (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- 8b97ddfc-2285-4344-b35e-f441d990b004 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- myshare (obj)
|     |
|     +- ...
|
+- volumes (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- myvolume (obj)
|     |
|     +- ...
|
+- clusters
   |
   +- mycluster (obj)
   |
   + ...
   ```
