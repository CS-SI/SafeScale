# SafeScale: metadata in Object Storage

SafeScale stores metadata of the objects it uses in Object Storage. This document describes how this storage is organizes.

## SafeScale metadata Container/Bucket

The container/bucket name is ``0.safescale``. Everything is stored in there.

Each object in this container/bucket is stored as a gob representation of Go structs.

Note: by defining the environment variable SAFESCALE_METADATA_SUFFIX, it's possible to contextualize
the bucket name to ``0.safescale.$SAFESCALE_METADATA_SUFFIX``.
For example, with SAFESCALE_METADATA_SUFFIX=dev, the bucket name will be ``0.safescale.dev``.
The variable needs to be defined before starting brokerd, and for every SafeScale cli (broker, deploy, perform, ...).

### SafeScale Hosts

The host informations are stored in folder ``0.safescale/hosts``.

Inside this folder, the metadata of an host is stored in object named with its ID in subfolder ``byID``,
and in object named with its name in subfolder ``byName``.

### SafeScale Networks

The metadata for network informations are stored in ``0.safescale/networks``.

Inside this folder, the metadata of a network are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

metadata of objects linked to a network are stored in a subfolder named with the ID of the network, and in this subfolder will be find :

* an object named ``gw`` which contains the ID of the host acting as a default gateway for the network if it exists.
* a subfolder named ``host`` containing for each host attached to the network its metadata named with itd ID

### SafeScale NAS

The metadata for NAS informations are stored in ``0.safescale/nas``.

Inside this folder, the metadata of a volume are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

### SafeScale Volumes

The metadata for volume informations are stored in ``0.safescale/volumes`.

Inside this folder, the metadata of a volume are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

Besides the folders ``byID`` and ``byName`` will be find folders named with the uuid of the volumes, containing an object named with the uuids of the hosts that are currently attached to the volume.

### SafeScale Clusters

The metadata for Cluster informations are stored in ``0.safescale/clusters``.

Inside this folder, the metadata of a cluster is stored in a folder named as the Cluster Name submitted at its creation.

Inside this subfolder is stored :

* an object called `config` containing cluster configuration
* a subfolder named `masters` containing metadata of the hosts acting as Cluster controllers
* a subfolder named `nodes` containing :
  * a subfolder named `private` containing metadata of private nodes
  * a subfolder named `public` containing metadata of public nodes

## Example

```shell
0.safescale (dir)
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
|  |  |
|  |  +- net-dev (obj)
|  |  |
|  |  +- ...
|  |
|  +- 4d17de45-e019-445f-b746-9ab0805008a7 (dir)
|  |  |
|  |  +- gw (obj)
|  |  |
|  |  +- hosts (dir)
|  |     |
|  |     +- 4856512f-fca1-4129-b1d5-3c2a19a7b747 (obj)
|  |     |
|  |     +- ...
|  |
|  +- ...
|
+- nas (dir)
|  |
|  +- byID (dir)
|  |  |
|  |  +- 8b97ddfc-2285-4344-b35e-f441d990b004 (obj)
|  |  |
|  |  +- ...
|  |
|  +- byName (dir)
|     |
|     +- mynas (obj)
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
|  |  |
|  |  +- myvolume (obj)
|  |  |
|  |  +- ...
|  |
|  +- 4d17de45-e019-445f-b746-9ab0805008a7 (dir)
|  |  |
|  |  +- 4856512f-fca1-4129-b1d5-3c2a19a7b747 (obj)
|  |  |
|  |  +- ...
|  |
|  +- ...
|
+- clusters
   |
   +- mycluster (dir)
   |  |
   |  +- config (obj)
   |  |
   |  +- masters (dir)
   |  |  |
   |  |  +- 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
   |  |  |
   |  |  +- ...
   |  |
   |  +- nodes (dir)
   |     |
   |     +- private (dir)
   |     |  |
   |     |  + 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
   |     |  |
   |     |  +- ...
   |     |
   |     +- public (dir)
   |        |
   |        +- 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
   |        |
   |        + ...
   |
   + ...
   ```