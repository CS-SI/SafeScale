# SafeScale: metadata in Object Storage

SafeScale stores metadata of the objects it uses in Object Storage. This document describes how this storage is organizes.

## SafeScale metadata Container/Bucket

The container/bucket name is ``0.safescale``. Everything is stored in there.

Each object in this container/bucket is stored as a gob representation of Go structs.

### SafeScale Hosts

The host informations are stored in folder ``0.safescale/host``.

Inside this folder, the metadata of a host is stored in object named with its ID in subfolder ``byID``,
and in object named with its name in subfolder ``byName``.

### SafeScale Networks

The metadata for network informations are stored in ``0.safescale/network``.

Inside this folder, the metadata of a network are stored in an object named with its ID in subfolder ``byID``,
and in an object named with its name in subfolder ``byName``.

metadata of objects linked to a network are stored in a subfolder named with the ID of the network, and in this subfolder will be find :

* an object named ``gw`` which contains the ID of the host acting as a default gateway for the network if it exists.
* a subfolder named ``host`` containing for each host attached to the network its metadata named with itd ID

### SafeScale NAS

The metadata for NAS informations are stored in ``0.safescale/nas``.

TO COMPLETE

### SafeScale Clusters

The metadata for Cluster informations are stored in ``0.safescale/cluster``.

Inside this folder, the metadata of a cluster is stored in a file named as the Cluster Name submitted at its creation.

## Example

```
0.safescale (dir)
|
+ host (dir)
| |
| + 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
| |
| + ...
|
+ network (dir)
| |
| + byID (dir)
| | |
| | + 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
| | |
| | + ...
| |
| + byName (dir)
| | |
| | + net-dev (obj)
| | |
| | + ...
| |
| + 4d17de45-e019-445f-b746-9ab0805008a7 (dir)
| | |
| | + gw (obj)
| | |
| | + host (dir)
| |   |
| |   + 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
| |   |
| |   + ...
| |
| + ...
|
+ nas (dir)
| |
| + nas1 (dir)
| | |
| | + 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
| |
| + ...
|
+ cluster
  + mycluster (object)
  |
  + ...```