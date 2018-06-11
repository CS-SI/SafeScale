# SafeScale: metadata in Object Storage

SafeScale stores metadata of the objects it uses in Object Storage. This document describes how this storage is organizes.

## SafeScale metadata Container/Bucket

The container/bucket name is ``0.safescale``. Everything is stored in there.

Each object in this container/bucket is stored as a gob representation of Go structs.

### SafeScale Hosts

The host informations are stored in ``0.safescale/host``.

Metadata for a host in stored in an object named with its ID on the Cloud Provider.

### SafeScale Networks

The metadata for network informations are stored in ``0.safescale/network``.

Inside this folder, each network will have a folder named after its ID on the Cloud Provider.

For each network folder, there can be :

* an object named ``gw`` which contains the ID of the host acting as a default gateway for the network if it exists.
* an object for each vm attached to the network, named after its ID on the Cloud Provider.

### SafeScale NAS

The metadata for NAS informations are stored in ``0.safescale/nas``.

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
| + 4d17de45-e019-445f-b746-9ab0805008a7 (dir)
| | |
| | + gw (obj)
| | |
| | + 4d17de45-e019-445f-b746-9ab0805008a7 (obj)
| | |
| | + ...
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