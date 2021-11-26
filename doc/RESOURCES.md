# Resources managed by SafeScale

SafeScale being designed to abstract resources from various Cloud Providers, the resource names and usages may differ from
what one Cloud Provider may provide.

This documentation describes each SafeScale resource and differences from Cloud Provider counterparts (if it makes sense).

## resource `Network`

This kind of resource allows to isolate resources of a project from other projects, on the network level. The only way
proposed today by SafeScale to let `Networks` communicate is to use public IP addresses (some Cloud Providers allow to
set such communication between `Networks`, but this is not abstracted in SafeScale at this time).

A `Network` is the owner of at least one `Subnet` and `SecurityGroups`.

## resource `Subnet`

A `Subnet` will contain `Hosts`. It is characterized by a name, a CIDR, some DNS information (DNS servers,
domain name for the `Subnet`).

A `Subnet` is owned by a `Network`. It's name must be unique inside the `Network`.

SafeScale creates a `Host` in a `Subnet` to serve a `Subnet` gateway. 

## resource `SecurityGroup`

It's currently the only way in SafeScale to set network access authorization on `Hosts`.

## resource `Host`

This resource abstracts a computer instance from any Cloud Provider.

A `Host` is characterized by a name, a `Subnet` to which the `Host` is attached.

For now, an `Host` cannot have a public IP address, only `Subnet`'s gateway can (this will probably evolve in future release).

## resource `Share`

A `Share` exists to simplify the creation of NFS exports and NFS mounts. It's not actually an abstraction from Cloud Providers offers.

## resource `Volume`

This resource abstracts the ability to provide supplemental disk space to `Host`.

A `Volume` must be first created, then attached to a `Host`. By design, a `Volume` cannot be shared between multiple `Hosts`.

## resource `Bucket`

This resource exists mainly to allow mount of Object Storage bucket on `Hosts`.

## resource `Cluster`

This resource allows to control various `Hosts` as a whole, and to deploy software globally using `Features`.

## resource `Feature`

This resource proposes an unified way to add software to `Hosts` and `Clusters`.
It does not have a metadata for itself you will not find entry names `features` in metadata storage), but is referenced in `Hosts` and `Clusters` properties.
