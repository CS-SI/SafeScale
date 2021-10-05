# !!! WARNING !!!

Format of SafeScale metadata has evolved. It's strongly advised to not use the binaries of this release candidate with existing SafeScale resources. However, if you are adventurous, there is a metadata upgrade procedure proposed when using `safescale tenant set <tenant>`, that has not yet been extensively tested. Use at your own risk !!!

## What's new

- Introducing Security Group support. Please refer to documentation for more details.
- SafeScale Network abstraction evolves: where in previous releases, a SafeScale Network encapsulated a couple network/VPC+subnet, now SafeScale abstracts both Network and Subnet. Previous behaviour is kept as default (creating a Network AND a Subnet with the same names), with the ability to create an empty SafeScale Network in which multiple Subnets can be created
- significant improvements in tolerance to temporary communication failures (loss of connection, failed DNS resolution, variable latency, etc.); when possible, retries are attempted instead of immediate failure.
- merged scanner binaries inside safescale/safescaled. Use is now `safescale tenant scan <tenant name>`
- noticeable speed improvements when creating Clusters

## Security Fixes

- in previous releases of SafeScale, private SSH key may be readable from some Cloud Provider metadata services, from Host itself only. Now, even if a private SSH key is still readable, this key is used only once for first connection to the Host and then immediately replaced by a new private SSH key.
 
## Developer interest

- refactoring done to separate IaaS code from SafeScale metadata (previously intimately mixed)
- added metadata versioning
- replaced Jaro-Winkler image selection algorithm by WagnerFischer (Levenshtein Distance kind of algorithm) with pre- and post-processing

## Fixed bugs
- on cluster creation failure, sometimes metadata is not completely cleaned, sometimes there are also machines not deleted that might require manual intervention to be removed: FIXED
- some timeouts to tune: FIXED
- Ubuntu 20.04 not supported correctly: FIXED
- cluster expand fails due to bad use of Image Name instead of Image ID during the new node creation
- deadlocks occur: FIXED
- SSH zombies: FIXED
- various cases leading to panic: FIXED
- FlexibleEngine: fails to create CentOS 7 Host: FIXED (using new image selection algorithm)
- GCP, AWS: use of ephemeral public IP (that may change after reboot of Host): FIXED

## Known bugs
- tenant metadata upgrade is not extensively tested:
   - cluster expand after upgrade fails
- cluster shrink when there is only one node remaining fails badly (have to decide if we forbid that...)
- Sometimes, remote script execution fails with error message `bash: bad interpreter: file text busy`
- CLI flags are not handled correctly if placed after command (since upgrade to urfave/cli v2)
- GCP: sometimes, Network deletion reports success but Network still exist
- OVH: templates `i1.*` contain far more nvme disk than reported by the API, costing a lot more than expected if selected
- documentation has been improved but still needs work
