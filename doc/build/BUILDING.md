# Building instructions for SafeScale

- [How to build SafeScale on Ubuntu](UBUNTU_BUILD.md)
- [How to build SafeScale on Debian](DEBIAN_BUILD.md)
- [How to build SafeScale with Docker](DOCKER_BUILD.md)

## Following binaries will be produced :

- **safescale** in `SafeScale/cli/safescale/`: CLI to deal with daemon safescaled. Available commands are described [here](../USAGE.md#safescale)
- **safescaled** in `SafeScale/cli/safescaled/`: daemon in charge of executing requests from safescale on providers. Usage is described [here](../USAGE.md#safescaled)

For each previous binaries a cover version, is produced. They generate code coverage reports and are therefore only intended for developers.

- **safescale-cover** in `SafeScale/lib/cli/safescale/`
- **safescaled-cover** in `SafeScale/lib/cli/safescaled/`
