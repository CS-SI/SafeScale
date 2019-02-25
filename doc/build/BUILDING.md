# Building instructions for SafeScale

[How to build Safecale on Ubuntu](UBUNTU_BUILD.md)
[How to build SafeScale on Debian](DEBIAN_BUILD.md)
[How to build SafeScale on Centos](CENTOS_BUILD.md)

## Following binaries will be produced :

- **safescale** in `SafeScale/safescale/cli/safescale/`: CLI to deal with daemon safescaled. Available commands are described in [usage](../USAGE.md)
- **safescaled** in `SafeScale/safescale/cli/safescaled/`: daemon in charge of executing requests from safescale on providers
- **deploy** in `SafeScale/deploy/cli/`: CLI to manage cluster. Available commands are described in [usage](../USAGE.md)
- **perform** in `SafeScale/perform/`: CLI to manage cluster. Available commands are described in [usage](../USAGE.md)

For each previous binaries a cover version, is produced. They generate code coverage reports and are therefore only intended for developers.

- **safescale-cover** in `SafeScale/safescale/cli/safescale/`
- **safescaled-cover** in `SafeScale/safescale/cli/safescaled/`
- **deploy-cover** in `SafeScale/deploy/cli/`
- **perform-cover** in `SafeScale/perform/`
