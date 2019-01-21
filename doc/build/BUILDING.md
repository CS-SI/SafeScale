# Building instructions for SafeScale

[How to build safescale on Ubuntu](UBUNTU_BUILD.md)
[How to build safescale on Debian](DEBIAN_BUILD.md)
[How to build safescale on Centos](CENTOS_BUILD.md)

## Following binaries will be produced :

- **broker** in `SafeScale/broker/cli/broker/`: CLI to deal with daemon brokerd. Available commands are described in [usage](../USAGE.md)
- **brokerd** in `SafeScale/broker/cli/brokerd/`: daemon in charge of executing requests from broker on providers
- **deploy** in `SafeScale/deploy/cli/`: CLI to manage cluster. Available commands are described in [usage](../USAGE.md)
- **perform** in `SafeScale/perform/`: CLI to manage cluster. Available commands are described in [usage](../USAGE.md)

For each previous binaries a cover version, is produced. They generate code coverage reports and are therefore only intended for devloppers.

- **broker-cover** in `SafeScale/broker/cli/broker/`
- **brokerd-cover** in `SafeScale/broker/cli/brokerd/`
- **deploy-cover** in `SafeScale/deploy/cli/`
- **perform-cover** in `SafeScale/perform/`
