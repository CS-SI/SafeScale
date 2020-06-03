# Building instructions for SafeScale

- [How to build Safecale on Ubuntu](UBUNTU_BUILD.md)
- [How to build SafeScale on Debian](DEBIAN_BUILD.md)
- [How to build SafeScale on Centos](CENTOS_BUILD.md)

## Following binaries will be produced :

- **safescale** in `SafeScale/lib/cli/safescale/`: CLI to deal with daemon safescaled. Available commands are described [here](../USAGE.md#safescale)
- **safescaled** in `SafeScale/lib/cli/safescaled/`: daemon in charge of executing requests from safescale on providers. Usage is described [here](../USAGE.md#safescaled)
- **scanner** in `SafeScale/lib/cli/scanner/`: CLI to discover host templates. Available commands are described [here](../SCANNER.md)

For each previous binary a cover version is produced: binaries that also generate code coverage reports and are therefore only intended for developers.

- **safescale-cover** in `SafeScale/lib/cli/safescale/`
- **safescaled-cover** in `SafeScale/lib/cli/safescaled/`
- **scanner-cover** in `SafeScale/lib/cli/scanner/`
