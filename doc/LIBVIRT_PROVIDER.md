# Libvirt Provider (currently unavailable in V21.05)

For testing purposes it's possible to emulate a cloud provider locally with Libvirt/Qemu-KVM. SafeScale will work the same way except that all the hosts will be created on your own computer. The driver is designed to work with Ubuntu18.04, Debian9 and Centos7

## Build SafeScale with libvirt provider enabled
As the libvirt dependency is huge, libvirt provider is disabled by default and have to be enabled while building SafeScale.

### Downloading dependencies -

#### Ubuntu

```
#install docker
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get install -y docker-ce

#install libvirt
#universe repository is required (for virtinst & libguestfs-tools)
sudo add-apt-repository universe
sudo apt-get install -y qemu-kvm libvirt-bin libvirt-dev virtinst libguestfs-tools
#Note: The libvirt-bin package was dropped in 18.10. The package was split into two parts: libvirst-daemon-system and libvirt-clients
# So instead of libvirt-bin use libvirt-daemon-system libvirt-clients
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients libvirt-dev virtinst libguestfs-tools
```

#### Debian

```
#install docker
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
sudo apt-get install -y docker-ce

#install libvirt
#enable testing repository
sudo add-apt-repository "deb http://http.us.debian.org/debian/ testing non-free contrib main"
sudo apt-get install -y pkg-config dnsmasq ebtables
sudo apt-get install -y qemu-kvm libvirt-dev libvirt-clients libvirt-daemon-system virtinst libguestfs-tools
```

#### Centos
```
#install docker
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install -y docker-ce
sudo systemctl enable docker
sudo systemctl start docker

#install libvirt
#!! e2fsck is outdated (1.42) and will sometimes cause issues with virt-resize, e2fsck v>=1.43 will fix it !!
sudo yum install -y qemu-kvm libvirt virt-install libvirt-devel libguestfs-tools
sudo systemctl enable libvirtd
sudo systemctl start libvirtd
```

### Environment setup -
```
# Add the user to the right groups to create & manage VMs without sudo privileges
USER=$(whoami)
sudo usermod -a -G libvirt $USER
sudo usermod -a -G kvm $USER
# Enable the new groups
sudo su $USER

# Add read rights to the kernel executable to allow virt-sysprep to works well without admin privileges
sudo chmod 744 /boot/vmlinuz-`uname -r`

# Launch object storage (here a minio S3 storage with docker)
MINIO_ACCESS_KEY="accessKey" \
MINIO_SECRET_KEY="secretKey" \
sudo docker run -d --rm -p 9000:9000 --name minio1 -e "MINIO_ACCESS_KEY=$MINIO_ACCESS_KEY" -e "MINIO_SECRET_KEY=$MINIO_SECRET_KEY" -v /data/minio/data:/data -v /data/minio/config:/root/.minio minio/minio server /data
```
### Build

```
cd ${GOPATH:-$HOME}/src/github.com/CS-SI/SafeScale

#check that the dependencies are satisfied
make libvirt

#build with libvirt driver
make libvirt all

# Copy the binaries to $HOME/go/bin
make install
```

## Local Tenant
The local tenant is like [other providers tenants](TENANTS.md) but with some specificities. The ``[tenant.compute]`` section is used with modifications , ``[tenant.metadata] / [tenant.objectstorage]`` sections are used as any other provider, ``[tenant.identity]`` and ``[tenant.network]`` sections should be left empty.

### Section ``[tenant.compute]``

The valid keywords in this section are :

> | keyword     | presence    |
> | --- | --- |
> | ``uri`` | MANDATORY |
> | ``imagesJSONPath`` | MANDATORY|
> | ``templatesJSONPath`` | MANDATORY |
> | ``libvirtStorage`` | MANDATORY |

#### URI

The uri used by libvirt to connect to the hypervisor.
> | Hypervisor     | URI    |
> | --- | --- |
> | Qemu-KVM | ``qemu:///system`` |

#### ImagesJSONPath

The [images.json](#images) file path

#### TemplatesJSONPath

The [templates.json](#templates) file path

#### LibvirtStorage

The Folder that will be used by libvirt to store disk images and block storages (the folder must exists).

### Example

```toml
[[tenants]]
    name    = "Test_Local"
    client  = "local"

    [tenants.identity]

    [tenants.compute]
        uri                 = "qemu:///system"
        imagesJSONPath      = "/home/user/SafeScale/images.json"
        templatesJSONPath   = "/home/user/SafeScale/templates.json"
        libvirtStorage      = "/home/user/SafeScale/LibvirtStorage"

    [tenants.network]

    [tenants.objectstorage]
        Type        = "s3"
        Region      = "stub"
        Endpoint    = "http://localhost:9000"
        AccessKey   = "accessKey"
        SecretKey   = "secretKey"
```

## Images

To create a host we need a disk image with the os and useful functionalities pre-installed, available images are registered in a JSON file.

### Structure of JSON file

A List of images, each image is made up of :

* **imagePath** : The image path
* **imageName** : The image name
* **imageID**   : The image ID
* **disk**      : The name of the disk partition containing the root
* **download**  : How to download the image if not found localy, made of
    * **method**    : Method choosed to download the image (only GoogleDrive currently implemented)
    * **id**        : Id of the file to download (GoogleDrive)

### Example

```json
{
    "images" : [
        {
            "download"  : {
                "method"    : "GoogleDrive",
                "id"        : "1AXBdfVxlDuiQlefEVGjWxKZi5imPO62g"
            },
            "imagePath" : "/home/user/SafeScale/debian8_diskimage.qcow2",
            "imageName" : "Debian 8",
            "imageID"   : "8891e5fc-b42b-49a0-b852-569cc1f1062d",
            "disk"      : "/dev/sda1"
        },
        {
            "download"  : {
                "method"    : "GoogleDrive",
                "id"        : "1UbDc8Uip_z-V9UcYoJU8fQrQdokOuVSt"
            },
            "imagePath" : "/home/user/SafeScale/debian9_diskimage.qcow2",
            "imageName" : "Debian 9",
            "imageID"   : "8c411acd-78b8-45e1-affc-795189062b8e",
            "disk"      : "/dev/sda1"
        },
        {
            "download"  : {
                "method"    : "GoogleDrive",
                "id"        : "1f4yJ3_yjevdtdW1_SF6tlgBnvoUgKInK"
            },
            "imagePath" : "/home/user/SafeScale/centos7_diskimage.qcow2",
            "imageName" : "Centos 7",
            "imageID"   : "1fa9ae7a-1b7f-48ff-8ced-06e884d9aabc",
            "disk"      : "/dev/sda2"
        },
        {
            "download"  : {
                "method"    : "GoogleDrive",
                "id"        : "1wKr6Kf8LkRJnWKjzpUnWeAwp-FZFyJ3M"
            },
            "imagePath" : "/home/user/SafeScale/ubuntu1804_diskimage.qcow2",
            "imageName" : "Ubuntu 18.04",
            "imageID"   : "9c7e752d-43da-44f2-992e-3294b2326aa4",
            "disk"      : "/dev/sda1"
        },
        {
            "download"  : {
                "method"    : "GoogleDrive",
                "id"        : "1lQbL0I08_4vkOZKnksnTpYV9XBsQTA0Q"
            },
            "imagePath" : "/home/user/SafeScale/ubuntu2004_diskimage.qcow2",
            "imageName" : "Ubuntu 20.04",
            "imageID"   : "58390614-e8c1-442c-bbe8-5e8e7790a5aa",
            "disk"      : "/dev/sda2"
        }
    ]
}
```

## Templates

to create a host you need a template specifying its characteristics, all the availables templates are stored in JSON file

### Structure of JSON file

A List of templates, each template is made up of :

* **templateID**    : The template ID
* **templateName**  : The template name
* **templateSpecs** : The template specifications
    * **coresNumber**   : The number of cores allowed to the host
    * **ramSize**       : The ram size allowed to the host (in GB)
    * **diskSize**      : The disk size allowed to the host (in GB)
    * **gpuNumber**     : Currently unused
    * **gpuType**       : Currently unused


### Example

```json
{
    "templates" : [
        {
            "templateID"    : "03014bb3-9096-49a7-bf5e-0f9e440ad7c6",
            "templateName"  : "tpl-1",
            "templateSpecs" : {
                "coresNumber"   : 1,
                "ramSize"       : 1.0,
                "diskSize"      : 10,
                "gpuNumber"     : 0,
                "gpuType"       : ""
            }
        },
        {
            "templateID"    : "a7270c78-b61c-448c-878c-c9ab72e33f83",
            "templateName"  : "tpl-2",
            "templateSpecs" : {
                "coresNumber"   : 1,
                "ramSize"       : 2.0,
                "diskSize"      : 20,
                "gpuNumber"     : 0,
                "gpuType"       : ""
            }
        },
        {
            "templateID"    : "484e3686-4ea5-4af0-b215-e404947e0477",
            "templateName"  : "tpl-3",
            "templateSpecs" : {
                "coresNumber"   : 1,
                "ramSize"       : 4.0,
                "diskSize"      : 30,
                "gpuNumber"     : 0,
                "gpuType"       : ""
            }
        },
        {
            "templateID"    : "d2bf2825-b864-4355-a278-02e5f7281475",
            "templateName"  : "tpl-4",
            "templateSpecs" : {
                "coresNumber"   : 2,
                "ramSize"       : 4.0,
                "diskSize"      : 30,
                "gpuNumber"     : 0,
                "gpuType"       : ""
            }
        },
        {
            "templateID"    : "d6a45564-a7a1-422a-9045-453ffb38f155",
            "templateName"  : "tpl-5",
            "templateSpecs" : {
                "coresNumber"   : 3,
                "ramSize"       : 6.0,
                "diskSize"      : 100,
                "gpuNumber"     : 0,
                "gpuType"       : ""
            }
        }
    ]
}
```