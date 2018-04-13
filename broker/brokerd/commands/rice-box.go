package commands

import (
	"github.com/GeertJohan/go.rice/embedded"
	"time"
)

func init() {

	// define files
	file2 := &embedded.EmbeddedFile{
		Filename:    "create_nas.sh",
		FileModTime: time.Unix(1523631764, 0),
		Content:     string("#!/usr/bin/env bash\n\necho \"install nfs server\"\napt-get update && apt-get install -qqy nfs-common nfs-kernel-server && apt-get clean && rm -rf /var/lib/apt/lists/*\n\necho \"Create exported dir if necessary\"\nmkdir -p {{.ExportedPath}}\n\necho \"Export diretory\"\necho \"{{.ExportedPath}} *(rw,fsid=1,sync,no_root_squash)\" >>/etc/exports\n/etc/init.d/nfs-kernel-server restart"),
	}
	file3 := &embedded.EmbeddedFile{
		Filename:    "mount_block_device.sh",
		FileModTime: time.Unix(1523631762, 0),
		Content:     string("#!/usr/bin/env bash\n\n#mount device to repository\nmkfs.{{.Fsformat}} {{.Device}}\nmkdir -p {{.MountPoint}}\n\n#configure fstab\necho \"{{.Device}} {{.MountPoint}} {{.Fsformat}} defaults 0 2\" >> /etc/fstab\nmount -a\nchmod a+rw {{.MountPoint}}\n"),
	}
	file4 := &embedded.EmbeddedFile{
		Filename:    "mount_object_storage.sh",
		FileModTime: time.Unix(1523621175, 0),
		Content:     string("#!/usr/bin/env bash\n\n# Instal s3ql\n# TODO move this installation in a dedicated go executable which will be eanble to handle different linux flavor (apt, yum, ...)\napt-get update && apt-get install -y s3ql && apt-get clean && rm -rf /var/lib/apt/lists/*\n\nmkdir -p /etc/s3ql\n\n# Create auth file\ncat <<- EOF > /etc/s3ql/auth.{{.Container}}\n[swift]\nbackend-login: {{.Tenant}}:{{.Login}}\nbackend-password: {{.Password}}\nstorage-url: swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}}\nfs-passpharse: {{.Password}}\nEOF\n\nchmod 0600 /etc/s3ql/auth.{{.Container}}\n\n# Format filesystem\necho \"{{.Password}}\"| mkfs.s3ql --authfile /etc/s3ql/auth.{{.Container}} --quiet swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}}\n\n# Create MountPoint\nmkdir -p {{.MountPoint}}\n\n# Create script to mount container\ncat <<- FOE > /usr/local/bin/mount-{{.Container}}\nsudo /bin/bash << EOF\necho \"{{.Password}}\" |mount.s3ql --allow-other --authfile /etc/s3ql/auth.{{.Container}} swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}} {{.MountPoint}}\nEOF\nFOE\nchmod +x /usr/local/bin/mount-{{.Container}}\n\n# Create script to umount container\ncat <<- FOE > /usr/local/bin/umount-{{.Container}}\nsudo /bin/bash << EOF\necho \"{{.Password}}\" |umount.s3ql {{.MountPoint}}\nEOF\nFOE\nchmod +x /usr/local/bin/umount-{{.Container}}\n\n/usr/local/bin/mount-{{.Container}}\nchmod a+w {{.MountPoint}}\n"),
	}
	file5 := &embedded.EmbeddedFile{
		Filename:    "umount_block_device.sh",
		FileModTime: time.Unix(1523621175, 0),
		Content:     string("#!/usr/bin/env bash\n\n#umount the device\numount {{.Device}}\n\n#Retrieve mount point from fstab\nmountpoint=`grep -e \"^{{.Device}}\" /etc/fstab |awk '{print $2;}'`\n\n#Remove line in fstab\nsed -i '\\#^{{.Device}}#d' /etc/fstab\n\n# #Remove mount directory*\n# if [[ \"${mountpoint}\" =~ /[^/*].* ]]\n# then\n# \trm -rf ${mountpoint}\n# fi\n"),
	}
	file6 := &embedded.EmbeddedFile{
		Filename:    "umount_object_storage.sh",
		FileModTime: time.Unix(1523621175, 0),
		Content:     string("#!/usr/bin/env bash\n\n/usr/local/bin/umount-{{.Container}}\necho \"umount : $?\" > /tmp/umount.log\n\nrm /etc/s3ql/auth.{{.Container}}\necho \"rm auth : $?\" >> /tmp/umount.log\nrm /usr/local/bin/mount-{{.Container}}\necho \"rm mount : $?\" >> /tmp/umount.log\nrm /usr/local/bin/umount-{{.Container}}\necho \"rm umount : $?\" >> /tmp/umount.log\n"),
	}

	// define dirs
	dir1 := &embedded.EmbeddedDir{
		Filename:   "",
		DirModTime: time.Unix(1523631489, 0),
		ChildFiles: []*embedded.EmbeddedFile{
			file2, // "create_nas.sh"
			file3, // "mount_block_device.sh"
			file4, // "mount_object_storage.sh"
			file5, // "umount_block_device.sh"
			file6, // "umount_object_storage.sh"

		},
	}

	// link ChildDirs
	dir1.ChildDirs = []*embedded.EmbeddedDir{}

	// register embeddedBox
	embedded.RegisterEmbeddedBox(`broker_scripts`, &embedded.EmbeddedBox{
		Name: `broker_scripts`,
		Time: time.Unix(1523631489, 0),
		Dirs: map[string]*embedded.EmbeddedDir{
			"": dir1,
		},
		Files: map[string]*embedded.EmbeddedFile{
			"create_nas.sh":            file2,
			"mount_block_device.sh":    file3,
			"mount_object_storage.sh":  file4,
			"umount_block_device.sh":   file5,
			"umount_object_storage.sh": file6,
		},
	})
}
