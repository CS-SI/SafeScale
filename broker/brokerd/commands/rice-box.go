package commands

import (
	"github.com/GeertJohan/go.rice/embedded"
	"time"
)

func init() {

	// define files
	file2 := &embedded.EmbeddedFile{
		Filename:    "mount_block_device.sh",
		FileModTime: time.Unix(1522932090, 0),
		Content:     string("#!/usr/bin/env bash\n\n#mount device to repository\nmkfs.{{.Fsformat}} {{.Device}}\nmkdir -p {{.MountPoint}}\n\n#configure fstab\necho \"{{.Device}} {{.MountPoint}} {{.Fsformat}} defaults 0 2\" >> /etc/fstab\nmount -a\nchmod a+rw {{.MountPoint}}\n"),
	}
	file3 := &embedded.EmbeddedFile{
		Filename:    "mount_object_storage.sh",
		FileModTime: time.Unix(1523366215, 0),
		Content:     string("#!/usr/bin/env bash\n\n# Instal s3ql\n# TODO move this installation in a dedicated go executable which will be eanble to handle different linux flavor (apt, yum, ...)\napt-get update && apt-get install -y s3ql && apt-get clean && rm -rf /var/lib/apt/lists/*\n\nmkdir -p /etc/s3ql\n\n# Create auth file\ncat <<- EOF > /etc/s3ql/auth.{{.Container}}\n[swift]\nbackend-login: {{.Tenant}}:{{.Login}}\nbackend-password: {{.Password}}\nstorage-url: swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}}\nfs-passpharse: {{.Password}}\nEOF\n\nchmod 0600 /etc/s3ql/auth.{{.Container}}\n\n# Format filesystem\necho \"{{.Password}}\"| mkfs.s3ql --force --authfile /etc/s3ql/auth.{{.Container}} --quiet swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}}\n\n# Create MountPoint\nmkdir -p {{.MountPoint}}\n\n# Create script to mount container\ncat <<- FOE > /usr/local/bin/mount-{{.Container}}\nsudo /bin/bash << EOF\necho \"{{.Password}}\" |mount.s3ql --allow-other --authfile /etc/s3ql/auth.{{.Container}} swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}} {{.MountPoint}}\nEOF\nFOE\nchmod +x /usr/local/bin/mount-{{.Container}}\n\n# Create script to umount container\ncat <<- FOE > /usr/local/bin/umount-{{.Container}}\nsudo /bin/bash << EOF\necho \"{{.Password}}\" |umount.s3ql {{.MountPoint}}\nEOF\nFOE\nchmod +x /usr/local/bin/umount-{{.Container}}\n\n/usr/local/bin/mount-{{.Container}}\nchmod a+w {{.MountPoint}}\n"),
	}
	file4 := &embedded.EmbeddedFile{
		Filename:    "umount_block_device.sh",
		FileModTime: time.Unix(1523285795, 0),
		Content:     string("#!/usr/bin/env bash\n\n#umount the device\numount {{.Device}}\n\n#Retrieve mount point from fstab\nmountpoint=`grep -e \"^{{.Device}}\" /etc/fstab |awk '{print $2;}'`\n\n#Remove line in fstab\nsed -i '\\#^{{.Device}}#d' /etc/fstab\n\n#Remove mount directory*\nif [[ \"${mountpoint}\" =~ /[^/*].* ]]\nthen\n\trm -rf ${mountpoint}\nfi\n"),
	}
	file5 := &embedded.EmbeddedFile{
		Filename:    "umount_object_storage.sh",
		FileModTime: time.Unix(1523282499, 0),
		Content:     string("#!/usr/bin/env bash\n\n#echo \"{{.Password}}\" |sudo mount.s3ql --authfile /etc/s3ql/auth.{{.Container}} swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}} {{.MountPoint}}\n\nsystemctl stop s3ql-{{.Container}}\n\nrm /lib/systemd/system/s3ql-{{.Container}}.service\nrm /etc/s3ql/auth.{{.Container}}\n\n#Remove mount directory*\nif [[ \"{{.MountPoint}}\" =~ /[^/*].* ]]\nthen\n\trm -rf {{.MountPoint}}\nfi\n"),
	}

	// define dirs
	dir1 := &embedded.EmbeddedDir{
		Filename:   "",
		DirModTime: time.Unix(1523029028, 0),
		ChildFiles: []*embedded.EmbeddedFile{
			file2, // "mount_block_device.sh"
			file3, // "mount_object_storage.sh"
			file4, // "umount_block_device.sh"
			file5, // "umount_object_storage.sh"

		},
	}

	// link ChildDirs
	dir1.ChildDirs = []*embedded.EmbeddedDir{}

	// register embeddedBox
	embedded.RegisterEmbeddedBox(`broker_scripts`, &embedded.EmbeddedBox{
		Name: `broker_scripts`,
		Time: time.Unix(1523029028, 0),
		Dirs: map[string]*embedded.EmbeddedDir{
			"": dir1,
		},
		Files: map[string]*embedded.EmbeddedFile{
			"mount_block_device.sh":    file2,
			"mount_object_storage.sh":  file3,
			"umount_block_device.sh":   file4,
			"umount_object_storage.sh": file5,
		},
	})
}
