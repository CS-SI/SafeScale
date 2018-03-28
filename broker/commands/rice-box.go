package commands

import (
	"github.com/GeertJohan/go.rice/embedded"
	"time"
)

func init() {

	// define files
	file2 := &embedded.EmbeddedFile{
		Filename:    "mount_block_device.sh",
		FileModTime: time.Unix(1522250300, 0),
		Content:     string("#!/usr/bin/env bash\n\n#mount device to repository\nmkfs.{{.Fsformat}} {{.Device}}\nmkdir -p {{.MountPoint}}\n\n#configure fstab\necho \"{{.Device}} {{.MountPoint}} {{.Fsformat}} defaults 0 2\" >> /etc/fstab\nmount -a\nchmod a+rw {{.MountPoint}}\n"),
	}

	// define dirs
	dir1 := &embedded.EmbeddedDir{
		Filename:   "",
		DirModTime: time.Unix(1522250240, 0),
		ChildFiles: []*embedded.EmbeddedFile{
			file2, // "mount_block_device.sh"

		},
	}

	// link ChildDirs
	dir1.ChildDirs = []*embedded.EmbeddedDir{}

	// register embeddedBox
	embedded.RegisterEmbeddedBox(`broker_scripts`, &embedded.EmbeddedBox{
		Name: `broker_scripts`,
		Time: time.Unix(1522250240, 0),
		Dirs: map[string]*embedded.EmbeddedDir{
			"": dir1,
		},
		Files: map[string]*embedded.EmbeddedFile{
			"mount_block_device.sh": file2,
		},
	})
}
