#!/usr/bin/env bash

# Instal s3ql
# TODO move this installation in a dedicated go executable which will be eanble to handle different linux flavor (apt, yum, ...)
apt-get update && apt-get install -y s3ql && apt-get clean && rm -rf /var/lib/apt/lists/*

mkdir -p /etc/s3ql

# Create auth file
cat <<- EOF > /etc/s3ql/auth.{{.Container}}
[swift]
backend-login: {{.Tenant}}:{{.Login}}
backend-password: {{.Password}}
storage-url: swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}}
fs-passpharse: {{.Password}}
EOF

chmod 0600 /etc/s3ql/auth.{{.Container}}

# Format filesystem
echo "{{.Password}}"| mkfs.s3ql --authfile /etc/s3ql/auth.{{.Container}} --quiet swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}}

# Create MountPoint
mkdir -p {{.MountPoint}}

# Create script to mount container
cat <<- FOE > /usr/local/bin/mount-{{.Container}}
sudo /bin/bash << EOF
echo "{{.Password}}" |mount.s3ql --allow-other --authfile /etc/s3ql/auth.{{.Container}} swiftks://{{.AuthURL}}/{{.Region}}:{{.Container}} {{.MountPoint}}
EOF
FOE
chmod +x /usr/local/bin/mount-{{.Container}}

# Create script to umount container
cat <<- FOE > /usr/local/bin/umount-{{.Container}}
sudo /bin/bash << EOF
echo "{{.Password}}" |umount.s3ql {{.MountPoint}}
EOF
FOE
chmod +x /usr/local/bin/umount-{{.Container}}

/usr/local/bin/mount-{{.Container}}
chmod a+w {{.MountPoint}}
