#!/usr/bin/env bash

echo "Unexport path {{.ExportedPath}}"
#Remove line in fstab
sed -i '\#^{{.ExportedPath}}#d' /etc/exports
# TODO Check if there no more exported path to stop the nfs server as it is not used anymore
# Exported directory is not deleted as it might contains data or be used in another context

exportfs -ar