#!/usr/bin/env bash
#
# Unexports and unconfigures a NFS export of a local path
sed -i '\#^{{.Path}} #d' /etc/exports
exportfs -ar
