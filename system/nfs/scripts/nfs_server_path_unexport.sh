#!/usr/bin/env bash
#
# Unexports and unconfigures a NFS export of a local path

grep -v "^{{.Path}} " /etc/exports >/etc/exports.new
mv /etc/exports.new /etc/exports
exportfs -ar
