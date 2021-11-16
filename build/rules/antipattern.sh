#
# Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#! /bin/bash

# Detect code returning interfaces instead of a struct that implements the interface
# it breaks the 'accept interfaces, return structs' principle, and when we call a function upon a nil interface, it panics
# https://medium.com/@cep21/what-accept-interfaces-return-structs-means-in-go-2fe879e25ee8

gogrep -x 'func ($_) $x($*_) (resources.Bucket, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Bucket, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.Cluster, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Cluster, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.Host, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Host, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.Network, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Network, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.SecurityGroup, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.SecurityGroup, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.Share, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Share, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.Subnet, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Subnet, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func ($_) $x($*_) (resources.Volume, $*_) { $*_ }' ./... | awk '{ print $1 }'
gogrep -x 'func $x($*_) (resources.Volume, $*_) { $*_ }' ./... | awk '{ print $1 }'
