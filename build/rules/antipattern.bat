@ECHO OFF
CLS

gogrep -x "func ($_) $x($*_) (resources.Bucket, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Bucket, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.Cluster, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Cluster, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.Host, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Host, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.Network, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Network, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.SecurityGroup, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.SecurityGroup, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.Share, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Share, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.Subnet, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Subnet, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func ($_) $x($*_) (resources.Volume, $*_) { $*_ }" ./... | awk "{ print $1 }"
gogrep -x "func $x($*_) (resources.Volume, $*_) { $*_ }" ./... | awk "{ print $1 }"
