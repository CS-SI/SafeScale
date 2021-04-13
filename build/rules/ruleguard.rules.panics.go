// +build ignore

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// This is a collection of rules for ruleguard: https://github.com/quasilyte/go-ruleguard

// Calling functions on a nil interface

func BucketDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Bucket")).Report(`panic danger`)
}

func ClusterDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Cluster")).Report(`panic danger`)
}

func HostDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Host")).Report(`panic danger`)
}

func NetworkDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Network")).Report(`panic danger`)
}

func SecurityGroupDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.SecurityGroup")).Report(`panic danger`)
}

func ShareDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Share")).Report(`panic danger`)
}

func SubnetDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Subnet")).Report(`panic danger`)
}

func VolumeDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.Volume")).Report(`panic danger`)
}

func isNullIsDeprecated(m dsl.Matcher) {
	m.Match(`if $x.isNull() { return $*_ }`).Where(m["x"].Text != "instance").Report("isNull is DANGEROUS when called upon something that is NOT a struct, consider using 'if $x == nil || ($x != nil && $x.isNull()) {'").
		Suggest("if $x == nil || ($x != nil && $x.isNull()) {")
}
