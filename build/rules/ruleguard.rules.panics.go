//go:build ignore
// +build ignore

/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// This is a collection of rules for ruleguard: https://github.com/quasilyte/go-ruleguard

// Calling functions on a nil interface

func BucketDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.bucket")).Report(`panic danger`)
}

func ClusterDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.cluster")).Report(`panic danger`)
}

func HostDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.host")).Report(`panic danger`)
}

func NetworkDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.network")).Report(`panic danger`)
}

func SecurityGroupDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.securitygroup")).Report(`panic danger`)
}

func ShareDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.share")).Report(`panic danger`)
}

func SubnetDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.subnet")).Report(`panic danger`)
}

func VolumeDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/server/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.Service($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.volume")).Report(`panic danger`)
}

func isNullIsDeprecated(m dsl.Matcher) {
	m.Match(`if $x.isNull() { return $*_ }`).Where(m["x"].Text != "instance").Report("isNull is DANGEROUS when called upon something that is NOT a struct, consider using 'if $x == nil || $x.isNull() {'").
		Suggest("if $x == nil || $x.isNull() {")
}
