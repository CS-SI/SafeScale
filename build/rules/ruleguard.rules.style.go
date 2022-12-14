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

func xerrShouldNotBeARawError(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match(
		"if $*_, err := $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, err := $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, err := $x; $err != nil { $*_ }",

		"if $*_, err = $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, err = $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, err = $x; $err != nil { $*_ }",

		"$*_, err := $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, err := $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, err := $x; if $err != nil { $*_ }",

		"$*_, err = $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, err = $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, err = $x; if $err != nil { $*_ }",
	).
		Where(m["err"].Text == "xerr" && !m["err"].Type.Is("fail.Error") && m["x"].Text != "recover()").
		Report("xerr variable shoud be of type fail.Error, it's not, rename to err")
}

func failuresShouldBeXerrs(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match(
		"if $*_, err := $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, err := $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, err := $x; $err != nil { $*_ }",

		"if $*_, err = $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, err = $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, err = $x; $err != nil { $*_ }",

		"$*_, err := $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, err := $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, err := $x; if $err != nil { $*_ }",

		"$*_, err = $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, err = $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, err = $x; if $err != nil { $*_ }",
	).
		Where(m["err"].Text == "err" && m["err"].Type.Is("fail.Error") && m["x"].Text != "recover()").
		Report("err variable shoud not be of type fail.Error, rename to xerr")
}

func removeDebugCode(m dsl.Matcher) {
	m.Match(
		"logrus.Warningf($*_, $*_)",
		"logrus.Warning($*_, $x)",
		"logrus.Warningf($*_)",
		"logrus.Warning($*_)",
	).
		Report("REMOVE debug code before a release")
}

func removeMoreDebugCode(m dsl.Matcher) {
	m.Match(
		"logrus.WithContext($*_).Warningf($*_, $*_)",
		"logrus.WithContext($*_).Warning($*_, $x)",
		"logrus.WithContext($*_).Warningf($*_)",
		"logrus.WithContext($*_).Warning($*_)",
	).
		Report("REMOVE ctx debug code before a release")
}
