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

// WIP rules

func isNullIsDeprecated(m dsl.Matcher) {
	m.Match(`if $x.isNull() { return $*_ }`).Where(m["x"].Text != "instance").
		Report("isNull is DANGEROUS when called upon something that is NOT a struct, if the code is valid rename the acceptor to 'instance' to disable this warning, if not, consider using instead 'if $x == nil || $x.isNull() {'").
		Suggest("if $x == nil || $x.isNull() {")
}

func falsePositives(m dsl.Matcher) {
	m.Match(`if $x, ok := $y.($z); !ok { return $*_ }`).Where(m["x"].Text != "_").Report("false positive")
}

func unexpectedNegatives(m dsl.Matcher) {
	m.Match(`if $x, $k := $y.($z); !$k { return $*_ }`,
		`if _, $k := $y.($z); !$k { return $*_ }`,
		`if $x, $k = $y.($z); !$k { return $*_ }`,
		`if _, $k = $y.($z); !$k { return $*_ }`,
		`if $x, $k := $y[$_].($z); !$k { return $*_ }`,
		`if _, $k := $y[$_].($z); !$k { return $*_ }`,
		`if _, $k = $y[$_].($z); !$k { return $*_ }`,
		`if $x, $k = $y[$_].($z); !$k { return $*_ }`).Where(!m["k"].Text.Matches("ok")).
		Report("surpising idiom, consider less surprises")
}

func dangerousNegatives(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(!m["z"].Text.Matches(".fail.*") && !m["x"].Text.Matches("_") && !m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be nil")
}

func typedNil(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(m["z"].Text.Matches(".fail.*") && m["x"].Text.Matches("_") && !m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be a typed nil")
}

func usingTypedNil(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(m["z"].Text.Matches(".fail.*") && !m["x"].Text.Matches("_") && !m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be a typed nil, so using $x is a serious mistake")
}
