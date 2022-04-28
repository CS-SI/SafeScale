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

func kickYouOutOfMyHead(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")

	m.Match(
		"$*_, $err := $x; if $y != nil { $*_ }",
		"$err := $x; if $y != nil { $*_ }",

		"$*_, $err = $x; if $y != nil { $*_ }",
		"$err = $x; if $y != nil { $*_ }",
	).
		Where(m["err"].Text != m["y"].Text && (m["y"].Type.Is("fail.Error") || m["y"].Type.Is("error")) && (m["err"].Type.Is("fail.Error") || m["err"].Type.Is("error"))).
		Report("maybe we are checking the wrong error")
}

func nilerr(m dsl.Matcher) {
	m.Match(
		`if err == nil { return err }`,
		`if err == nil { return $*_, err }`,
	).
		Report(`return nil error instead of nil value`)
}

func nilxerr(m dsl.Matcher) {
	m.Match(
		`if xerr == nil { return xerr }`,
		`if xerr == nil { return $*_, xerr }`,
	).
		Report(`return nil error instead of nil value`)
}

// err but no an error
func errnoterror(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")

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
		Where(m["err"].Text == "err" && !(m["err"].Type.Is("error") || m["err"].Type.Is("fail.Error")) && m["x"].Text != "recover()").
		Report("err variable not error type")
}

// err but no an error
func xerrnoterror(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")

	m.Match(
		"if $*_, xerr := $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, xerr := $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, xerr := $x; $err != nil { $*_ }",

		"if $*_, xerr = $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, xerr = $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, xerr = $x; $err != nil { $*_ }",

		"$*_, xerr := $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, xerr := $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, xerr := $x; if $err != nil { $*_ }",

		"$*_, xerr = $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, xerr = $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, xerr = $x; if $err != nil { $*_ }",
	).
		Where(m["err"].Text == "xerr" && !(m["err"].Type.Is("error") || m["err"].Type.Is("fail.Error")) && m["x"].Text != "recover()").
		Report("xerr variable not error type")
}

func errnetclosed(m dsl.Matcher) {
	m.Match(
		`strings.Contains($err.Error(), $text)`,
	).
		Where(m["text"].Text.Matches("\".*closed network connection.*\"")).
		Report(`String matching against error texts is fragile; use net.ErrClosed instead`).
		Suggest(`errors.Is($err, net.ErrClosed)`)

}

func wrongerrcall(m dsl.Matcher) {
	m.Match(
		`if $x.Err() != nil { return err }`,
		`if $x.Err() != nil { return $*_, err }`,
	).
		Report(`maybe returning wrong error after Err() call`)
}

func wrongxerrcall(m dsl.Matcher) {
	m.Match(
		`if $x.Err() != nil { return xerr }`,
		`if $x.Err() != nil { return $*_, xerr }`,
	).
		Report(`maybe returning wrong error after Err() call`)
}

func isNullIsDeprecated(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")
	m.Match(`if $x.isNull() { return $*_ }`, `if $x.IsNull() { return $*_ }`, `if !$x.isNull() { return $*_ }`, `if !$x.IsNull() { return $*_ }`).Where(m["x"].Text != "instance" && m["x"].Text != "e" && m["x"].Text != "el" && m["x"].Text != "s" && m["x"].Text != "p" && m["x"].Text != "self").
		Report("isNull is DANGEROUS when called upon something that is NOT a struct, if the code is valid rename the acceptor to 'instance' to disable this warning, if not, consider using instead 'if $x == nil || $x.isNull() {'").
		Suggest("if $x == nil || $x.isNull() {")
}

func isNullIsToxic(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")
	m.Match(`if !$x.isNull() { $*_ }`, `if $x.isNull() { $*_ }`, `if !$x.IsNull() { $*_ }`, `if $x.IsNull() { $*_ }`).Where(m["x"].Text != "instance" && m["x"].Text != "e" && m["x"].Text != "el" && m["x"].Text != "s" && m["x"].Text != "p" && m["x"].Text != "self").
		Report("isNull is DANGEROUS when called upon something that is NOT a struct, if the code is valid rename the acceptor to 'instance' to disable this warning, if not, consider using instead 'if $x == nil || $x.isNull() {'")
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
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(!m["z"].Text.Matches(".fail.*") && !m["x"].Text.Matches("_") && !m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be nil")
}

func typedNil(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(m["z"].Text.Matches(".fail.*") && m["x"].Text.Matches("_") && !m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be a typed nil")
}

func usingTypedNil(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v21/lib/utils/fail")
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(m["z"].Text.Matches(".fail.*") && !m["x"].Text.Matches("_") && !m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be a typed nil, so using $x is a serious mistake")
}
