// +build ignore

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// This is a collection of rules for ruleguard: https://github.com/quasilyte/go-ruleguard

func xerrShouldNotBeARawError(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/lib/utils/fail")

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
	m.Import("github.com/CS-SI/SafeScale/lib/utils/fail")

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
