// +build ignore

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// WIP rules

func isNullIsDeprecated(m dsl.Matcher) {
	m.Match(`if $x.isNull() { return $*_ }`).Where(m["x"].Text != "instance").
		Report("isNull is DANGEROUS when called upon something that is NOT a struct, if the code is valid rename the acceptor to 'instance' to disable this warning, if not, consider using instead 'if $x == nil || ($x != nil && $x.isNull()) {'").
		Suggest("if $x == nil || ($x != nil && $x.isNull()) {")
}

func dangerousNegatives(m dsl.Matcher) {
	m.Match(`if $x, ok := $y.($z); !ok { return $*_ }`).Report("false positive")
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

func dangerousNegativesAll(m dsl.Matcher) {
	m.Match(`if $x, ok := $y.($z); !ok { $*_ }`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report("the expression $y.($z) might be nil")
}
