// +build ignore

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// unchecked casts, just don't

func uncheckedCast(m dsl.Matcher) {
	m.Match(`$x := $y.($z)`, `$x = $y.($z)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, when this breaks, it panics... and adding 3 lines of code to prevent a panic is always, always, worths it`)
}

func ignoredCastError(m dsl.Matcher) {
	m.Match(`$x, _ := $y.($z)`, `$x, _ = $y.($z)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`good luck tracking down an error here if it breaks`)
}

func intermediateCast(m dsl.Matcher) {
	m.Match(`$x := $y.($z).$w`, `$x = $y.($z).$w`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, then accessing a field, it's a panic waiting to happen... and adding 3 lines of code to prevent a panic is always, always, worths it`)
}

func intermediateCastWithFunc(m dsl.Matcher) {
	m.Match(`$x := $y.($z).$w($*_)`, `$x = $y.($z).$w($*_)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, then calling a function, it's a panic waiting to happen... and adding 3 lines of code to prevent a panic is always, always, worths it`)
}
