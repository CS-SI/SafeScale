//go:build ignore
// +build ignore

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// This is a collection of rules for ruleguard: https://github.com/quasilyte/go-ruleguard

func riskyRUnlock(m dsl.Matcher) {
	m.Match(`$x.RUnlock($*_)`, `$x.$y.RUnlock($*_)`).
		Where(!m.File().Name.Matches(`.*test.go`)).
		Report("if something between rlock and runlock can panic, who takes care of unrlocking ?, consider using Deferred unrlock; if this is NOT a mistake, add a Nolint to the line")
}

func riskyUnlock(m dsl.Matcher) {
	m.Match(`$x.Unlock($*_)`, `$x.$y.Unlock($*_)`).
		Where(!m.File().Name.Matches(`.*test.go`)).
		Report("if something between lock and unlock can panic, who takes care of unlocking ?, consider using Deferred unlock; if this is NOT a mistake, add a Nolint to the line")
}
