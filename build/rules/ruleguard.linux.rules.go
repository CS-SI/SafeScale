// +build ignore, !windows

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// Remove not relesable code
func notReleasable(m dsl.Matcher) {
	m.MatchComment(`// TBR:`).Report(`CANNOT be released until all the debug code is gone`)
}
