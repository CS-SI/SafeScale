//go:build ignore
// +build ignore

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// This is a collection of rules for ruleguard: https://github.com/quasilyte/go-ruleguard

func jsonUnMarshalIgnored(m dsl.Matcher) {
	m.Match(`_ = json.UnMarshal($*_)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report("json marshalling errors cannot be ignored, log the error or handle it, never ignore")
}

func jsonMarshalIgnored(m dsl.Matcher) {
	m.Match(`$x, _ = json.Marshal($*_)`,
		`$x, _ := json.Marshal($*_)`,
	).Where(!m.File().Name.Matches(`.*test.go`)).
		Report("json unmarshalling errors cannot be ignored, log the error or handle it, never ignore")
}
