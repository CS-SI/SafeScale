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

// unchecked casts, just don't

func uncheckedCast(m dsl.Matcher) {
	m.Match(`$x := $y.($z)`, `$x = $y.($z)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, when this breaks, it panics... and adding 3 lines of code to prevent a panic is always, always, worthy`)
}

func ignoredCastError(m dsl.Matcher) {
	m.Match(`$x, _ := $y.($z)`, `$x, _ = $y.($z)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`good luck tracking down an error here if it breaks`)
}

func intermediateCast(m dsl.Matcher) {
	m.Match(`$x := $y.($z).$w`, `$x = $y.($z).$w`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, then accessing a field, it's a panic waiting to happen... and adding 3 lines of code to prevent a panic is always, always, worthy`)
}

func intermediateCastWithFunc(m dsl.Matcher) {
	m.Match(`$x := $y.($z).$w($*_)`, `$x = $y.($z).$w($*_)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, then calling a function, it's a panic waiting to happen... and adding 3 lines of code to prevent a panic is always, always, worthy`)
}
