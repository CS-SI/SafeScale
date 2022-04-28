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
