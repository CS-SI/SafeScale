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

package env

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type _options struct {
	prefixes    []string
	containsAll []string
	containsAny []string
}

type Option func(*_options) error

// OptionStartsWithAny allows to filter entries that starts with one of the provided strings
func OptionStartsWithAny(prefix ...string) func(*_options) error {
	fn := func(o *_options) error {
		if o == nil {
			return fail.InvalidParameterCannotBeNilError("o")
		}

		if len(prefix) > 0 {
			o.prefixes = append(o.prefixes, prefix...)
		}
		return nil
	}
	return fn
}

// OptionContainsAll allows to filter entries that contains all substrings provided
func OptionContainsAll(substrings ...string) func(*_options) error {
	fn := func(o *_options) error {
		if o == nil {
			return fail.InvalidParameterCannotBeNilError("o")
		}
		o.containsAll = append(o.containsAll, substrings...)
		return nil
	}
	return fn
}

// OptionContainsAny allows to filter entries that contains any substring provided
func OptionContainsAny(substrings ...string) func(*_options) error {
	fn := func(o *_options) error {
		if o == nil {
			return fail.InvalidParameterCannotBeNilError("o")
		}
		o.containsAny = append(o.containsAny, substrings...)
		return nil
	}
	return fn
}

// buildFilter builds callback function that will be called for each entry
func buildFilter(opts _options) func(string) bool {
	all := func(string) bool {
		return true
	}
	any := func(string) bool {
		return true
	}
	prefixes := func(string) bool {
		return true
	}

	if len(opts.prefixes) > 0 {
		prefixes = func(val string) bool {
			for _, v := range opts.prefixes {
				if strings.HasPrefix(val, v) {
					return true
				}
			}
			return false
		}
	}

	if len(opts.containsAll) > 0 {
		all = func(val string) bool {
			for _, v := range opts.containsAll {
				if !strings.Contains(val, v) {
					return false
				}
			}
			return true
		}
	}

	if len(opts.containsAny) > 0 {
		all = func(val string) bool {
			for _, v := range opts.containsAny {
				if strings.Contains(val, v) {
					return true
				}
			}
			return false
		}
	}

	return func(val string) bool {
		return prefixes(val) && all(val) && any(val)
	}
}
