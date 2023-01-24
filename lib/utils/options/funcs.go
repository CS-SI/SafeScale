/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package options

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Value returns the value of a key
func Value[O any](opts Options, key string) (O, fail.Error) {
	var out O
	anon, xerr := opts.Load(key)
	if xerr != nil {
		return out, xerr
	}

	var ok bool
	out, ok = anon.(O)
	if !ok {
		return out, fail.InconsistentError("failed to convert value to expected type '%s'", reflect.TypeOf(out).String())
	}

	return out, nil
}

// ValueOrDefault returns the value of key in options, or the default value if not found
func ValueOrDefault[T any](opts Options, key string, value T) (T, fail.Error) {
	var empty T
	out, xerr := Value[T](opts, key)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return value, nil
		default:
			return empty, xerr
		}
	}

	return out, nil
}

// ValueOrSet returns the value of key in options, or set the key with the value and returns it
// returns:
// - value, false, nil: there was no key in options but now it's set
// - value, true, nil: key was found in options
// - zero-value, false, fail.Error: an error occurred
func ValueOrSet[T any](opts Options, key string, value T) (T, bool, fail.Error) {
	var empty T
	out, xerr := Value[T](opts, key)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			xerr = Set(opts, key, value)
			if xerr != nil {
				return empty, false, xerr
			}

			return value, false, nil

		default:
			return empty, false, xerr
		}
	}

	return out, true, nil
}

// Set adds or changes value of key in options
func Set[T any](opts Options, key string, value T) fail.Error {
	return opts.Store(key, value)
}

// Add sets the key value if key is not in options, fails if key already in options
func Add[O any](opts Options, key string, value O) fail.Error {
	_, found, xerr := ValueOrSet(opts, key, value)
	if xerr == nil && found {
		return fail.DuplicateError("failed to add key '%s' in options; already there", key)
	}

	return nil
}

// Subset extracts elements from Options to create a new Options
func Subset(in Options, keys ...string) (Options, fail.Error) {
	return in.Subset(keys...)
}
