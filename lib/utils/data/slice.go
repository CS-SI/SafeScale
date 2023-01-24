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

package data

// // AnonymousMap ...
// type AnonymousMap map[any]any
//
// func AnonymousMapToStringMap(in map[any]any) map[string]any {
// 	out := make(map[string]interface{}, len(in))
// 	for k, v := range in {
// 		key := fmt.Sprintf("%v", k)
// 		out[key] = v
// 	}
// 	return out
// }

// Slice ...
type Slice[T any] []T

func (s Slice[T]) Length() int {
	return len(s)
}

// NewSlice ...
func NewSlice[T any](o ...int) Slice[T] {
	if len(o) > 0 {
		capability := o[0]
		return make(Slice[T], 0, capability)
	}

	return Slice[T]{}
}

func (s Slice[T]) Clone() (Slice[T], error) {
	if s == nil {
		return NewSlice[T](), nil
	}

	cs := NewSlice[T]()
	err := (&cs).Replace(s)
	return cs, err
}

func (s *Slice[T]) Replace(src Slice[T]) error {
	*s = make(Slice[T], len(src))
	for k, v := range src {
		(*s)[k] = v
	}
	return nil
}

// StringSliceToMap transforms a Slice of string to a Map of T indexed by slice values
func StringSliceToMap[T any](s Slice[string]) Map[string, T] {
	var null T
	l := s.Length()
	m := NewMap[string, T](l)
	for _, v := range s {
		m[v] = null
	}

	return m
}
