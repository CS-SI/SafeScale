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

package result

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

func Payload[T any](r Holder[T]) (T, fail.Error) {
	var empty T
	casted, ok := r.(*holder[T])
	if !ok {
		return empty, fail.InconsistentError("failed to cast 'r' to type '*holder[T]' as expected")
	}

	return casted.payload, nil
}

// PayloadIfSuccessful returns the payload only if the holder is successful
// Returns:
//   - if successful: payload of type T, true, nil
//   - if unsuccessful: empty payload of type T, false, nil
//   - if an error occurs: empty payload of type T, false, error
func PayloadIfSuccessful[T any](r Holder[T]) (T, bool, fail.Error) {
	var empty T
	if valid.IsNull(r) {
		return empty, false, fail.InvalidParameterError("r", "cannot be null value of 'Holder'")
	}

	ok, xerr := r.Successful()
	if xerr != nil {
		return empty, false, xerr
	}

	if ok {
		payload, xerr := Payload[T](r)
		if xerr != nil {
			return empty, false, xerr
		}

		return payload, true, nil
	}

	return empty, false, nil
}
