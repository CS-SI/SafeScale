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

package openstack

import (
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func caseInsensitiveContains(haystack, needle string) bool {
	lowerHaystack := strings.ToLower(haystack)
	lowerNeedle := strings.ToLower(needle)

	return strings.Contains(lowerHaystack, lowerNeedle)
}

func IsServiceUnavailableError(err error) bool {
	if err != nil {
		text := err.Error()
		return caseInsensitiveContains(text, "Service Unavailable")
	}

	return false
}

func GetUnexpectedGophercloudErrorCode(err error) (int64, fail.Error) {
	xType := reflect.TypeOf(err)
	xValue := reflect.ValueOf(err)

	if xValue.Kind() != reflect.Struct {
		return 0, fail.NewError("not a gophercloud.ErrUnexpectedResponseCode")
	}

	_, there := xType.FieldByName("ErrUnexpectedResponseCode")
	if there {
		_, there := xType.FieldByName("Actual")
		if there {
			recoveredValue := xValue.FieldByName("Actual").Int()
			if recoveredValue != 0 {
				return recoveredValue, nil
			}
		}
	}

	return 0, fail.NewError("not a gophercloud.ErrUnexpectedResponseCode")
}

func reinterpretGophercloudErrorCode(gopherErr error, success []int64, transparent []int64, abort []int64, defaultHandler func(error) error) error {
	if gopherErr != nil {
		code, err := GetUnexpectedGophercloudErrorCode(gopherErr)
		if err != nil {
			debug.IgnoreError(err)
			return gopherErr
		}
		if code == 0 {
			return gopherErr
		}
		for _, tcode := range success {
			if tcode == code {
				return nil
			}
		}

		for _, tcode := range abort {
			if tcode == code {
				return fail.AbortedError(gopherErr)
			}
		}

		for _, tcode := range transparent {
			if tcode == code {
				return gopherErr
			}
		}

		if defaultHandler == nil {
			return nil
		}

		return defaultHandler(gopherErr)
	}
	return nil
}

func defaultErrorInterpreter(inErr error) error { // nolint
	return reinterpretGophercloudErrorCode(
		inErr, nil, []int64{408, 409, 425, 429, 500, 503, 504}, nil, func(ferr error) error {
			if IsServiceUnavailableError(ferr) {
				return ferr
			}

			return fail.AbortedError(ferr)
		},
	)
}
