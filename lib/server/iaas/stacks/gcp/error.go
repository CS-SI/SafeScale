/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package gcp

import (
	"fmt"
	"net/url"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"google.golang.org/api/googleapi"
)

// normalizeError translates AWS error to SafeScale one
func normalizeError(err error) fail.Error {
	if err == nil {
		return nil
	}

	switch cerr := err.(type) {
	case fail.Error:
		return cerr
	case *url.Error:
		return fail.NewErrorWithCause(err)
	case *googleapi.Error:
		switch cerr.Code {
		case 400:
			return fail.InvalidRequestError(cerr.Message)
		case 404:
			return fail.NotFoundError(cerr.Message)
		case 409:
			return fail.DuplicateError(cerr.Message)
		default:
			logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from gcp provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
			return fail.UnknownError("from gcp driver, type='%s', error='%s'", reflect.TypeOf(err), err.Error())
		}
	}
	logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from gcp provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
	return fail.UnknownError("from gcp driver, type='%s', error='%s'", reflect.TypeOf(err), err.Error())
}
