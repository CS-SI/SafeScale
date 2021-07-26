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
	"net"
	"net/url"
	"reflect"

	"github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"google.golang.org/api/googleapi"
)

func normalizeOperationError(oe *compute.OperationError) fail.Error {
	if oe == nil {
		return nil
	}

	if len(oe.Errors) == 0 {
		return nil
	}

	var errors []error
	for _, operr := range oe.Errors {
		if operr != nil {
			ne := fail.NewError(operr.Message)
			ne.Annotate("code", operr.Code)

			errors = append(errors, ne)
		}
	}

	if len(errors) == 0 {
		return nil
	}

	return fail.NewErrorList(errors)
}

// normalizeError translates GCP error to SafeScale one
func normalizeError(err error) fail.Error {
	if err == nil {
		return nil
	}

	switch cerr := err.(type) {
	case fail.Error:
		return cerr
	case *url.Error: // go connection errors, this is a 'subclass' of next error net.Error, that captures all go connection errors
		return fail.NewErrorWithCause(cerr)
	case net.Error: // also go connection errors
		return fail.NewErrorWithCause(cerr)
	case *googleapi.Error:
		message := cerr.Message
		switch cerr.Code {
		case 400:
			return fail.InvalidRequestError(message)
		case 401:
			return fail.NotAuthenticatedError(message)
		case 403:
			return fail.ForbiddenError(message)
		case 404:
			return fail.NotFoundError(message)
		case 408:
			return fail.TimeoutError(err, 0)
		case 409:
			return fail.InvalidRequestError(message)
		case 410:
			return fail.NotFoundError(message)
		case 425:
			return fail.OverloadError(message)
		case 429:
			return fail.OverloadError(message)
		case 500:
			return fail.ExecutionError(nil, message)
		case 503:
			return fail.NotAvailableError(message)
		case 504:
			return fail.NotAvailableError(message)
		default:
			logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from gcp provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
			return fail.UnknownError("from gcp driver, type='%s', error='%s'", reflect.TypeOf(err), err.Error())
		}
	}
	logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from gcp provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
	return fail.UnknownError("from gcp driver, type='%s', error='%s'", reflect.TypeOf(err), err.Error())
}
