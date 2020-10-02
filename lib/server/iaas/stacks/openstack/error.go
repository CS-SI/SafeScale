/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"

	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// // ProviderErrorToString creates an error string from openstack api error
// func ProviderErrorToString(err error) string {
//     if err == nil {
//         return ""
//     }
//     if _, ok := err.(gophercloud.ErrUnexpectedResponseCode); ok {
//         switch e := err.(type) {
//         case gophercloud.ErrDefault401:
//             return fmt.Sprintf("code: 401, reason: %s", string(e.Body))
//         case *gophercloud.ErrDefault401:
//             return fmt.Sprintf("code: 401, reason: %s", string(e.Body))
//         case gophercloud.ErrDefault404:
//             return fmt.Sprintf("code: 404, reason: %s", string(e.Body))
//         case *gophercloud.ErrDefault404:
//             return fmt.Sprintf("code: 404, reason: %s", string(e.Body))
//         case gophercloud.ErrDefault409:
//             return fmt.Sprintf("code: 409, reason: %s", string(e.Body))
//         case *gophercloud.ErrDefault409:
//             return fmt.Sprintf("code: 409, reason: %s", string(e.Body))
//         case gophercloud.ErrDefault500:
//             return fmt.Sprintf("code: 500, reason: %s", string(e.Body))
//         case *gophercloud.ErrDefault500:
//             return fmt.Sprintf("code: 500, reason: %s", string(e.Body))
//         case gophercloud.ErrUnexpectedResponseCode:
//             return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body))
//         case *gophercloud.ErrUnexpectedResponseCode:
//             return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body))
//         default:
//             logrus.Debugf("Error code not yet handled specifically: ProviderErrorToString(%s, %+v)\n", reflect.TypeOf(err).String(), err)
//             return err.Error()
//         }
//     }
//     return ""
// }

// NormalizeError translates gophercloud or openstack error to SafeScale error
func NormalizeError(err error) fail.Error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case fail.Error:
		return e
	case gophercloud.ErrDefault400: // bad request
		return fail.InvalidRequestError(string(e.Body))
	case *gophercloud.ErrDefault400: // bad request
		return fail.InvalidRequestError(string(e.Body))
	case gophercloud.ErrDefault401: // unauthorized
		return fail.NotAuthenticatedError(string(e.Body))
	case *gophercloud.ErrDefault401: // unauthorized
		return fail.NotAuthenticatedError(string(e.Body))
	case gophercloud.ErrDefault403: // forbidden
		return fail.ForbiddenError(string(e.Body))
	case *gophercloud.ErrDefault403: // forbidden
		return fail.ForbiddenError(string(e.Body))
	case gophercloud.ErrDefault404: // not found
		return fail.NotFoundError(string(e.Body))
	case *gophercloud.ErrDefault404: // not found
		return fail.NotFoundError(string(e.Body))
	case gophercloud.ErrDefault408: // request timeout
		return fail.OverflowError(nil, 0, string(e.Body))
	case *gophercloud.ErrDefault408: // request timeout
		return fail.OverflowError(nil, 0, string(e.Body))
	case gophercloud.ErrDefault409: // conflict
		return fail.InvalidRequestError(string(e.Body))
	case *gophercloud.ErrDefault409: // conflict
		return fail.InvalidRequestError(string(e.Body))
	case gophercloud.ErrDefault429: // too many requests
		return fail.OverloadError(string(e.Body))
	case *gophercloud.ErrDefault429: // too many requests
		return fail.OverloadError(string(e.Body))
	case gophercloud.ErrDefault500: // internal server error
		return fail.ExecutionError(nil, string(e.Body))
	case *gophercloud.ErrDefault500: // internal server error
		return fail.ExecutionError(nil, string(e.Body))
	case gophercloud.ErrDefault503: // service unavailable
		return fail.NotAvailableError(string(e.Body))
	case *gophercloud.ErrDefault503: // service unavailable
		return fail.NotAvailableError(string(e.Body))
	case gophercloud.ErrResourceNotFound:
		return fail.NotFoundError(e.Error())
	case *gophercloud.ErrResourceNotFound:
		return fail.NotFoundError(e.Error())
	case gophercloud.ErrMultipleResourcesFound:
		return fail.DuplicateError(e.Error())
	case *gophercloud.ErrMultipleResourcesFound:
		return fail.DuplicateError(e.Error())
	case gophercloud.ErrUnexpectedResponseCode:
		return qualifyGophercloudResponseCode(&e)
	case *gophercloud.ErrUnexpectedResponseCode:
		return qualifyGophercloudResponseCode(e)
	case *url.Error:
		return fail.NewErrorWithCause(e)
	default:
		logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
		return fail.NewError("unhandled error received from provider: %s", err.Error())
	}
}

// qualifyGophercloudResponseCode requalifies the unqualified error with appropriate error based on error code
func qualifyGophercloudResponseCode(err *gophercloud.ErrUnexpectedResponseCode) fail.Error {
	if err == nil {
		return nil
	}

	var newError error
	switch err.Actual {
	case 408:
		newError = &gophercloud.ErrDefault408{ErrUnexpectedResponseCode: *err}
	case 429:
		newError = &gophercloud.ErrDefault409{ErrUnexpectedResponseCode: *err}
	case 500:
		newError = &gophercloud.ErrDefault500{ErrUnexpectedResponseCode: *err}
	case 503:
		newError = &gophercloud.ErrDefault503{ErrUnexpectedResponseCode: *err}
	}

	if newError != nil {
		return NormalizeError(newError)
	}
	return fail.NewError("unexpected response code: code: %d, reason: %s", err.Actual, string(err.Body))
}

// errorMeansServiceUnavailable tells of err contains "service unavailable" (lower/upper/mixed case)
func errorMeansServiceUnavailable(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "service unavailable")
}

// ParseNeutronError parses neutron json error and returns fields
// Returns (nil, fail.ErrSyntax) if json syntax error occured (and maybe operation should be retried...)
// Returns (nil, fail.Error) if any other error occurs
// Returns (<retval>, nil) if everything is understood
func ParseNeutronError(neutronError string) (map[string]string, fail.Error) {
	startIdx := strings.Index(neutronError, "{\"NeutronError\":")
	jsonError := strings.Trim(neutronError[startIdx:], " ")
	unjsoned := map[string]map[string]interface{}{}
	if err := json.Unmarshal([]byte(jsonError), &unjsoned); err != nil {
		switch err.(type) {
		case *json.SyntaxError:
			return nil, fail.SyntaxError(err.Error())
		default:
			logrus.Debugf(err.Error())
			return nil, fail.ToError(err)
		}
	}
	if content, ok := unjsoned["NeutronError"]; ok {
		retval := map[string]string{
			"message": "",
			"type":    "",
			"code":    "",
			"detail":  "",
		}
		if field, ok := content["message"].(string); ok {
			retval["message"] = field
		}
		if field, ok := content["type"].(string); ok {
			retval["type"] = field
		}
		if field, ok := content["code"].(string); ok {
			retval["code"] = field
		}
		if field, ok := content["detail"].(string); ok {
			retval["detail"] = field
		}

		return retval, nil
	}
	return nil, nil
}
