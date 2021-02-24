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

// NormalizeError translates gophercloud or openstack error to SafeScale error
func NormalizeError(err error) fail.Error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case fail.Error:
		return e
	case gophercloud.ErrDefault400: // bad request
		return reduceOpenstackError("BadRequest", e.Body)
	case *gophercloud.ErrDefault400: // bad request
		return reduceOpenstackError("BadRequest", e.Body)
	case gophercloud.ErrDefault401: // unauthorized
		return fail.NotAuthenticatedError(string(e.Body))
	case *gophercloud.ErrDefault401: // unauthorized
		return fail.NotAuthenticatedError(string(e.Body))
	case gophercloud.ErrDefault403: // forbidden
		return reduceOpenstackError("Forbidden", e.Body)
		// return fail.ForbiddenError(string(e.Body))
	case *gophercloud.ErrDefault403: // forbidden
		return reduceOpenstackError("Forbidden", e.Body)
		// return fail.ForbiddenError(string(e.Body))
	case gophercloud.ErrDefault404: // not found
		return reduceOpenstackError("NotFound", e.Body)
	case *gophercloud.ErrDefault404: // not found
		return reduceOpenstackError("NotFound", e.Body)
	case gophercloud.ErrDefault408: // request timeout
		return fail.OverflowError(nil, 0, string(e.Body))
	case *gophercloud.ErrDefault408: // request timeout
		return fail.OverflowError(nil, 0, string(e.Body))
	case gophercloud.ErrDefault409: // conflict
		return reduceOpenstackError("Duplicate", e.Body)
	case *gophercloud.ErrDefault409: // conflict
		// It may be a NeutronError, to be parsed
		return reduceOpenstackError("Duplicate", e.Body)
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
	case gophercloud.ErrMissingInput:
		return fail.InvalidRequestError(e.Error())
	case *gophercloud.ErrMissingInput:
		return fail.InvalidRequestError(e.Error())
	case *url.Error:
		return fail.NewErrorWithCause(e)
	default:
		switch err.Error() {
		case "EOF":
			return fail.NotFoundError("EOF")
		default:
			logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
			return fail.NewError("unhandled error received from provider: %s", err.Error())
		}
	}
}

//// reduceOpenstackBadRequest ...
//func reduceOpenstackBadRequest(in []byte) (xerr fail.Error) {
//	// FIXME: check if json.Unmarshal() may panic; if not theses 2 defers are superfluous
//	defer func() {
//		switch xerr.(type) {
//		case *fail.ErrRuntimePanic:
//			xerr = fail.InvalidRequestError(string(in))
//		}
//	}()
//	defer fail.OnPanic(&xerr)
//
//	var body map[string]interface{}
//	unjsonedErr := json.Unmarshal(in, &body)
//	if unjsonedErr == nil {
//		if content, ok := body["badRequest"].(map[string]interface{}); ok {
//			if msg, ok := content["message"].(string); ok {
//				return fail.InvalidRequestError(msg)
//			}
//		}
//		if content, ok := body["NeutronError"].(map[string]interface{}); ok {
//			if msg, ok := content["message"].(string); ok {
//				return fail.InvalidRequestError(msg)
//			}
//		}
//		if content, ok := body["message"].(string); ok {
//			return fail.InvalidRequestError(content)
//		}
//	}
//	return fail.InvalidRequestError(string(in))
//}

var errorFuncMap = map[string]func(string) fail.Error{
	"NotFound":   func(msg string) fail.Error { return fail.NotFoundError(msg) },
	"BadRequest": func(msg string) fail.Error { return fail.InvalidRequestError(msg) },
	"Duplicate":  func(msg string) fail.Error { return fail.DuplicateError(msg) },
	"Forbidden":  func(msg string) fail.Error { return fail.ForbiddenError(msg) },
}

// reduceOpenstackError ...
func reduceOpenstackError(errorName string, in []byte) (xerr fail.Error) {
	defer func() {
		switch xerr.(type) { //nolint
		case *fail.ErrRuntimePanic:
			xerr = fail.InvalidRequestError(string(in))
		}
	}()
	defer fail.OnPanic(&xerr)

	fn, ok := errorFuncMap[errorName]
	if !ok {
		return fail.InvalidParameterError("errorName", fmt.Sprintf("value '%s' not supported", errorName))
	}

	var body map[string]interface{}
	msg := string(in)
	unjsonedErr := json.Unmarshal(in, &body)
	if unjsonedErr == nil {
		if lvl1, ok := body["badRequest"].(map[string]interface{}); ok {
			if lvl2, ok := lvl1["message"].(string); ok {
				msg = lvl2
			}
		} else if lvl1, ok := body["NeutronError"].(map[string]interface{}); ok {
			if t, ok := lvl1["type"].(string); ok {
				var m string
				if m, ok = lvl1["message"].(string); ok {
					msg = m
					// This switch exists only to return another kind of fail.Error if the errorName does not comply with the real Neutron error (not seen yet)
					switch t { // nolint
					// FIXME: What obout *fail.ErrDuplicate ?
					case "SecurityGroupRuleExists": // return a *fail.ErrDuplicate
					}
				}
			}
		} else if lvl1, ok := body["conflictingRequest"].(map[string]interface{}); ok {
			msg = lvl1["message"].(string)
		} else if lvl1, ok := body["message"].(string); ok {
			msg = lvl1
		}
	}

	return fn(msg)
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

// // ParseNeutronError parses neutron json error and returns fields
// // Returns (nil, fail.ErrSyntax) if json syntax error occured (and maybe operation should be retried...)
// // Returns (nil, fail.Error) if any other error occurs
// // Returns (<retval>, nil) if everything is understood
// func ParseNeutronError(neutronError string) (map[string]string, fail.Error) {
// 	startIdx := strings.index(neutronError, "{\"NeutronError\":")
// 	jsonError := strings.Trim(neutronError[startIdx:], " ")
// 	unjsoned := map[string]map[string]interface{}{}
// 	if err := json.Unmarshal([]byte(jsonError), &unjsoned); err != nil {
// 		switch err.(type) {
// 		case *json.SyntaxError:
// 			return nil, fail.SyntaxError(err.Error())
// 		default:
// 			logrus.Debugf(err.Error())
// 			return nil, fail.ToError(err)
// 		}
// 	}
// 	if content, ok := unjsoned["NeutronError"]; ok {
// 		retval := map[string]string{
// 			"message": "",
// 			"type":    "",
// 			"code":    "",
// 			"detail":  "",
// 		}
// 		if field, ok := content["message"].(string); ok {
// 			retval["message"] = field
// 		}
// 		if field, ok := content["type"].(string); ok {
// 			retval["type"] = field
// 		}
// 		if field, ok := content["code"].(string); ok {
// 			retval["code"] = field
// 		}
// 		if field, ok := content["detail"].(string); ok {
// 			retval["detail"] = field
// 		}
//
// 		return retval, nil
// 	}
// 	return nil, nil
// }
