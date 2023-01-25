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

package openstack

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/gophercloud/gophercloud"
)

// NormalizeError translates gophercloud or openstack error to SafeScale error
func NormalizeError(err error) fail.Error {
	if err != nil {
		switch e := err.(type) {
		case fail.Error:
			cause := e.Cause()
			if cause != nil {
				return NormalizeError(cause)
			}
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
		case *gophercloud.ErrDefault403: // forbidden
			return reduceOpenstackError("Forbidden", e.Body)
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
			return reduceOpenstackError("Duplicate", e.Body)
		case gophercloud.ErrDefault429: // too many requests
			return fail.OverloadError(string(e.Body))
		case *gophercloud.ErrDefault429: // too many requests
			return fail.OverloadError(string(e.Body))
		case gophercloud.ErrDefault500: // internal server error
			return reduceOpenstackError("Execution", e.Body)
		case *gophercloud.ErrDefault500: // internal server error
			return reduceOpenstackError("Execution", e.Body)
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
		case gophercloud.ErrEndpointNotFound:
			return fail.NotAvailableError(e.Error())
		case *gophercloud.ErrEndpointNotFound:
			return fail.NotAvailableError(e.Error())
		case *url.Error: // go connection errors, this is a 'subclass' of next error net.Error, that captures all go connection errors
			return fail.NewErrorWithCause(e)
		case net.Error: // also go connection errors
			return fail.NewErrorWithCause(e)
		default:
			if strings.Contains(err.Error(), "Bad request with") {
				return fail.InvalidRequestError(e.Error())
			}
			if strings.Contains(err.Error(), "NeutronError") {
				return fail.InvalidRequestError(e.Error())
			}
			return fail.ConvertError(defaultErrorInterpreter(err))
		}
	}
	return nil
}

// OldNormalizeError translates gophercloud or openstack error to SafeScale error
func OldNormalizeError(err error) fail.Error {
	if err != nil {
		switch e := err.(type) {
		case fail.Error:
			cause := e.Cause()
			if cause != nil {
				return NormalizeError(cause)
			}
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
		case *gophercloud.ErrDefault403: // forbidden
			return reduceOpenstackError("Forbidden", e.Body)
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
			return reduceOpenstackError("Duplicate", e.Body)
		case gophercloud.ErrDefault429: // too many requests
			return fail.OverloadError(string(e.Body))
		case *gophercloud.ErrDefault429: // too many requests
			return fail.OverloadError(string(e.Body))
		case gophercloud.ErrDefault500: // internal server error
			return reduceOpenstackError("Execution", e.Body)
		case *gophercloud.ErrDefault500: // internal server error
			return reduceOpenstackError("Execution", e.Body)
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
		case gophercloud.ErrEndpointNotFound:
			return fail.NotAvailableError(e.Error())
		case *gophercloud.ErrEndpointNotFound:
			return fail.NotAvailableError(e.Error())
		case *url.Error: // go connection errors, this is a 'subclass' of next error net.Error, that captures all go connection errors
			return fail.NewErrorWithCause(e)
		case net.Error: // also go connection errors
			return fail.NewErrorWithCause(e)
		default:
			switch err.Error() {
			case "EOF":
				return fail.NotFoundError("EOF")
			default:
				return fail.NewError("unhandled error received from provider: %s", err.Error())
			}
		}
	}
	return nil
}

var errorFuncMap = map[string]func(string) fail.Error{
	"NotFound":   func(msg string) fail.Error { return fail.NotFoundError(msg) },
	"BadRequest": func(msg string) fail.Error { return fail.InvalidRequestError(msg) },
	"Duplicate":  func(msg string) fail.Error { return fail.DuplicateError(msg) },
	"Forbidden":  func(msg string) fail.Error { return fail.ForbiddenError(msg) },
	"Execution":  func(msg string) fail.Error { return fail.ExecutionError(nil, msg) },
}

// reduceOpenstackError ...
func reduceOpenstackError(errorName string, in []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	fn, ok := errorFuncMap[errorName]
	if !ok {
		return fail.InvalidParameterError("errorName", fmt.Sprintf("value '%s' not supported", errorName))
	}

	var body map[string]interface{}
	msg := string(in)
	unjsonedErr := json.Unmarshal(in, &body)
	if unjsonedErr != nil {
		return fail.Wrap(unjsonedErr, "error unmarshalling error received from provider: %s", string(in))
	}

	if lvl1, ok := body["badRequest"].(map[string]interface{}); ok {
		if lvl2, ok := lvl1["message"].(string); ok {
			msg = lvl2
		}
	} else if lvl1, ok := body["computeFault"].(map[string]interface{}); ok {
		if lvl2, ok := lvl1["message"].(string); ok {
			msg = lvl2
		}
	} else if lvl1, ok := body["NeutronError"].(map[string]interface{}); ok {
		if t, ok := lvl1["type"].(string); ok {
			var m string
			if m, ok = lvl1["message"].(string); ok {
				msg = m
				// This switch exists only to return another kind of fail.Error if the errorName does not comply with the real Neutron error (not seen yet)
				switch t {
				// FIXME: What about *fail.ErrDuplicate ?
				case "SecurityGroupRuleExists": // return a *fail.ErrDuplicate
				default:
				}
			}
		}
	} else if lvl1, ok := body["conflictingRequest"].(map[string]interface{}); ok {
		if m, ok := lvl1["message"].(string); ok {
			msg = m
		}
	} else if lvl1, ok := body["message"].(string); ok {
		msg = lvl1
	}

	return fn(msg)
}

// qualifyGophercloudResponseCode requalifies the unqualified error with appropriate error based on error code
func qualifyGophercloudResponseCode(err *gophercloud.ErrUnexpectedResponseCode) fail.Error {
	if err != nil {
		var newError error
		switch err.Actual {
		case 401:
			newError = &gophercloud.ErrDefault401{ErrUnexpectedResponseCode: *err}
		case 403:
			newError = &gophercloud.ErrDefault403{ErrUnexpectedResponseCode: *err}
		case 404:
			newError = &gophercloud.ErrDefault404{ErrUnexpectedResponseCode: *err}
		case 408:
			newError = &gophercloud.ErrDefault408{ErrUnexpectedResponseCode: *err}
		case 409:
			newError = &gophercloud.ErrDefault409{ErrUnexpectedResponseCode: *err}
		case 425: // to early, mapped to 429
			newError = &gophercloud.ErrDefault429{ErrUnexpectedResponseCode: *err}
		case 429:
			newError = &gophercloud.ErrDefault429{ErrUnexpectedResponseCode: *err}
		case 500:
			newError = &gophercloud.ErrDefault500{ErrUnexpectedResponseCode: *err}
		case 503:
			newError = &gophercloud.ErrDefault503{ErrUnexpectedResponseCode: *err}
		case 504: // Map also 504 to 503
			newError = &gophercloud.ErrDefault503{ErrUnexpectedResponseCode: *err}
		}

		if newError != nil {
			return NormalizeError(newError)
		}
		return fail.NewError("unexpected response code: code: %d, reason: %s", err.Actual, string(err.Body))
	}
	return nil
}

// errorMeansServiceUnavailable tells if err contains "service unavailable" (lower/upper/mixed case)
func errorMeansServiceUnavailable(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "service unavailable")
}
