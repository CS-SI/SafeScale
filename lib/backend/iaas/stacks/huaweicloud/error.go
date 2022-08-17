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

package huaweicloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/gophercloud/gophercloud"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// NormalizeError translates gophercloud or openstack error to SafeScale error
func NormalizeError(err error) fail.Error {
	if err != nil {
		tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks") || tracing.ShouldTrace("stack.openstack"), " Normalizing error").Entering()
		defer tracer.Exiting()

		switch e := err.(type) {
		case fail.Error:
			// Note: must check if the cause is a gophercloud error...
			cause := e.Cause()
			if cause != nil {
				tracer.Trace("received 'fail.Error' with a cause, normalizing on this cause...")
				return NormalizeError(cause)
			}
			tracer.Trace("received 'fail.Error', throwing it as-is")
			return e
		case gophercloud.ErrDefault400: // bad request
			tracer.Trace("received 'gophercloud.ErrDefault400', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("BadRequest", e.Body)
		case *gophercloud.ErrDefault400: // bad request
			tracer.Trace("received '*gophercloud.ErrDefault400', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("BadRequest", e.Body)
		case gophercloud.ErrDefault401: // unauthorized
			tracer.Trace("received 'gophercloud.ErrDefault401', normalized to '*fail.NotAuthenticated'")
			return fail.NotAuthenticatedError(string(e.Body))
		case *gophercloud.ErrDefault401: // unauthorized
			tracer.Trace("received '*gophercloud.ErrDefault401', normalized to '*fail.NotAuthenticated'")
			return fail.NotAuthenticatedError(string(e.Body))
		case gophercloud.ErrDefault403: // forbidden
			tracer.Trace("received 'gophercloud.ErrDefault403', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("Forbidden", e.Body)
		case *gophercloud.ErrDefault403: // forbidden
			tracer.Trace("received '*gophercloud.ErrDefault403', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("Forbidden", e.Body)
		case gophercloud.ErrDefault404: // not found
			tracer.Trace("received 'gophercloud.ErrDefault404', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("NotFound", e.Body)
		case *gophercloud.ErrDefault404: // not found
			tracer.Trace("received '*gophercloud.ErrDefault404', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("NotFound", e.Body)
		case gophercloud.ErrDefault408: // request timeout
			tracer.Trace("received 'gophercloud.ErrDefault408', normalized to '*fail.ErrOverflow'")
			return fail.OverflowError(nil, 0, string(e.Body))
		case *gophercloud.ErrDefault408: // request timeout
			tracer.Trace("received 'gophercloud.ErrDefault408', normalized to '*fail.ErrOverflow'")
			return fail.OverflowError(nil, 0, string(e.Body))
		case gophercloud.ErrDefault409: // conflict
			tracer.Trace("received 'gophercloud.ErrDefault409', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("Duplicate", e.Body)
		case *gophercloud.ErrDefault409: // conflict
			tracer.Trace("received '*gophercloud.ErrDefault409', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("Duplicate", e.Body)
		case gophercloud.ErrDefault429: // too many requests
			tracer.Trace("received 'gophercloud.ErrDefault429', normalized to '*fail.ErrOverload'")
			return fail.OverloadError(string(e.Body))
		case *gophercloud.ErrDefault429: // too many requests
			tracer.Trace("received '*gophercloud.ErrDefault429', normalized to '*fail.ErrOverload'")
			return fail.OverloadError(string(e.Body))
		case gophercloud.ErrDefault500: // internal server error
			tracer.Trace("received 'gophercloud.ErrDefault500', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("Execution", e.Body)
		case *gophercloud.ErrDefault500: // internal server error
			tracer.Trace("received '*gophercloud.ErrDefault500', forwarding to reduceOpenstackError()...")
			return reduceOpenstackError("Execution", e.Body)
		case gophercloud.ErrDefault503: // service unavailable
			tracer.Trace("received 'gophercloud.ErrDefault503', normalized to '*fail.ErrNotAvailable'")
			return fail.NotAvailableError(string(e.Body))
		case *gophercloud.ErrDefault503: // service unavailable
			tracer.Trace("received 'gophercloud.ErrDefault503', normalized to '*fail.ErrNotAvailable'")
			return fail.NotAvailableError(string(e.Body))
		case gophercloud.ErrResourceNotFound:
			tracer.Trace("received 'gophercloud.ErrResourceNotFound', normalized to '*fail.ErrNotFound'")
			return fail.NotFoundError(e.Error())
		case *gophercloud.ErrResourceNotFound:
			tracer.Trace("received '*gophercloud.ErrResourceNotFound', normalized to '*fail.ErrNotFound'")
			return fail.NotFoundError(e.Error())
		case gophercloud.ErrMultipleResourcesFound:
			tracer.Trace("received 'gophercloud.ErrMultipleResourcesFound', normalized to '*fail.ErrDuplicate'")
			return fail.DuplicateError(e.Error())
		case *gophercloud.ErrMultipleResourcesFound:
			tracer.Trace("received '*gophercloud.ErrMultipleResourcesFound', normalized to '*fail.ErrDuplicate'")
			return fail.DuplicateError(e.Error())
		case gophercloud.ErrUnexpectedResponseCode:
			tracer.Trace("received 'gophercloud.ErrUnexpectedResponseCode', requalifying based on error code...")
			return qualifyGophercloudResponseCode(&e)
		case *gophercloud.ErrUnexpectedResponseCode:
			tracer.Trace("received '*gophercloud.ErrUnexpectedResponseCode', requalifying based on error code...")
			return qualifyGophercloudResponseCode(e)
		case gophercloud.ErrMissingInput:
			tracer.Trace("received 'gophercloud.ErrMissingInput', normalized to '*fail.ErrInvalidRequest'")
			return fail.InvalidRequestError(e.Error())
		case *gophercloud.ErrMissingInput:
			tracer.Trace("received '*gophercloud.ErrMissingInput', normalized to '*fail.ErrInvalidRequest'")
			return fail.InvalidRequestError(e.Error())
		case gophercloud.ErrEndpointNotFound:
			tracer.Trace("received 'gophercloud.ErrEndpointNotFound', normalized to '*fail.ErrNotAvailable'")
			return fail.NotAvailableError(e.Error())
		case *gophercloud.ErrEndpointNotFound:
			tracer.Trace("received '*gophercloud.ErrEndpointNotFound', normalized to '*fail.ErrNotAvailable'")
			return fail.NotAvailableError(e.Error())
		case *url.Error: // go connection errors, this is a 'subclass' of next error net.Error, that captures all go connection errors
			tracer.Trace("received '*url.Error', normalized to 'fail.Error' with cause")
			return fail.NewErrorWithCause(e)
		case net.Error: // also go connection errors
			tracer.Trace("received 'net.Error', normalized to 'fail.Error' with cause")
			return fail.NewErrorWithCause(e)
		default:
			switch err.Error() {
			case "EOF":
				tracer.Trace("received 'EOF', normalized to '*fail.ErrNotFound'")
				return fail.NotFoundError("EOF")
			default:
				logrus.WithContext(context.Background()).Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
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

// reduceOpenstackError ...
func reduceOpenstackError(errorName string, in []byte) (ferr fail.Error) {
	defer func() {
		switch ferr.(type) {
		case *fail.ErrRuntimePanic:
			ferr = fail.InvalidRequestError(string(in))
		default:
		}
	}()
	defer fail.OnPanic(&ferr)

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks") || tracing.ShouldTrace("stack.openstack"), ": Normalizing error").Entering()
	defer tracer.Exiting()

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
		if lvl1m, ok := lvl1["message"].(string); ok {
			msg = lvl1m
		} // FIXME: Missing else
	} else if lvl1, ok := body["message"].(string); ok {
		msg = lvl1
	}

	tracer.Trace("normalized error to '*fail.Err%s'", errorName)
	return fn(msg)
}

// normalizeError translates gophercloud or openstack error to SafeScale error
func normalizeError(err error) fail.Error {
	if err != nil {
		switch lvl1 := err.(type) { // nolint
		case fail.Error:
			if cause := lvl1.Cause(); cause != nil {
				switch lvl2 := cause.(type) { // nolint
				case gophercloud.ErrDefault400:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault401:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault403:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault404:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault405:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault429:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault500:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				case gophercloud.ErrDefault503:
					return openstack.NormalizeError(reduceHuaweicloudError(lvl2.GetStatusCode(), lvl2.Body))
				}
			}
		}
		return openstack.NormalizeError(err)
	}
	return nil
}

func reduceHuaweiAPIErrors(errcode int, code string, body map[string]interface{}) (ferr fail.Error) {
	// look at https://support.huaweicloud.com/intl/en-us/devg-apisign/api-sign-errorcode.html
	switch code {
	case "APIGW.0101":
		return fail.NotFoundError("API not found")
	case "APIGW.0103":
		return fail.NotFoundError("The backend does not exist, contact your cloud provider")
	case "APIGW.0104":
		return fail.NotFoundError("The backend does not exist, contact your cloud provider")
	case "APIGW.0105":
		return fail.NotFoundError("The plugin does not exist, contact your cloud provider")
	case "APIGW.0106":
		return fail.NotAvailableError("Orchestration error")
	case "APIGW.0201":
		if errcode >= 500 {
			return fail.NotAvailableError("Backend service in timeout or not available")
		}
		return fail.InvalidRequestError("Invalid request")
	case "APIGW.0301", "APIGW.0302", "APIGW.0303", "APIGW.0304", "APIGW.0305", "APIGW.0306", "APIGW.0307":
		return fail.NotAuthenticatedError("Permission denied")
	case "APIGW.0308":
		return fail.OverloadError("Too many requests, try again later")
	case "APIGW.0310", "APIGW.0311":
		return fail.NotAuthenticatedError("Permission denied, contact your cloud provider")
	case "APIGW.0401", "APIGW.0402", "APIGW.0404", "APIGW.0801", "APIGW.0802":
		return fail.ForbiddenError("Access denied")
	case "APIGW.0501", "APIGW.0502":
		return fail.ForbiddenError("Quotas exceeded")
	case "APIGW.0601", "APIGW.0605", "APIGW.0606", "APIGW.0608", "APIGW.0609", "APIGW.0611", "APIGW.0613", "APIGW.0705":
		return fail.UnknownError("Internal error, contact your cloud provider")
	case "APIGW.0610":
		return fail.NotAvailableError("Backend service in timeout or not available")
	case "APIGW.0602", "APIGW.0607", "APIGW.0612":
		return fail.InvalidRequestError("Invalid request")
	default:
		return fail.UnknownError("unhandled error received from provider: %d, %s", errcode, code)
	}
}

// reduceHuaweicloudError ...
func reduceHuaweicloudError(errcode int, in []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var body map[string]interface{}
	unjsonedErr := json.Unmarshal(in, &body)
	if unjsonedErr != nil {
		return fail.Wrap(unjsonedErr, "error unmarshalling error received from provider: %s", string(in))
	}

	if code, ok := body["code"].(string); ok {
		switch code {
		case "VPC.0101":
			return fail.NotFoundError("failed to find VPC")
		case "VPC.0114":
			return fail.ForbiddenError("exceeded VPC quota")
		case "VPC.0209":
			return fail.NotAvailableError("subnet still in use")
		default:
			if strings.HasPrefix(code, "APIGW") {
				return reduceHuaweiAPIErrors(errcode, code, body)
			}
		}
	}

	logrus.WithContext(context.Background()).Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error received from provider: %s", string(in)), 0))
	return fail.NewError("unhandled error received from provider: %s", string(in))
}
