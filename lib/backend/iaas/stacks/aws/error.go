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

package aws

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// normalizeError translates AWS error to SafeScale one
func normalizeError(err error) fail.Error {
	if err != nil {
		switch cerr := err.(type) { // nolint
		case awserr.Error:
			switch cerr.Code() {
			case "InvalidGroupId.Malformed":
				return fail.SyntaxError("failed to find Security Group: id is malformed")
			case "InvalidGroup.NotFound":
				return fail.NotFoundError("failed to find Security Group")
			case "InvalidVpcID.NotFound":
				return fail.NotFoundError("failed to find Network")
			case "InvalidGroup.Duplicate":
				return fail.DuplicateError("a Security Group already exists with that name")
			case "InvalidVolume.NotFound":
				return fail.NotFoundError("failed to find Volume")
			case "InvalidSubnetID.NotFound":
				return fail.NotFoundError("failed to find Subnet")
			case "InvalidNetworkInterfaceID.NotFound":
				return fail.NotFoundError("failed to find network interface")
			case "InvalidParameterValue":
				return fail.InvalidRequestError(cerr.Message())
			case "VcpuLimitExceeded":
				return fail.OverloadError(cerr.Message())
			case "InsufficientInstanceCapacity":
				return fail.OverloadError(cerr.Message())
			case "DependencyViolation":
				return fail.NotAvailableError(cerr.Message())
			default:
				switch cerr := err.(type) {
				case awserr.RequestFailure:
					switch cerr.StatusCode() {
					case 400:
						return fail.InvalidRequestError(err.Error())
					case 401:
						return fail.NotAuthenticatedError(err.Error())
					case 403:
						return fail.ForbiddenError(err.Error())
					case 404:
						return fail.NotFoundError(err.Error())
					case 408:
						return fail.TimeoutError(err, 0)
					case 409:
						return fail.InvalidRequestError(err.Error())
					case 410:
						return fail.NotFoundError(err.Error())
					case 425:
						return fail.OverloadError(err.Error())
					case 429:
						return fail.OverloadError(err.Error())
					case 500:
						return fail.ExecutionError(nil, err.Error())
					case 503:
						return fail.NotAvailableError(err.Error())
					case 504:
						return fail.NotAvailableError(err.Error())
					}
				default:
					logrus.WithContext(context.Background()).Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error()), 0))
					return fail.NewError("unhandled error received from provider: %s", err.Error())
				}
			}
		case *url.Error: // go connection errors, this is a 'subclass' of next error net.Error, that captures all go connection errors
			return fail.NewErrorWithCause(cerr)
		case net.Error: // also go connection errors
			return fail.NewErrorWithCause(cerr)
		}

		return fail.ConvertError(err)
	}

	return nil
}
