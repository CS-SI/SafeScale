/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package abstract

import (
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ResourceNotFoundError creates a NotFound error
func ResourceNotFoundError(resource, name string) fail.NotFound {
	msgFinal := fmt.Sprintf("failed to find %s", resource)
	if name != "" {
		msgFinal += fmt.Sprintf(" '%s'", name)
	}

	return fail.NotFoundReport(msgFinal)
}

// ResourceTimeoutError creates a Timeout error
func ResourceTimeoutError(resource, name string, dur time.Duration) fail.Timeout {
	msgFinal := fmt.Sprintf("timeout of '%s' waiting for '%s' '%s'", dur, resource, name)
	return fail.TimeoutReport(nil, dur, msgFinal)
}

// // TimeoutReport creates a Timeout error
// func TimeoutReport(message string, dur time.Duration) fail.Timeout {
// 	return fail.TimeoutReport(nil, dur, message)
// }

// ResourceNotAvailableError creates a ResourceNotAvailable error
func ResourceNotAvailableError(resource, name string) fail.NotAvailable {
	msgFinal := fmt.Sprintf("%s '%s' is unavailable", resource, name)
	return fail.NotAvailableReport(msgFinal)
}

// ResourceDuplicateError creates a ResourceAlreadyExists error
func ResourceDuplicateError(resource, name string) fail.Duplicate {
	msgFinal := fmt.Sprintf("%s '%s' already exists", resource, name)
	return fail.DuplicateReport(msgFinal)
}

// ResourceInvalidRequestError creates a ErrResourceInvalidRequest error
func ResourceInvalidRequestError(resource, reason string) fail.InvalidRequest {
	msgFinal := fmt.Sprintf("%s request is invalid: %s", resource, reason)

	return fail.InvalidRequestReport(msgFinal)
}

// ResourceForbiddenError creates a ErrResourceForbidden error
func ResourceForbiddenError(resource, name string) fail.Forbidden {
	msgFinal := fmt.Sprintf("access to %s resource '%s' is denied", resource, name)

	return fail.ForbiddenReport(msgFinal)
}

// IsProvisioningError detects provisioning errors
func IsProvisioningError(err error) bool {
	errText := err.Error()
	return strings.Contains(errText, "PROVISIONING_ERROR:")
}
