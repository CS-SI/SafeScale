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

package abstract

import (
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ResourceNotFoundError creates a ErrNotFound error
func ResourceNotFoundError(resource, name string) fail.Error {
	msgFinal := fmt.Sprintf("failed to find %s", resource)
	if name != "" {
		msgFinal += fmt.Sprintf(" '%s'", name)
	}

	return fail.NotFoundError(msgFinal)
}

// ResourceTimeoutError creates a ErrTimeout error
func ResourceTimeoutError(resource, name string, dur time.Duration) fail.Error {
	msgFinal := fmt.Sprintf("timeout of '%s' waiting for %s '%s'", dur, resource, name)
	return fail.TimeoutError(nil, dur, msgFinal)
}

// ResourceNotAvailableError creates a ResourceNotAvailable error
func ResourceNotAvailableError(resource, name string) fail.Error {
	msgFinal := fmt.Sprintf("%s %s is unavailable", resource, name)
	return fail.NotAvailableError(msgFinal)
}

// ResourceDuplicateError creates a ResourceAlreadyExists error
func ResourceDuplicateError(resource, name string) fail.Error {
	msgFinal := fmt.Sprintf("%s '%s' already exists", resource, name)
	return fail.DuplicateError(msgFinal)
}

// ResourceInvalidRequestError creates a ErrResourceInvalidRequest error
func ResourceInvalidRequestError(resource, reason string) fail.Error {
	msgFinal := fmt.Sprintf("%s request is invalid: %s", resource, reason)

	return fail.InvalidRequestError(msgFinal)
}

// ResourceForbiddenError creates a ErrResourceForbidden error
func ResourceForbiddenError(resource, name string) fail.Error {
	msgFinal := fmt.Sprintf("access to %s resource '%s' is denied", resource, name)

	return fail.ForbiddenError(msgFinal)
}

// IsProvisioningError detects provisioning errors
func IsProvisioningError(err error) bool {
	errText := err.Error()
	return strings.Contains(errText, "PROVISIONING_ERROR:")
}
