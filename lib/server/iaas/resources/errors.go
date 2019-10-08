/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package resources

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// ResourceNotFoundError creates a ErrNotFound error
func ResourceNotFoundError(resource, name string) *scerr.ErrNotFound {
	msgFinal := fmt.Sprintf("failed to find %s", resource)
	if name != "" {
		msgFinal += fmt.Sprintf(" '%s'", name)
	}

	return scerr.NotFoundError(msgFinal)
}

// ResourceTimeoutError creates a ErrTimeout error
func ResourceTimeoutError(resource, name string, dur time.Duration) *scerr.ErrTimeout {
	msgFinal := fmt.Sprintf("timeout of '%s' waiting for '%s' '%s'", dur, resource, name)
	return scerr.TimeoutError(msgFinal, dur, nil)
}

// TimeoutError creates a ErrTimeout error
func TimeoutError(message string, dur time.Duration) *scerr.ErrTimeout {
	return scerr.TimeoutError(message, dur, nil)
}

// ResourceNotAvailableError creates a ResourceNotAvailable error
func ResourceNotAvailableError(resource, name string) *scerr.ErrNotAvailable {
	msgFinal := fmt.Sprintf("%s '%s' is unavailable", resource, name)
	return scerr.NotAvailableError(msgFinal)
}

// ResourceDuplicateError creates a ResourceAlreadyExists error
func ResourceDuplicateError(resource, name string) *scerr.ErrDuplicate {
	msgFinal := fmt.Sprintf("%s '%s' already exists", resource, name)
	return scerr.DuplicateError(msgFinal)
}

// ResourceInvalidRequestError creates a ErrResourceInvalidRequest error
func ResourceInvalidRequestError(resource, reason string) *scerr.ErrInvalidRequest {
	msgFinal := fmt.Sprintf("%s request is invalid: %s", resource, reason)

	return scerr.InvalidRequestError(msgFinal)
}

// ResourceForbiddenError creates a ErrResourceForbidden error
func ResourceForbiddenError(resource, name string) *scerr.ErrForbidden {
	msgFinal := fmt.Sprintf("access to %s resource '%s' is denied", resource, name)

	return scerr.ForbiddenError(msgFinal)
}
