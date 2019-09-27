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
	"github.com/CS-SI/SafeScale/lib/utils"
	"time"
)

// ResourceNotFoundError creates a ErrNotFound error
func ResourceNotFoundError(resource, name string) utils.ErrNotFound {
	msgFinal := fmt.Sprintf("failed to find %s", resource)
	if name != "" {
		msgFinal += fmt.Sprintf(" '%s'", name)
	}

	return utils.NotFoundError(msgFinal)
}

func ResourceTimeoutError(resource, name string, dur time.Duration) utils.ErrTimeout {
	msgFinal := fmt.Sprintf("timeout of '%s' waiting for '%s' '%s'", dur, resource, name)
	return utils.TimeoutError(msgFinal, dur, nil)
}

func TimeoutError(message string, dur time.Duration) utils.ErrTimeout {
	return utils.TimeoutError(message, dur, nil)
}

// ResourceNotAvailableError creates a ResourceNotAvailable error
func ResourceNotAvailableError(resource, name string) utils.ErrNotAvailable {
	msgFinal := fmt.Sprintf("%s '%s' is unavailable", resource, name)
	return utils.NotAvailableError(msgFinal)
}

// ResourceDuplicateError creates a ResourceAlreadyExists error
func ResourceDuplicateError(resource, name string) utils.ErrDuplicate {
	msgFinal := fmt.Sprintf("%s '%s' already exists", resource, name)
	return utils.DuplicateError(msgFinal)
}

// ResourceInvalidRequestError creates a ErrResourceInvalidRequest error
func ResourceInvalidRequestError(resource, reason string) utils.ErrInvalidRequest {
	msgFinal := fmt.Sprintf("%s request is invalid: %s", resource, reason)

	return utils.InvalidRequestError(msgFinal)
}

// ResourceAccessDeniedError creates a ErrResourceAccessDenied error
func ResourceAccessDeniedError(resource, name string) utils.ErrAccessDenied {
	msgFinal := fmt.Sprintf("access to %s resource '%s' is denied", resource, name)

	return utils.AccessDeniedError(msgFinal)
}
