/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

import "fmt"

// ErrTimeout defines a Timeout error
type ErrTimeout struct {
	Message string
}

func (e *ErrTimeout) Error() string {
	return e.Message
}

// ErrResource resource error
type ErrResource struct {
	Name         string
	ResourceType string
}

// ErrResourceNotFound resource not found error
type ErrResourceNotFound struct {
	ErrResource
}

// ResourceNotFoundError creates a ResourceNotFound error
func ResourceNotFoundError(resource string, name string) ErrResourceNotFound {
	return ErrResourceNotFound{
		ErrResource{
			Name:         name,
			ResourceType: resource,
		},
	}
}
func (e ErrResourceNotFound) Error() string {
	tmpl := "failed to find %s"
	if e.Name != "" {
		tmpl += " '%s'"
		return fmt.Sprintf(tmpl, e.ResourceType, e.Name)
	}
	return fmt.Sprintf(tmpl, e.ResourceType)
}

// ErrResourceNotAvailable resource not available error
type ErrResourceNotAvailable struct {
	ErrResource
}

// ResourceNotAvailableError creates a ResourceNotAvailable error
func ResourceNotAvailableError(resource, name string) ErrResourceNotAvailable {
	return ErrResourceNotAvailable{
		ErrResource{
			Name:         name,
			ResourceType: resource,
		},
	}
}
func (e ErrResourceNotAvailable) Error() string {
	return fmt.Sprintf("%s '%s' is unavailable", e.ResourceType, e.Name)
}

// ErrResourceAlreadyExists resource already exists error
type ErrResourceAlreadyExists struct {
	ErrResource
}

// ResourceAlreadyExistsError creates a ResourceAlreadyExists error
func ResourceAlreadyExistsError(resource string, name string) ErrResourceAlreadyExists {
	return ErrResourceAlreadyExists{
		ErrResource{
			Name:         name,
			ResourceType: resource,
		},
	}
}

func (e ErrResourceAlreadyExists) Error() string {
	return fmt.Sprintf("%s '%s' already exists", e.ResourceType, e.Name)
}

// ErrResourceInvalidRequest resource requested with invalid parameters
type ErrResourceInvalidRequest struct {
	ErrResource
}

// ResourceInvalidRequestError creates a ErrResourceInvalidRequest error
func ResourceInvalidRequestError(resource string, reason string) ErrResourceInvalidRequest {
	return ErrResourceInvalidRequest{
		ErrResource{
			Name:         reason,
			ResourceType: resource,
		},
	}
}

func (e ErrResourceInvalidRequest) Error() string {
	return fmt.Sprintf("%s request is invalid: %s", e.ResourceType, e.Name)
}
