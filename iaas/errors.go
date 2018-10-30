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

package iaas

import (
	"fmt"
)

// ResourceError resource error
type ResourceError struct {
	Name         string
	ResourceType string
}

// ResourceNotFound resource not found error
type ResourceNotFound struct {
	ResourceError
}

// ResourceNotFoundError creates a ResourceNotFound error
func ResourceNotFoundError(resource string, name string) ResourceNotFound {
	return ResourceNotFound{
		ResourceError{
			Name:         name,
			ResourceType: resource,
		},
	}
}
func (e ResourceNotFound) Error() string {
	return fmt.Sprintf("Unable to find %s '%s'", e.ResourceType, e.Name)
}

// ResourceAlreadyExists resource already exists error
type ResourceAlreadyExists struct {
	ResourceError
}

// ResourceAlreadyExistsError creates a ResourceAlreadyExists error
func ResourceAlreadyExistsError(resource string, name string) ResourceAlreadyExists {
	return ResourceAlreadyExists{
		ResourceError{
			Name:         name,
			ResourceType: resource,
		},
	}
}

func (e ResourceAlreadyExists) Error() string {
	return fmt.Sprintf("%s '%s' already exists", e.ResourceType, e.Name)
}
