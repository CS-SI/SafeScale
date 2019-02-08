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

package utils

// ErrCore ...
type ErrCore struct {
	message string
}

func (e *ErrCore) Error() string {
	return e.message
}

// ErrTimeout defines a Timeout error
type ErrTimeout struct {
	*ErrCore
}

// ErrNotFound resource not found error
type ErrNotFound struct {
	*ErrCore
}

// NotFoundError creates a ResourceNotFound error
func NotFoundError(msg string) ErrNotFound {
	return ErrNotFound{
		ErrCore: &ErrCore{
			message: msg,
		},
	}
}

// ErrNotAvailable resource not available error
type ErrNotAvailable struct {
	*ErrCore
}

// NotAvailableError creates a NotAvailable error
func NotAvailableError(msg string) ErrNotAvailable {
	return ErrNotAvailable{
		ErrCore: &ErrCore{
			message: msg,
		},
	}
}

// ErrAlreadyExists resource already exists error
type ErrAlreadyExists struct {
	*ErrCore
}

// AlreadyExistsError creates a ResourceAlreadyExists error
func AlreadyExistsError(msg string) ErrAlreadyExists {
	return ErrAlreadyExists{
		ErrCore: &ErrCore{
			message: msg,
		},
	}
}

// ErrInvalidRequest ...
type ErrInvalidRequest struct {
	*ErrCore
}

// InvalidRequestError creates a ErrInvalidRequest error
func InvalidRequestError(msg string) ErrInvalidRequest {
	return ErrInvalidRequest{
		ErrCore: &ErrCore{
			message: msg,
		},
	}
}
