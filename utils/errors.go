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

package utils

// errCore ...
type errCore struct {
	message string
}

func (e errCore) Error() string {
	return e.message
}

// ErrTimeout defines a Timeout error
type ErrTimeout struct {
	errCore
}

// TimeoutError ...
func TimeoutError(msg string) ErrTimeout {
	return ErrTimeout{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrNotFound resource not found error
type ErrNotFound struct {
	errCore
}

// NotFoundError creates a ResourceNotFound error
func NotFoundError(msg string) ErrNotFound {
	return ErrNotFound{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrNotAvailable resource not available error
type ErrNotAvailable struct {
	errCore
}

// NotAvailableError creates a NotAvailable error
func NotAvailableError(msg string) ErrNotAvailable {
	return ErrNotAvailable{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrAlreadyExists resource already exists error
type ErrAlreadyExists struct {
	errCore
}

// AlreadyExistsError creates a ResourceAlreadyExists error
func AlreadyExistsError(msg string) ErrAlreadyExists {
	return ErrAlreadyExists{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrInvalidRequest ...
type ErrInvalidRequest struct {
	errCore
}

// InvalidRequestError creates a ErrInvalidRequest error
func InvalidRequestError(msg string) ErrInvalidRequest {
	return ErrInvalidRequest{
		errCore: errCore{
			message: msg,
		},
	}
}
