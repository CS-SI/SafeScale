/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package fail

import "fmt"

// ErrorLike interface
type ErrorLike interface {
	IsError() bool
}

// IsError ...
func IsError(err error) bool {
	if err != nil {
		ei, ok := err.(ErrorLike)
		if !ok {
			return true
		}
		return ei.IsError()
	}
	return false
}

// Status interface
type Status interface {
	Message() string
	Cause() error
	IsError() bool
}

type status struct {
	success bool
	message string
	cause   error
}

// StatusWrapErr ...
func StatusWrapErr(err error, msg string) Status {
	return &status{
		success: false,
		message: msg,
		cause:   err,
	}
}

// Success ..
func Success(msg string, args ...interface{}) Status {
	return &status{
		success: true,
		message: fmt.Sprintf(msg, args...),
	}
}

// Message ...
func (msg *status) Message() string {
	return msg.message
}

// Cause ...
func (msg *status) Cause() error {
	return msg.cause
}

// IsError ...
func (msg *status) IsError() bool {
	return msg.cause != nil || !msg.success
}
