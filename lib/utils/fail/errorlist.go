/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

import (
	"github.com/sirupsen/logrus"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// ErrorList ...
type ErrorList struct {
	*errorCore
	errors []error
}

// NewErrorList creates a ErrorList
func NewErrorList(errors []error) Error {
	if len(errors) == 0 {
		return &ErrorList{}
	}

	return &ErrorList{
		errorCore: newError(nil, nil, ""),
		errors:    errors,
	}
}

// ToGRPCStatus returns a grpcstatus struct from ErrorList
func (el ErrorList) ToGRPCStatus() error {
	return grpcstatus.Errorf(el.GRPCCode(), el.Error())
}

// AddConsequence ...
func (el *ErrorList) AddConsequence(err error) Error {
	if el == err { // do nothing
		return el
	}
	if el.IsNull() {
		logrus.Errorf("invalid call of ErrorList.AddConsequence() from null instance")
		return el
	}
	_ = el.errorCore.AddConsequence(err)
	return el
}

// Annotate ...
// satisfies interface data.Annotatable
func (el *ErrorList) Annotate(key string, value data.Annotation) data.Annotatable {
	if el.IsNull() {
		logrus.Errorf("invalid call of ErrorList.WithField() from null instance")
		return el
	}
	_ = el.errorCore.Annotate(key, value)
	return el
}

// Note: no Reset() overloading, it's wanted... It doesn't have that much sense with ErrorList

// Error returns a string containing all the errors
func (el *ErrorList) Error() string {
	if el.IsNull() {
		logrus.Errorf("invalid call of ErrorList.Error() from null instance")
		return ""
	}
	r := el.message
	if len(el.errors) > 0 {
		for _, v := range el.errors {
			r += v.Error() + "\n"
		}
	}
	return r
}

// UnformattedError returns Error() without any extra formatting applied
func (el *ErrorList) UnformattedError() string {
	return el.Error()
}

// ToErrorSlice transforms ErrorList to []error
func (el *ErrorList) ToErrorSlice() []error {
	if el.IsNull() {
		logrus.Errorf("invalid call of ErrNotFound.AddConsequence() from null instance")
		return []error{}
	}
	return el.errors
}
