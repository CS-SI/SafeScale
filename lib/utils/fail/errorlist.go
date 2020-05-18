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

package fail

import (
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/sirupsen/logrus"
)

// ErrorList ...
type ErrorList = *errorList
type errorList struct {
	*errorCore
	errors []error
}

// NewErrorList creates a ErrorList
func NewErrorList(errors []error) Error {
	if len(errors) == 0 {
		return &errorList{}
	}

	return &errorList{
		errorCore: newError(nil, nil, ""),
		errors:    errors,
	}
}

// AddConsequence ...
func (e *errorList) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrorList.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
// satisfies interface data.Annotatable
func (e *errorList) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrorList.WithField() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// Note: no Reset() overloading, it's wanted... It doesn't have that much sense with ErrorList

// Error returns a string containing all the errors
func (e *errorList) Error() string {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrorList.Error() from null instance")
		return ""
	}
	var r string
	for _, v := range e.errors {
		r += v.Error() + "\n"
	}
	return r
}

// ToErrorSlice transforms ErrorList to []error
func (e *errorList) ToErrorSlice() []error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotFound.AddConsequence() from null instance")
		return []error{}
	}
	return e.errors
}
