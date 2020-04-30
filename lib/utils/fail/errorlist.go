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
	"github.com/sirupsen/logrus"
)

// ErrorList ...
type ErrorList = *errorList
type errorList struct {
	*reportCore
	errors []error
}

// ErrorListReport creates a ErrorList
func ErrorListReport(errors []error) *errorList {
	if len(errors) == 0 {
		return nil
	}

	return &errorList{
		reportCore: &reportCore{},
		errors:     errors,
	}
}

// AddConsequence ...
func (e *errorList) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrorList.AddConsequence() from null instance")
		return nullReport()
	}
	if err != nil {
		if e.consequences == nil {
			e.consequences = []error{}
		}
		e.consequences = append(e.consequences, err)
	}
	return e
}

// WithField ...
func (e *errorList) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrorList.WithField() from null instance")
		return nullReport()
	}
	if e.fields != nil {
		e.fields[key] = value
	}

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

// ToErrors transforms ErrorList to []error
func (e *errorList) ToErrors() []error {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotFound.AddConsequence() from null instance")
		return []error{}
	}
	return e.errors
}
