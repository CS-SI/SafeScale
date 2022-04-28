/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

import "github.com/CS-SI/SafeScale/v21/lib/utils/fail"

//go:generate minimock -i github.com/CS-SI/SafeScale/v21/lib/server/resources.UnitResult -o mocks/mock_unitresult.go

// UnitResult ...
type UnitResult interface {
	Successful() bool
	Completed() bool
	Error() error
	ErrorMessage() string
}

//go:generate minimock -i github.com/CS-SI/SafeScale/v21/lib/server/resources.UnitResults -o mocks/mock_unitresults.go

// UnitResults ...
type UnitResults interface {
	AddOne(string, UnitResult)
	Completed() bool
	Uncompleted() []string
	ErrorMessages() string
	Successful() bool
	Keys() []string
	ResultOfKey(key string) UnitResult
}

//go:generate minimock -i github.com/CS-SI/SafeScale/v21/lib/server/resources.Results -o mocks/mock_results.go

// Results ...
type Results interface {
	Add(string, UnitResults) error
	AddOne(string, string, UnitResult) error
	Successful() bool
	AllErrorMessages() string
	ErrorMessagesOfUnit(name string) (string, fail.Error)
	ErrorMessagesOfKey(name string) string
	ResultsOfKey(key string) UnitResults
	Keys() []string
}
