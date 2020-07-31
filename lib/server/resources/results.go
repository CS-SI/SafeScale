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

package resources

// UnitResult ...
type UnitResult interface {
    Successful() bool
    Completed() bool
    Error() error
    ErrorMessage() string
}

// UnitResults ...
type UnitResults interface {
    AddSingle(string, UnitResult)
    Completed() bool
    Uncompleted() []string
    ErrorMessages() string
    Successful() bool
}

// Results ...
type Results interface {
    Add(string, UnitResults) error
    AddUnit(string, string, UnitResult) error
    Successful() bool
    AllErrorMessages() string
    ErrorMessagesOfUnit(name string) string
    ErrorMessagesOfKey(name string) string
    ResultsOfKey(key string) UnitResults
    // ResultsOfUnit(unitKey string) UnitResults
    Keys() []string
}
