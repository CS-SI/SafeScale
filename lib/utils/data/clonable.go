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

package data

//go:generate minimock -o mocks/mock_clonable.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data.Clonable

// Clonable is the interface a struct must satisfy to be able to be cloned
type Clonable interface {
	IsNull() bool                       // tells of Clonable represents a null value
	Clone() (Clonable, error)           // allows duplication of a Clonable
	Replace(Clonable) (Clonable, error) // allows replacing a Clonable with data from another one
}
