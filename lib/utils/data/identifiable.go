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

//go:generate minimock -o mocks/mock_identifyable.go -i github.com/CS-SI/SafeScale/v21/lib/utils/data.Identifiable

// Identifiable proposes methods to identify a struct
type Identifiable interface {
	GetName() string // GetName Returns the name of the instance
	GetID() string   // GetID Returns the ID of the instance
}
