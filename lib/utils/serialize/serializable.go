/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package serialize

import "github.com/CS-SI/SafeScale/lib/utils/fail"

//go:generate mockgen -destination=../mocks/mock_serializable.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/serialize Serializable

// Serializable is the interface allowing the conversion of satisfying struct to []byte (Serialize()
// and reverse operation (Unserialize()
type Serializable interface {
	Serialize() ([]byte, fail.Error)
	Deserialize([]byte) fail.Error
}
