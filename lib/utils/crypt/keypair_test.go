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

package crypt

import (
	"testing"
)

func Test_GenerateRSAKeyPair(t *testing.T) {

	_, _, xerr := GenerateRSAKeyPair("")
	if xerr == nil {
		t.Error("Can't generate RSA Key from empty name")
		t.Fail()
	}
	_, _, xerr = GenerateRSAKeyPair("any")
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}

}
