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
package clusterflavor

import (
	"strings"
	"testing"
)

func TestEnum_String(t *testing.T) {
	if len(stringMap) != len(enumMap) {
		t.Error("Not the same size")
	}

	for k, v := range stringMap {
		if r, ok := enumMap[v]; ok {
			if strings.Compare(strings.ToLower(k), strings.ToLower(r)) != 0 {
				t.Errorf("Value mismatch: %s, %s", k, r)
			}
		} else {
			t.Errorf("Key %s not found: ", k)
		}
	}
}
