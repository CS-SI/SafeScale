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

package utils

import (
	"fmt"
	"os"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/tests"
)

func Test_LazyRemove(t *testing.T) {

	if _, err := os.Stat("/tmp"); os.IsNotExist(err) {
		t.Log("Directory /tmp not found, check is u are on Linux OS")
		t.Skip()
		return
	}

	if _, err := os.Stat("/tmp/safescale-test"); os.IsExist(err) {
		t.Log("Directory /tmp/safescale-test already found...process already running ?")
		t.Skip()
		return
	}

	// Make working directory
	_ = os.Mkdir("/tmp/safescale-test", 0x0777)

	log := tests.LogrusCapture(func() {
		err := LazyRemove("/tmp/safescale-test")
		if err != nil {
			// Remove working directory
			os.RemoveAll("/tmp/safescale-test")
			t.Error(err)
			t.Fail()
		} else {
			// Remove working directory
			os.RemoveAll("/tmp/safescale-test")
		}
	})
	fmt.Println(log)

}
