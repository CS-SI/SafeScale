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

package tests

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Used for tests to capture logrus output
func LogrusCapture(routine func()) string {

	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logrus.SetOutput(w)

	routine()

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	// back to normal state
	w.Close()
	os.Stdout = old // restoring the real stdout
	logrus.SetOutput(old)
	out := <-outC

	return out

}

// Used for tests to run code segment with timelimit
// return status of (true: in time, false: timeouted)
func TimelimitCapture(routine func(), timeout time.Duration) bool {

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		fmt.Println(reflect.TypeOf(routine))

		routine()
	}()

	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true
	case <-time.After(timeout):
		logrus.Warnf("Routine exceed timelimit of %d sec", timeout/1000000000)
		return false
	}

}
