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
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type SafeLog struct {
	mu  sync.Mutex
	log string
}

func (c *SafeLog) Trace(line string) {
	c.mu.Lock()
	c.log = c.log + line
	defer c.mu.Unlock()
}

func (c *SafeLog) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.log
}

var preservedOutput = os.Stdout

// Used for tests to capture logrus output
func LogrusCapture(routine func()) string {

	logLine := make(chan string)
	logs := SafeLog{log: ""}

	r, w, _ := os.Pipe()
	logrus.SetOutput(w)
	os.Stdout = w
	defer func() {
		os.Stdout = preservedOutput
		logrus.SetOutput(preservedOutput)
	}()

	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		logLine <- buf.String()
	}()

	routine()
	w.Close()
	logs.Trace(<-logLine)
	return logs.String()

}

// Used for tests to run code segment with timelimit
// return status of (true: in time, false: timeouted)
func TimelimitCapture(routine func(), timeout time.Duration) bool {

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
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
