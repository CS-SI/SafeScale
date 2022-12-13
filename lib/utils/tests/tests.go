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
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var preservedOutput = os.Stdout

// LogrusCapture Used for tests to capture logrus output
func LogrusCapture(routine func()) string {
	log := ""
	r, w, _ := os.Pipe()
	logrus.SetOutput(w)
	os.Stdout = w

	routine()

	os.Stdout = preservedOutput
	logrus.SetOutput(preservedOutput)

	err := w.Close()
	if err != nil {
		return ""
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	if err == nil {
		log = buf.String()
	}
	fmt.Println(log)
	return log
}

// TimelimitCapture Used for tests to run code segment with timelimit
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

func MinioOnline() bool {

	endpoint := func() string {
		value, ok := os.LookupEnv("MINIO_HEALTH_ENDPOINT")
		if !ok {
			value = "http://localhost:9000/"
		}
		return value
	}()

	return func() (status bool) {
		resp, err := http.Get(endpoint)
		if err != nil {
			return false
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				status = false
			}
		}(resp.Body)
		return true
	}()

}
